// The analyst journey on the real stack: sign in, watch live traffic, see a
// simulated DDoS raise an alert without reloading, and work it to resolution.
//
// Needs ADMIN_PASSWORD (and ADMIN_USERNAME if not "admin"). The attack is
// injected with E2E_INJECT_COMMAND, by default through docker compose from the
// repository root.
import { execSync } from "node:child_process";
import path from "node:path";
import { expect, test, type Page } from "@playwright/test";

const USERNAME = process.env.ADMIN_USERNAME ?? "admin";
const PASSWORD = process.env.ADMIN_PASSWORD ?? "";
const INJECT =
  process.env.E2E_INJECT_COMMAND ??
  "docker compose exec -T engine python -m sentinel_engine inject --scenario ddos --duration 10";
const TARGET = "10.20.0.10:80";

test.skip(!PASSWORD, "set ADMIN_PASSWORD to run the end-to-end tests");

async function signIn(page: Page, password = PASSWORD) {
  await page.getByLabel("Username").fill(USERNAME);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test("pages require a session and bad credentials are refused", async ({ page }) => {
  await page.goto("/alerts");
  await expect(page).toHaveURL(/\/login\?next=%2Falerts$/);
  await signIn(page, "definitely-not-the-password");
  await expect(page.getByRole("alert").filter({ hasText: "Incorrect" })).toHaveText(
    "Incorrect username or password.",
  );
  await signIn(page);
  await expect(page).toHaveURL(/\/alerts$/);
  await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
});

test("a simulated DDoS is detected live and worked to resolution", async ({ page }) => {
  await page.goto("/");
  await signIn(page);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // Live feed: the SSE relay authenticates to the API WebSocket and the
  // engine's traffic ticks draw the live chart.
  await expect(page.getByRole("status").filter({ hasText: "Live" })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("img", { name: /Live flows per second/ }).locator("svg")).toBeVisible({
    timeout: 30_000,
  });

  execSync(INJECT, { cwd: path.resolve(__dirname, "../.."), stdio: "ignore", timeout: 60_000 });

  // The alert appears on the overview without a reload (alert.new / alert.updated).
  const alertLink = page.getByRole("link", { name: `DDoS → ${TARGET}` }).first();
  await expect(alertLink).toBeVisible({ timeout: 60_000 });
  await alertLink.click();

  await expect(page.getByRole("heading", { name: `DDoS → ${TARGET}` })).toBeVisible();
  await expect(page.getByText("Why the model flagged it")).toBeVisible();
  await expect(page.getByText(/Advisory: SentinelAI does not block traffic/)).toBeVisible();

  const workflow = async (button: string, status: string) => {
    await page.getByRole("button", { name: button, exact: true }).click();
    await expect(page.getByText(status, { exact: true }).first()).toBeVisible();
  };

  if (await page.getByRole("button", { name: "Acknowledge" }).isVisible()) {
    await workflow("Acknowledge", "Investigating");
  }
  await page.getByRole("button", { name: "Assign to me" }).click();
  await expect(page.getByRole("button", { name: "Unassign me" })).toBeVisible();

  const note = `E2E check ${Date.now()}: traffic from the simulator, no action needed.`;
  await page.getByLabel("New note").fill(note);
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText(note)).toBeVisible();

  await workflow("Mark contained", "Contained");
  await workflow("Resolve", "Resolved");
  await expect(page.getByText("Status → Resolved").first()).toBeVisible();

  // Every step is in the audit trail.
  await page.getByRole("link", { name: "Audit log" }).click();
  await expect(page.getByRole("cell", { name: "alert.status_changed" }).first()).toBeVisible();
  await expect(page.getByRole("cell", { name: "alert.note_added" }).first()).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login/);
  await page.goto("/settings");
  await expect(page).toHaveURL(/\/login\?next=%2Fsettings$/);
});

test("settings show the detection configuration to an admin", async ({ page }) => {
  await page.goto("/settings");
  await signIn(page);
  await expect(page.getByRole("heading", { name: "Detection settings" })).toBeVisible();
  await expect(page.getByText("Total: 100%")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save settings" })).toBeEnabled();
});

test("an admin adds an email channel and its test message is delivered", async ({ page, request }) => {
  const mailpit = process.env.MAILPIT_URL;
  await page.goto("/notifications");
  await signIn(page);
  await expect(page.getByRole("heading", { name: "Notifications" })).toBeVisible();

  const name = `E2E mail ${Date.now()}`;
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Recipients").fill("e2e@example.com");
  await page.getByRole("button", { name: "Add channel" }).click();
  await expect(page.getByText(`Added ${name}.`)).toBeVisible();

  const row = page.getByRole("listitem").filter({ hasText: name });
  await row.getByRole("button", { name: "Send test" }).click();
  await expect(row.getByText("Test queued")).toBeVisible();

  // The notifier picks the delivery up within seconds; the log refreshes itself.
  const logRow = page.getByRole("row").filter({ hasText: `channel '${name}'` });
  if (mailpit) {
    await expect(logRow.getByText("Sent", { exact: true })).toBeVisible({ timeout: 30_000 });
    const messages = await (await request.get(`${mailpit}/api/v1/messages`)).json();
    expect(messages.messages.map((m: { Subject: string }) => m.Subject)).toContain(
      `SentinelAI test notification for channel '${name}'`,
    );
  } else {
    // Without an SMTP relay (the default) the delivery fails with a clear reason.
    await expect(logRow.getByText("Failed", { exact: true })).toBeVisible({ timeout: 30_000 });
    await expect(logRow.getByText(/SMTP is not configured/)).toBeVisible();
  }
});
