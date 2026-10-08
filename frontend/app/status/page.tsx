import { connection } from "next/server";
import Link from "next/link";

type ServiceState = "ok" | "error" | "unknown";

type Readiness = {
  status: "ready" | "unavailable";
  checks: Record<string, "ok" | "error">;
};

// Called from the server, so the backend does not need to be reachable from
// the browser. API_INTERNAL_URL is the in-network address set by docker-compose.
async function getReadiness(): Promise<Readiness | null> {
  const baseUrl = process.env.API_INTERNAL_URL ?? "http://localhost:8000";
  try {
    const response = await fetch(`${baseUrl}/health/ready`, {
      signal: AbortSignal.timeout(5000),
    });
    // A 503 still carries a body saying which dependency is down.
    return (await response.json()) as Readiness;
  } catch {
    return null;
  }
}

const badge: Record<ServiceState, { label: string; dot: string }> = {
  ok: { label: "Online", dot: "bg-good" },
  error: { label: "Offline", dot: "bg-critical" },
  unknown: { label: "Unknown", dot: "bg-muted" },
};

export const metadata = { title: "System status · SentinelAI" };

export default async function StatusPage() {
  // Render on every request: without this, the build would prerender the page
  // and freeze whatever health status the backend had at build time.
  await connection();
  const readiness = await getReadiness();

  const services: { name: string; state: ServiceState }[] = [
    { name: "API", state: readiness ? "ok" : "error" },
    { name: "PostgreSQL", state: readiness?.checks.database ?? "unknown" },
    { name: "Redis", state: readiness?.checks.redis ?? "unknown" },
  ];

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col gap-8 px-6 py-16">
      <header>
        <p className="label-caps text-accent">SENTINEL//AI · public status</p>
        <h1 className="mt-2 font-display text-3xl font-bold uppercase tracking-[0.1em]">System status</h1>
        <p className="mt-3 text-ink-2">
          Public health check: confirms that every service in the stack is reachable. It needs
          no login and shows no security data.
        </p>
      </header>

      <section
        aria-labelledby="status-heading"
        className="hud p-6"
      >
        <h2 id="status-heading" className="font-display text-lg font-semibold uppercase tracking-wider">
          {readiness?.status === "ready"
            ? "All systems operational"
            : "Degraded: some services are unavailable"}
        </h2>
        <ul className="mt-4 divide-y divide-line">
          {services.map(({ name, state }) => (
            <li key={name} className="flex items-center justify-between py-3">
              <span>{name}</span>
              <span className="flex items-center gap-2 text-sm text-ink-2">
                <span aria-hidden className={`size-2 rounded-full ${badge[state].dot}`} />
                {badge[state].label}
              </span>
            </li>
          ))}
        </ul>
      </section>
      <Link href="/" className="text-sm text-accent hover:underline">
        Open the SOC dashboard →
      </Link>
    </main>
  );
}
