"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { PageHeader } from "@/components/shell";
import { Button, Card, Field, Notice, Skeleton, inputClass } from "@/components/ui";
import { send } from "@/lib/api";
import { RISK_COMPONENTS } from "@/lib/format";
import { hasRole, useMe } from "@/lib/user";
import type { DetectionConfig } from "@/lib/types";

type Weights = DetectionConfig["risk_weights"];
const WEIGHT_KEYS = Object.keys(RISK_COMPONENTS) as (keyof Weights)[];

export function SettingsView() {
  const { data: me } = useMe();
  return (
    <>
      <PageHeader title="Settings" />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          {me ? (
            hasRole(me, "analyst") ? (
              <DetectionSettings editable={hasRole(me, "admin")} />
            ) : (
              <Card title="Detection settings">
                <Notice>Detection settings are visible to analysts and administrators.</Notice>
              </Card>
            )
          ) : (
            <Skeleton className="h-80" />
          )}
        </div>
        <PasswordChange />
      </div>
    </>
  );
}

function DetectionSettings({ editable }: { editable: boolean }) {
  const { data, error, mutate } = useSWR<DetectionConfig>("config/detection");
  // null = no unsaved edits: the form shows the stored settings.
  const [draft, setForm] = useState<DetectionConfig | null>(null);
  const form = draft ?? data ?? null;
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  if (error) return <Notice tone="error">{error.message}</Notice>;
  if (!form) return <Skeleton className="h-80" />;

  const total = WEIGHT_KEYS.reduce((sum, key) => sum + form.risk_weights[key], 0);
  const valid = Math.abs(total - 1) < 1e-6;
  const setWeight = (key: keyof Weights, percent: number) =>
    setForm({ ...form, risk_weights: { ...form.risk_weights, [key]: percent / 100 } });

  return (
    <Card
      title="Detection settings"
      description={
        editable
          ? "Changes apply within seconds to the alert engine and the real-time risk engine, and are audited."
          : "Read-only: only administrators can change these."
      }
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setMessage(null);
          try {
            const saved = await send<DetectionConfig>("PUT", "config/detection", form);
            await mutate(saved, { revalidate: false });
            setForm(null);
            setMessage({ tone: "info", text: "Settings saved." });
          } catch (err) {
            setMessage({ tone: "error", text: err instanceof Error ? err.message : "Could not save." });
          } finally {
            setBusy(false);
          }
        }}
      >
        <fieldset disabled={!editable || busy} className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Minimum risk score for an alert" hint="Detections below it are stored, not alerted (0–100).">
              <input
                type="number"
                min={0}
                max={100}
                required
                value={form.alert_min_risk}
                onChange={(e) => setForm({ ...form, alert_min_risk: Number(e.target.value) })}
                className={inputClass}
              />
            </Field>
            <Field label="Aggregation window (minutes)" hint="An open alert absorbs matching detections seen within it.">
              <input
                type="number"
                min={1}
                max={1440}
                required
                value={form.aggregation_window_minutes}
                onChange={(e) => setForm({ ...form, aggregation_window_minutes: Number(e.target.value) })}
                className={inputClass}
              />
            </Field>
          </div>
          <div>
            <p className="text-xs font-medium text-ink-2">Risk weights</p>
            <p className="text-xs text-muted">How much each signal counts towards the risk score; they must add up to 100%.</p>
            <div className="mt-3 space-y-3">
              {WEIGHT_KEYS.map((key) => (
                <label key={key} className="grid grid-cols-[10rem_1fr_4.5rem] items-center gap-3 text-sm">
                  <span className="text-ink">{RISK_COMPONENTS[key]}</span>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    step={5}
                    value={Math.round(form.risk_weights[key] * 100)}
                    onChange={(e) => setWeight(key, Number(e.target.value))}
                    className="accent-[var(--accent)]"
                  />
                  <input
                    type="number"
                    aria-label={`${RISK_COMPONENTS[key]} weight in percent`}
                    min={0}
                    max={100}
                    value={Math.round(form.risk_weights[key] * 100)}
                    onChange={(e) => setWeight(key, Number(e.target.value))}
                    className={`${inputClass} tabular text-right`}
                  />
                </label>
              ))}
            </div>
            <p className={`tabular mt-2 text-xs ${valid ? "text-muted" : "font-medium text-critical"}`}>
              Total: {Math.round(total * 100)}%{valid ? "" : " (must be 100%)"}
            </p>
          </div>
          {message && <Notice tone={message.tone}>{message.text}</Notice>}
          {editable && (
            <div className="flex gap-2">
              <Button type="submit" variant="primary" disabled={!valid || busy}>
                Save settings
              </Button>
              <Button type="button" onClick={() => setForm(null)}>
                Discard changes
              </Button>
            </div>
          )}
        </fieldset>
      </form>
    </Card>
  );
}

function PasswordChange() {
  const router = useRouter();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Card title="Change password" description="12–128 characters. Signs you out everywhere, including here.">
      <form
        className="space-y-3"
        onSubmit={async (e) => {
          e.preventDefault();
          if (next !== confirm) return setError("The new passwords do not match.");
          setBusy(true);
          setError(null);
          try {
            await send("POST", "auth/password", { current_password: current, new_password: next });
            router.replace("/login");
          } catch (err) {
            setError(err instanceof Error ? err.message : "Could not change the password.");
            setBusy(false);
          }
        }}
      >
        <Field label="Current password">
          <input type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} className={inputClass} />
        </Field>
        <Field label="New password">
          <input type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={next} onChange={(e) => setNext(e.target.value)} className={inputClass} />
        </Field>
        <Field label="Repeat new password">
          <input type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={confirm} onChange={(e) => setConfirm(e.target.value)} className={inputClass} />
        </Field>
        {error && <Notice tone="error">{error}</Notice>}
        <Button type="submit" disabled={busy}>Change password</Button>
      </form>
    </Card>
  );
}
