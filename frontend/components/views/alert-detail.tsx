"use client";
import Link from "next/link";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell";
import {
  Button,
  Card,
  Notice,
  STATUS_LABEL,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  inputClass,
} from "@/components/ui";
import { send } from "@/lib/api";
import {
  RISK_COMPONENTS,
  attackName,
  featureName,
  formatBytesRate,
  formatCount,
  formatPercent,
  formatTime,
  target,
} from "@/lib/format";
import { hasRole, useMe } from "@/lib/user";
import type { AlertDetail, AlertStatus, EventSummary, Page } from "@/lib/types";

const ACTION_LABEL: Record<AlertStatus, string> = {
  NEW: "New",
  INVESTIGATING: "Investigate",
  CONTAINED: "Mark contained",
  RESOLVED: "Resolve",
  FALSE_POSITIVE: "False positive",
};

export function AlertDetailView({ id }: { id: number }) {
  const { data: me } = useMe();
  const { data: alert, error, mutate } = useSWR<AlertDetail>(`alerts/${id}`, {
    refreshInterval: 15_000,
  });
  const events = useSWR<Page<EventSummary>>(`alerts/${id}/events?limit=10`);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [note, setNote] = useState("");

  if (error) return <Notice tone="error">{error.status === 404 ? "This alert does not exist." : error.message}</Notice>;
  if (!alert) return <Skeleton className="h-96" />;

  const canAct = hasRole(me, "analyst");
  const run = async (fn: () => Promise<AlertDetail | unknown>, clearNote = false) => {
    setBusy(true);
    setActionError(null);
    try {
      const result = await fn();
      if (result && typeof result === "object" && "allowed_transitions" in result) {
        await mutate(result as AlertDetail, { revalidate: false });
      } else {
        await mutate();
      }
      if (clearNote) setNote("");
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "The action failed.");
      await mutate();
    } finally {
      setBusy(false);
    }
  };

  const changeStatus = (status: AlertStatus) =>
    run(
      () =>
        alert.status === "NEW" && status === "INVESTIGATING"
          ? send<AlertDetail>("POST", `alerts/${id}/ack`)
          : send<AlertDetail>("PATCH", `alerts/${id}/status`, {
              status,
              ...(note.trim() ? { note: note.trim() } : {}),
            }),
      alert.status !== "NEW" && !!note.trim(),
    );

  const transitionLabel = (status: AlertStatus) =>
    status === "INVESTIGATING"
      ? alert.status === "NEW"
        ? "Acknowledge"
        : alert.status === "CONTAINED"
          ? "Back to investigating"
          : "Reopen"
      : ACTION_LABEL[status];

  return (
    <>
      <Link href="/alerts" className="text-sm text-ink-2 hover:text-ink hover:underline">
        ← Alerts
      </Link>
      <div className="mt-2">
        <PageHeader
          title={`${attackName(alert.attack_type)} → ${target(alert.destination_ip, alert.destination_port)}`}
          description={
            <span className="flex flex-wrap items-center gap-2">
              <span className="tabular text-muted">#{alert.id}</span>
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <span>{alert.description}</span>
            </span>
          }
        />
      </div>

      {canAct && (
        <Card className="mb-4" title="Response">
          <div className="flex flex-wrap items-center gap-2">
            {alert.allowed_transitions.map((status) => (
              <Button
                key={status}
                disabled={busy}
                variant={status === "FALSE_POSITIVE" ? "secondary" : "primary"}
                onClick={() => changeStatus(status)}
              >
                {transitionLabel(status)}
              </Button>
            ))}
            <span aria-hidden className="mx-1 h-5 w-px bg-line" />
            {alert.assigned_to?.id === me?.id ? (
              <Button disabled={busy} onClick={() => run(() => send("PUT", `alerts/${id}/assignee`, { user_id: null }))}>
                Unassign me
              </Button>
            ) : (
              <Button
                disabled={busy || !me}
                onClick={() => run(() => send("PUT", `alerts/${id}/assignee`, { user_id: me!.id }))}
              >
                Assign to me
              </Button>
            )}
          </div>
          {alert.status !== "NEW" && (
            <textarea
              aria-label="Note for the status change"
              placeholder="Optional note, saved with the next status change"
              value={note}
              maxLength={5000}
              onChange={(e) => setNote(e.target.value)}
              rows={2}
              className={`${inputClass} mt-3`}
            />
          )}
          {actionError && <div className="mt-3"><Notice tone="error">{actionError}</Notice></div>}
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card
            title="Recommended action"
            description="Advisory: Argus does not block traffic itself."
            tone={alert.severity === "CRITICAL" && alert.allowed_transitions.length && alert.status !== "RESOLVED" && alert.status !== "FALSE_POSITIVE" ? "critical" : undefined}
          >
            <p className="text-sm text-ink">{alert.recommended_action}</p>
          </Card>

          <Card
            title="Why the model flagged it"
            description={`Top factors behind the ${attackName(alert.attack_type)} prediction (SHAP), share of total attribution`}
          >
            <Factors alert={alert} />
          </Card>

          <Card title="Detections" description={`${alert.detection_count} aggregated into this alert; latest 10`}>
            <Detections data={events.data} />
          </Card>

          <Notes alert={alert} canAct={canAct} onAdded={() => mutate()} />
        </div>

        <div className="space-y-4">
          <Card title="Details">
            <Facts alert={alert} />
          </Card>
          <Card title="Risk score" description="Signals combined by the risk engine (0–100 each)">
            <p className="tabular mb-3 font-mono text-4xl font-semibold text-ink glow-text">
              {alert.risk_score}
              <span className="text-sm font-normal text-muted"> / 100</span>
            </p>
            <RiskBreakdown components={alert.risk_components} />
          </Card>
          <Card title="History">
            <History alert={alert} />
          </Card>
        </div>
      </div>
    </>
  );
}

function Facts({ alert }: { alert: AlertDetail }) {
  const rows: [string, React.ReactNode][] = [
    ["Source", <>{alert.source_ip}{alert.unique_sources > 1 && <span className="text-muted"> +{alert.unique_sources - 1} more</span>}</>],
    ["Target", target(alert.destination_ip, alert.destination_port)],
    ["Protocol", alert.protocol.toUpperCase()],
    ["Confidence", formatPercent(alert.confidence)],
    ["Peak packets", `${formatCount(alert.peak_packets_per_sec)}/s`],
    ["Peak bandwidth", formatBytesRate(alert.peak_bytes_per_sec)],
    ["First seen", formatTime(alert.first_seen_at)],
    ["Last seen", formatTime(alert.last_seen_at)],
    ["Assigned to", alert.assigned_to?.username ?? "Nobody"],
    [
      "Acknowledged",
      alert.acknowledged_by
        ? `${alert.acknowledged_by.username}, ${formatTime(alert.acknowledged_at!)}`
        : "Not yet",
    ],
    ...(alert.resolved_at ? [["Closed", formatTime(alert.resolved_at)] as [string, string]] : []),
    ["Model", <code key="m" className="text-xs">{alert.model_version}</code>],
  ];
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="label-caps self-center text-muted">{label}</dt>
          <dd className="tabular break-all text-right font-mono text-xs text-ink">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Factors({ alert }: { alert: AlertDetail }) {
  if (!alert.explanation.length) {
    return <p className="text-sm text-muted">No explanation was recorded for this detection.</p>;
  }
  const max = Math.max(...alert.explanation.map((f) => f.weight), 1);
  return (
    <ul className="space-y-3">
      {alert.explanation.map((factor) => (
        <li key={factor.feature}>
          <div className="flex justify-between gap-3 text-xs">
            <span className="text-ink" title={factor.feature}>
              {featureName(factor.feature)}
            </span>
            <span className="tabular whitespace-nowrap text-ink-2">
              value {formatCount(factor.value)} · {factor.weight.toFixed(1)}%
            </span>
          </div>
          <div className="mt-1 h-2 rounded-[1px] bg-accent/5">
            <div
              className="h-2 rounded-[1px] bg-accent shadow-[0_0_10px_-2px_var(--accent)]"
              style={{ width: `${(factor.weight / max) * 100}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

function RiskBreakdown({ components }: { components: Record<string, number> }) {
  const entries = Object.entries(components);
  if (!entries.length) return <p className="text-sm text-muted">No breakdown recorded.</p>;
  return (
    <ul className="space-y-2.5">
      {entries.map(([key, value]) => (
        <li key={key}>
          <div className="flex justify-between text-xs">
            <span className="text-ink">{RISK_COMPONENTS[key] ?? featureName(key)}</span>
            <span className="tabular text-ink-2">{Math.round(value)}</span>
          </div>
          <div className="mt-1 h-1.5 rounded-[1px] bg-accent/5">
            <div
              className="h-1.5 rounded-[1px] bg-accent-strong/70"
              style={{ width: `${Math.min(Math.max(value, 0), 100)}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

function Detections({ data }: { data?: Page<EventSummary> }) {
  if (!data) return <Skeleton className="h-32" />;
  if (!data.items.length) return <p className="text-sm text-muted">No detections stored.</p>;
  return (
    <div className="-mx-4 overflow-x-auto sm:mx-0">
      <table className="w-full min-w-[520px] text-left text-sm">
        <thead className="label-caps text-muted">
          <tr className="border-b border-line">
            <th className="px-4 py-2 font-medium sm:pl-0">Time</th>
            <th className="px-2 py-2 font-medium">Source</th>
            <th className="px-2 py-2 text-right font-medium">Packets/s</th>
            <th className="px-2 py-2 text-right font-medium">Confidence</th>
            <th className="px-4 py-2 text-right font-medium sm:pr-0">Risk</th>
          </tr>
        </thead>
        <tbody className="tabular font-mono text-xs">
          {data.items.map((event) => (
            <tr key={event.id} className="border-b border-line last:border-0">
              <td className="px-4 py-2 text-ink-2 sm:pl-0">{formatTime(event.ts)}</td>
              <td className="px-2 py-2 text-ink">{target(event.src_ip, event.src_port)}</td>
              <td className="px-2 py-2 text-right text-ink-2">{formatCount(event.packets_per_sec)}</td>
              <td className="px-2 py-2 text-right text-ink-2">{formatPercent(event.confidence)}</td>
              <td className="px-4 py-2 text-right text-ink sm:pr-0">{event.risk_score}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Notes({ alert, canAct, onAdded }: { alert: AlertDetail; canAct: boolean; onAdded: () => void }) {
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <Card title="Notes" description="Investigation notes are permanent and audited">
      {alert.notes.length ? (
        <ul className="mb-4 space-y-3">
          {alert.notes.map((n) => (
            <li key={n.id} className="rounded-sm bg-sunken border border-line p-3">
              <p className="text-xs text-muted">
                <span className="font-medium text-ink-2">{n.author.username}</span> · {formatTime(n.created_at)}
              </p>
              <p className="mt-1 whitespace-pre-wrap break-words text-sm text-ink">{n.body}</p>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mb-4 text-sm text-muted">No notes yet.</p>
      )}
      {canAct && (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (!body.trim()) return;
            setBusy(true);
            setError(null);
            try {
              await send("POST", `alerts/${alert.id}/notes`, { body: body.trim() });
              setBody("");
              onAdded();
            } catch (err) {
              setError(err instanceof Error ? err.message : "Could not save the note.");
            } finally {
              setBusy(false);
            }
          }}
        >
          <textarea
            aria-label="New note"
            placeholder="Add a note"
            value={body}
            maxLength={5000}
            rows={3}
            onChange={(e) => setBody(e.target.value)}
            className={inputClass}
          />
          {error && <div className="mt-2"><Notice tone="error">{error}</Notice></div>}
          <Button type="submit" disabled={busy || !body.trim()} className="mt-2">
            Add note
          </Button>
        </form>
      )}
    </Card>
  );
}

function describe(entry: AlertDetail["history"][number], alert: AlertDetail): string {
  const after = entry.after ?? {};
  const before = entry.before ?? {};
  switch (entry.action) {
    case "alert.created":
      return "Alert raised";
    case "alert.escalated":
      return `Escalated ${String(before.severity ?? "").toLowerCase()} → ${String(after.severity ?? "").toLowerCase()}`;
    case "alert.acknowledged":
      return "Acknowledged";
    case "alert.status_changed": {
      const status = after.status as AlertStatus | undefined;
      return `Status → ${status ? STATUS_LABEL[status] ?? status : "?"}`;
    }
    case "alert.note_added":
      return "Note added";
    case "alert.assigned":
      if (after.assigned_to_id == null) return "Unassigned";
      return after.assigned_to_id === alert.assigned_to?.id
        ? `Assigned to ${alert.assigned_to.username}`
        : `Assigned to user #${String(after.assigned_to_id)}`;
    default:
      return entry.action;
  }
}

function History({ alert }: { alert: AlertDetail }) {
  if (!alert.history.length) return <p className="text-sm text-muted">No changes yet.</p>;
  return (
    <ol className="space-y-3 border-l border-line pl-4">
      {alert.history.map((entry, i) => (
        <li key={i} className="relative">
          <span aria-hidden className="absolute -left-[21px] top-1.5 size-2 rotate-45 border border-accent bg-sunken" />
          <p className="text-sm text-ink">{describe(entry, alert)}</p>
          <p className="text-xs text-muted">
            {entry.actor} · {formatTime(entry.ts)}
          </p>
        </li>
      ))}
    </ol>
  );
}
