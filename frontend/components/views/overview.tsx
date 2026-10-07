"use client";
import Link from "next/link";
import { useState } from "react";
import useSWR from "swr";
import { ActivityChart, DistributionBars, LiveTrafficChart } from "@/components/charts";
import { AlertTable } from "@/components/alert-table";
import { PageHeader } from "@/components/shell";
import { EventFeed } from "@/components/event-feed";
import { Card, Notice, SeverityBadge, Skeleton, StatTile, severityColor } from "@/components/ui";
import { formatCount, formatRate } from "@/lib/format";
import { useLive } from "@/lib/live";
import type { AlertSummary, Distribution, Page, StatsSummary, Timeseries } from "@/lib/types";

const WINDOWS = { "1h": "5m", "6h": "15m", "24h": "15m", "7d": "6h" } as const;
type Window = keyof typeof WINDOWS;
const WINDOW_LABEL: Record<Window, string> = {
  "1h": "last hour",
  "6h": "last 6 hours",
  "24h": "last 24 hours",
  "7d": "last 7 days",
};
const OPEN = "status=NEW&status=INVESTIGATING&status=CONTAINED";

export function Overview() {
  const [window, setWindow] = useState<Window>("24h");
  const summary = useSWR<StatsSummary>(`stats/summary?window=${window}`, { refreshInterval: 30_000 });
  const series = useSWR<Timeseries>(`stats/timeseries?window=${window}&bucket=${WINDOWS[window]}`, {
    refreshInterval: 60_000,
  });
  const distribution = useSWR<Distribution>(`stats/distribution?window=${window}`, {
    refreshInterval: 60_000,
  });
  const alerts = useSWR<Page<AlertSummary>>(`alerts?${OPEN}&limit=8`);

  const error = summary.error ?? series.error ?? distribution.error ?? alerts.error;
  const s = summary.data;
  const severities = s
    ? (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)
        .filter((sev) => s.open_alerts_by_severity[sev])
        .map((sev) => `${s.open_alerts_by_severity[sev]} ${sev.toLowerCase()}`)
        .join(" · ")
    : "";

  return (
    <>
      <PageHeader
        title="Overview"
        description="Detections from the real-time engine. Argus detects and alerts; it does not block traffic."
        actions={
          <div role="group" aria-label="Time window" className="flex rounded-sm border border-line-strong bg-sunken p-0.5">
            {(Object.keys(WINDOWS) as Window[]).map((w) => (
              <button
                key={w}
                type="button"
                aria-pressed={w === window}
                onClick={() => setWindow(w)}
                className={`rounded-sm px-2.5 py-1 font-mono text-xs uppercase ${
                  w === window ? "bg-accent/15 text-accent-strong" : "text-ink-2 hover:text-ink"
                }`}
              >
                {w}
              </button>
            ))}
          </div>
        }
      />

      {error && <div className="mb-4"><Notice tone="error">{error.message}</Notice></div>}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {s ? (
          <>
            <StatTile
              label="Open alerts"
              value={formatCount(s.alerts_open)}
              detail={severities || "Nothing open"}
              accent={s.alerts_open ? severityColor(s.severity) : "var(--status-good)"}
            />
            <StatTile
              label="Highest open risk"
              value={s.alerts_open ? s.risk_score : "–"}
              detail={s.alerts_open ? <SeverityBadge severity={s.severity} /> : "No open alerts"}
              accent={s.alerts_open ? severityColor(s.severity) : "var(--status-good)"}
            />
            <StatTile
              label="Flows analysed"
              value={formatCount(s.events)}
              detail={WINDOW_LABEL[window]}
              accent="var(--series-1)"
            />
            <StatTile
              label="Attack flows"
              accent={s.attacks ? "var(--status-critical)" : "var(--status-good)"}
              value={formatCount(s.attacks)}
              detail={
                s.events
                  ? `${((s.attacks / s.events) * 100).toFixed(2)}% of flows · ${WINDOW_LABEL[window]}`
                  : WINDOW_LABEL[window]
              }
            />
          </>
        ) : (
          Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-[98px]" />)
        )}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <LiveCard />
        <Card title="Event feed" description="Alert events as they happen">
          <EventFeed />
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card
          title="Activity"
          description={`Flows analysed per ${WINDOWS[window]}, ${WINDOW_LABEL[window]}`}
          className="lg:col-span-2"
        >
          {series.data ? <ActivityChart series={series.data} /> : <Skeleton className="h-64" />}
        </Card>
        <Card title="Attack types" description={`Attack flows by type, ${WINDOW_LABEL[window]}`}>
          {distribution.data ? (
            <DistributionBars distribution={distribution.data} />
          ) : (
            <Skeleton className="h-64" />
          )}
        </Card>
      </div>

      <Card
        title="Open alerts"
        description="Most recently active first; updates live"
        className="mt-4"
        actions={
          <Link href="/alerts" className="text-sm text-accent hover:underline">
            All alerts →
          </Link>
        }
      >
        {alerts.data ? (
          alerts.data.items.length ? (
            <AlertTable alerts={alerts.data.items} compact />
          ) : (
            <p className="py-6 text-center text-sm text-muted">No open alerts.</p>
          )
        ) : (
          <Skeleton className="h-40" />
        )}
      </Card>
    </>
  );
}

function LiveCard() {
  const { ticks, status } = useLive();
  const last = ticks.at(-1);
  return (
    <Card
      title="Live traffic"
      description="Flows classified per second by the engine, last 5 minutes"
      className="xl:col-span-2"
      actions={
        last && (
          <dl className="tabular flex gap-5 text-right font-mono text-xs">
            <div>
              <dt className="label-caps text-muted">Flows</dt>
              <dd className="font-medium text-ink">{formatRate(last.flows_per_s, "")}</dd>
            </div>
            <div>
              <dt className="label-caps text-muted">Packets</dt>
              <dd className="font-medium text-ink">{formatRate(last.packets_per_s, "")}</dd>
            </div>
            <div>
              <dt className="label-caps text-muted">Attack flows</dt>
              <dd className="font-medium text-ink">
                {formatRate(last.attacks_per_s ?? last.attacks, "")}
              </dd>
            </div>
            <div>
              <dt className="label-caps text-muted">Active flows</dt>
              <dd className="font-medium text-ink">{formatCount(last.active_flows)}</dd>
            </div>
          </dl>
        )
      }
    >
      {ticks.length > 1 ? (
        <LiveTrafficChart ticks={ticks} />
      ) : (
        <p className="flex h-56 items-center justify-center text-sm text-muted">
          {status === "live"
            ? "Waiting for traffic from the engine…"
            : "Connecting to the live feed…"}
        </p>
      )}
    </Card>
  );
}
