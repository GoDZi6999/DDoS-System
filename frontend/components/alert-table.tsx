"use client";
import Link from "next/link";
import { attackName, formatPercent, target, timeAgo } from "@/lib/format";
import type { AlertSummary } from "@/lib/types";
import { SeverityBadge, StatusBadge } from "@/components/ui";

export function AlertTable({ alerts, compact = false }: { alerts: AlertSummary[]; compact?: boolean }) {
  return (
    <div className="-mx-4 overflow-x-auto sm:mx-0">
      <table className="w-full min-w-[640px] text-left text-sm">
        <thead className="label-caps text-muted">
          <tr className="border-b border-line">
            <th className="px-4 py-2 font-medium sm:pl-0">Severity</th>
            <th className="px-2 py-2 font-medium">Alert</th>
            <th className="px-2 py-2 font-medium">Source</th>
            {!compact && <th className="px-2 py-2 text-right font-medium">Confidence</th>}
            <th className="px-2 py-2 text-right font-medium">Risk</th>
            <th className="px-2 py-2 font-medium">Status</th>
            <th className="px-4 py-2 text-right font-medium sm:pr-0">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="border-b border-line last:border-0 hover:bg-accent/5">
              <td className="px-4 py-2.5 sm:pl-0">
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="px-2 py-2.5">
                <Link href={`/alerts/${alert.id}`} className="font-medium text-ink hover:text-accent">
                  {attackName(alert.attack_type)} → {target(alert.destination_ip, alert.destination_port)}
                </Link>
                <span className="block font-mono text-[11px] text-muted">
                  #{alert.id} · {alert.detection_count} detection{alert.detection_count === 1 ? "" : "s"}
                  {alert.assigned_to ? ` · ${alert.assigned_to.username}` : ""}
                </span>
              </td>
              <td className="tabular px-2 py-2.5 font-mono text-xs text-ink-2">{alert.source_ip}</td>
              {!compact && (
                <td className="tabular px-2 py-2.5 text-right text-ink-2">
                  {formatPercent(alert.confidence)}
                </td>
              )}
              <td className="tabular px-2 py-2.5 text-right font-mono font-semibold text-ink">{alert.risk_score}</td>
              <td className="px-2 py-2.5">
                <StatusBadge status={alert.status} />
              </td>
              <td className="tabular px-4 py-2.5 text-right text-ink-2 sm:pr-0" title={alert.last_seen_at}>
                {timeAgo(alert.last_seen_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
