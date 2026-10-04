"use client";
import Link from "next/link";
import { severityColor } from "@/components/ui";
import { attackName, target } from "@/lib/format";
import { useLive } from "@/lib/live";

const clock = (ms: number) => new Date(ms).toISOString().slice(11, 19);

/** Terminal-style stream of alert events as they arrive over the live feed. */
export function EventFeed() {
  const { feed, status } = useLive();
  return (
    <div
      className="relative h-[17rem] overflow-y-auto rounded-sm border border-line bg-sunken p-3 font-mono text-xs leading-relaxed"
      role="log"
      aria-live="polite"
      aria-label="Live alert events"
    >
      {feed.length === 0 ? (
        <p className="text-muted">
          <span className="text-accent">sentinel@soc</span>:~$ tail -f alerts
          <br />
          {status === "live" ? "waiting for alert events" : "connecting to live feed"}
          <span aria-hidden className="ml-0.5 inline-block w-2 animate-pulse bg-accent">
            &nbsp;
          </span>
        </p>
      ) : (
        <ol className="space-y-1">
          {feed.map((event) => (
            <li key={event.id} className="feed-in flex gap-2">
              <span className="tabular shrink-0 text-muted">{clock(event.at)}</span>
              <span
                className="w-14 shrink-0 font-semibold uppercase"
                style={{ color: severityColor(event.alert.severity) }}
              >
                {event.alert.severity.slice(0, 4)}
              </span>
              <span className="w-12 shrink-0 uppercase text-ink-2">
                {event.kind === "alert.new" ? "new" : "upd"}
              </span>
              <Link href={`/alerts/${event.alert.id}`} className="min-w-0 truncate text-ink hover:text-accent">
                {attackName(event.alert.attack_type)} → {target(event.alert.destination_ip, event.alert.destination_port)}
                <span className="text-muted">
                  {" "}
                  risk {event.alert.risk_score} · {event.alert.detection_count} det
                </span>
              </Link>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
