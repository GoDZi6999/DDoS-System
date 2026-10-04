"use client";
import useSWR from "swr";
import { PageHeader } from "@/components/shell";
import { Card, Notice, Skeleton, StatTile } from "@/components/ui";
import { formatCount, formatRate, timeAgo } from "@/lib/format";
import type { Sensor, SensorList, SensorStatus } from "@/lib/types";

const STATUS: Record<SensorStatus, { label: string; dot: string }> = {
  online: { label: "Online", dot: "bg-good" },
  stale: { label: "Stale", dot: "bg-warning" },
  offline: { label: "Offline", dot: "bg-[var(--status-neutral)]" },
};

const SETUP = `docker compose -f docker-compose.yml -f docker-compose.sensor.yml up -d --wait
pip install -r engine/requirements-sensor.txt
SENSOR_REDIS_URL=redis://sensor:<password>@localhost:6379/0 \\
  python -m sentinel_engine.sensor --interface eth0 --name my-laptop`;

function SensorStatusBadge({ status }: { status: SensorStatus }) {
  const { label, dot } = STATUS[status];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-ink/5 px-2 py-0.5 text-xs font-medium text-ink">
      <span aria-hidden className={`size-2 rounded-full ${dot}`} />
      {label}
    </span>
  );
}

function Problems({ sensor }: { sensor: Sensor }) {
  const issues = [
    sensor.flows_buffered > 0 && `${formatCount(sensor.flows_buffered)} flows waiting to send`,
    sensor.flows_dropped > 0 && `${formatCount(sensor.flows_dropped)} flows lost (buffer full)`,
    sensor.capture_drops > 0 && `${formatCount(sensor.capture_drops)} packets dropped by capture`,
  ].filter(Boolean);
  if (!issues.length) return <span className="text-muted">–</span>;
  return <span className="text-ink">{issues.join(" · ")}</span>;
}

function Setup() {
  return (
    <div className="space-y-3 py-6 text-sm text-ink-2">
      <p className="text-ink">No capture sensor has reported yet.</p>
      <p>
        Sensors capture real traffic on the host where they run and send flow statistics (never
        payloads) to this stack. Start the stack with the sensor overlay, then run a sensor:
      </p>
      <pre className="overflow-x-auto rounded-lg bg-ink/5 p-3 text-xs text-ink">{SETUP}</pre>
      <p>Windows, Linux and macOS setup is described in engine/README.md.</p>
    </div>
  );
}

export function SensorsView() {
  const { data, error } = useSWR<SensorList>("sensors", { refreshInterval: 5_000 });
  const online = data?.items.filter((s) => s.status === "online") ?? [];
  const rate = online.reduce((sum, s) => sum + s.packets_per_s, 0);
  const backlog = data?.backlog;

  return (
    <>
      <PageHeader
        title="Sensors"
        description="Capture sensors shipping real traffic to the engine. Refreshes every 5 seconds."
      />
      {error ? (
        <Notice tone="error">{error.message}</Notice>
      ) : !data ? (
        <Skeleton className="h-64" />
      ) : (
        <>
          <div className="mb-4 grid gap-3 sm:grid-cols-3">
            <StatTile
              label="Sensors online"
              value={`${online.length} / ${data.items.length}`}
              detail="Reported within the last 15 seconds"
            />
            <StatTile label="Captured traffic" value={formatRate(rate, "pkt")} detail="All online sensors" />
            <StatTile
              label="Engine backlog"
              value={backlog ? formatCount((backlog.lag ?? 0) + backlog.pending) : "–"}
              detail={backlog ? "Flows not yet classified" : "The engine is not reading sensor flows"}
            />
          </div>
          <Card>
            {data.items.length ? (
              <div className="-mx-4 overflow-x-auto sm:mx-0">
                <table className="w-full min-w-[860px] text-left text-sm">
                  <thead className="text-xs text-muted">
                    <tr className="border-b border-line">
                      <th className="px-4 py-2 font-medium sm:pl-0">Sensor</th>
                      <th className="px-2 py-2 font-medium">Status</th>
                      <th className="px-2 py-2 font-medium">Interface</th>
                      <th className="px-2 py-2 text-right font-medium">Traffic</th>
                      <th className="px-2 py-2 text-right font-medium">Flows sent</th>
                      <th className="px-2 py-2 font-medium">Last seen</th>
                      <th className="px-4 py-2 font-medium sm:pr-0">Problems</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((sensor) => (
                      <tr key={sensor.name} className="border-b border-line align-top last:border-0">
                        <td className="px-4 py-2 sm:pl-0">
                          <div className="font-medium text-ink">{sensor.name}</div>
                          <div className="text-xs text-muted">
                            {sensor.hostname} · {sensor.platform}
                          </div>
                        </td>
                        <td className="px-2 py-2">
                          <SensorStatusBadge status={sensor.status} />
                        </td>
                        <td className="px-2 py-2 text-ink-2">
                          {sensor.interface}
                          {sensor.filter && (
                            <div className="text-xs text-muted">
                              filter <code>{sensor.filter}</code>
                            </div>
                          )}
                        </td>
                        <td className="tabular px-2 py-2 text-right text-ink">
                          {sensor.status === "offline" ? "–" : formatRate(sensor.packets_per_s, "pkt")}
                        </td>
                        <td className="tabular px-2 py-2 text-right text-ink-2">
                          {formatCount(sensor.flows_sent)}
                        </td>
                        <td className="tabular whitespace-nowrap px-2 py-2 text-ink-2">
                          {sensor.last_seen ? timeAgo(sensor.last_seen) : "never"}
                        </td>
                        <td className="px-4 py-2 text-xs sm:pr-0">
                          <Problems sensor={sensor} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Setup />
            )}
          </Card>
        </>
      )}
    </>
  );
}
