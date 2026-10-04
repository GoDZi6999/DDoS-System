"use client";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import useSWR from "swr";
import { AlertTable } from "@/components/alert-table";
import { PageHeader } from "@/components/shell";
import { Button, Card, Notice, Pagination, STATUS_LABEL, Skeleton, inputBase } from "@/components/ui";
import { attackName } from "@/lib/format";
import type { AlertStatus, AlertSummary, Page, Severity } from "@/lib/types";

const LIMIT = 25;
const STATUSES: AlertStatus[] = ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"];
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const ATTACKS = ["ddos", "dos", "portscan", "bruteforce", "webattack", "botnet"];
const PRESETS: Record<string, AlertStatus[]> = {
  Open: ["NEW", "INVESTIGATING", "CONTAINED"],
  Closed: ["RESOLVED", "FALSE_POSITIVE"],
  All: [],
};

function Chip({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className={`rounded-full border px-2.5 py-1 text-xs font-medium ${
        on ? "border-accent bg-accent/15 text-ink" : "border-line text-ink-2 hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}

export function AlertsList() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();

  // Filters live in the URL so a filtered view can be shared or bookmarked.
  const statuses = params.getAll("status") as AlertStatus[];
  const severities = params.getAll("severity") as Severity[];
  const attack = params.get("attack_type") ?? "";
  const ip = params.get("ip") ?? "";
  const sort = params.get("sort") === "risk" ? "risk" : "last_seen";
  const offset = Math.max(0, Number(params.get("offset")) || 0);
  const [ipDraft, setIpDraft] = useState(ip);

  const update = (changes: Record<string, string | string[] | null>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      next.delete(key);
      for (const v of value === null ? [] : Array.isArray(value) ? value : [value]) {
        if (v) next.append(key, v);
      }
    }
    if (!("offset" in changes)) next.delete("offset");
    router.replace(`${pathname}${next.size ? `?${next}` : ""}`, { scroll: false });
  };
  const toggle = <T extends string>(list: T[], value: T) =>
    list.includes(value) ? list.filter((v) => v !== value) : [...list, value];

  const query = new URLSearchParams();
  statuses.forEach((s) => query.append("status", s));
  severities.forEach((s) => query.append("severity", s));
  if (attack) query.set("attack_type", attack);
  if (ip) query.set("ip", ip);
  query.set("sort", sort);
  query.set("limit", String(LIMIT));
  query.set("offset", String(offset));
  const { data, error, isLoading } = useSWR<Page<AlertSummary>>(`alerts?${query}`, {
    keepPreviousData: true,
  });

  const activePreset = Object.entries(PRESETS).find(
    ([, preset]) => preset.length === statuses.length && preset.every((s) => statuses.includes(s)),
  )?.[0];

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Detections are grouped by attack type and target; a flood raises one alert, not thousands."
      />
      <Card>
        <div className="flex flex-col gap-3 border-b border-line pb-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="w-16 text-xs text-muted">Status</span>
            {Object.keys(PRESETS).map((name) => (
              <Chip key={name} on={activePreset === name} onClick={() => update({ status: PRESETS[name] })}>
                {name}
              </Chip>
            ))}
            <span aria-hidden className="mx-1 h-4 w-px bg-line" />
            {STATUSES.map((s) => (
              <Chip key={s} on={statuses.includes(s)} onClick={() => update({ status: toggle(statuses, s) })}>
                {STATUS_LABEL[s]}
              </Chip>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="w-16 text-xs text-muted">Severity</span>
            {SEVERITIES.map((s) => (
              <Chip
                key={s}
                on={severities.includes(s)}
                onClick={() => update({ severity: toggle(severities, s) })}
              >
                {s.charAt(0) + s.slice(1).toLowerCase()}
              </Chip>
            ))}
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <select
              aria-label="Attack type"
              value={attack}
              onChange={(e) => update({ attack_type: e.target.value })}
              className={`${inputBase} w-auto`}
            >
              <option value="">All attack types</option>
              {ATTACKS.map((a) => (
                <option key={a} value={a}>
                  {attackName(a)}
                </option>
              ))}
            </select>
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                update({ ip: ipDraft.trim() });
              }}
            >
              <input
                aria-label="IP address"
                placeholder="Source or target IP"
                value={ipDraft}
                onChange={(e) => setIpDraft(e.target.value)}
                className={`${inputBase} w-48`}
              />
              <Button type="submit">Search</Button>
            </form>
            <select
              aria-label="Sort"
              value={sort}
              onChange={(e) => update({ sort: e.target.value === "risk" ? "risk" : null })}
              className={`${inputBase} ml-auto w-auto`}
            >
              <option value="last_seen">Most recent first</option>
              <option value="risk">Highest risk first</option>
            </select>
          </div>
        </div>

        <div className="pt-2">
          {error ? (
            <Notice tone="error">{error.message}</Notice>
          ) : !data && isLoading ? (
            <Skeleton className="h-64" />
          ) : data && data.items.length ? (
            <>
              <AlertTable alerts={data.items} />
              <Pagination
                offset={offset}
                limit={LIMIT}
                total={data.total}
                onChange={(o) => update({ offset: o ? String(o) : null })}
              />
            </>
          ) : (
            <p className="py-10 text-center text-sm text-muted">No alerts match these filters.</p>
          )}
        </div>
      </Card>
    </>
  );
}
