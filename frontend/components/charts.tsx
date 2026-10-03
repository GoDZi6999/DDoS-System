"use client";
// Charts follow the dataviz rules in docs: one axis, thin marks, recessive
// grid, a legend for 2+ series, a tooltip on hover, text in ink colours.
// Benign traffic is series-1 blue; attack traffic is status-critical and is
// always named in the legend and tooltip.
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { attackName, formatCount } from "@/lib/format";
import type { Distribution, Timeseries, TrafficTick } from "@/lib/types";

const BENIGN = "var(--series-1)";
const ATTACK = "var(--status-critical)";
const AXIS = { stroke: "var(--axis)", fontSize: 11, tick: { fill: "var(--text-muted)" } };

type TooltipRow = { name: string; value: number; color: string };

function TooltipBox({ title, rows, unit }: { title: string; rows: TooltipRow[]; unit?: string }) {
  return (
    <div className="rounded-lg border border-line bg-raised px-3 py-2 text-xs shadow-sm">
      <p className="mb-1 font-medium text-ink">{title}</p>
      {rows.map((row) => (
        <p key={row.name} className="flex items-center gap-2 text-ink-2">
          <span aria-hidden className="size-2 rounded-sm" style={{ background: row.color }} />
          <span>{row.name}</span>
          <span className="tabular ml-auto pl-3 font-medium text-ink">
            {formatCount(row.value)}
            {unit}
          </span>
        </p>
      ))}
    </div>
  );
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2">
      {items.map((item) => (
        <li key={item.label} className="flex items-center gap-1.5">
          <span aria-hidden className="size-2.5 rounded-sm" style={{ background: item.color }} />
          {item.label}
        </li>
      ))}
    </ul>
  );
}

const clock = (iso: string) =>
  new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

/** Benign vs attack flows per second, one point per engine tick. */
export function LiveTrafficChart({ ticks }: { ticks: TrafficTick[] }) {
  const data = ticks.map((tick) => {
    const attacks = Math.min(tick.attacks_per_s ?? tick.attacks, tick.flows_per_s);
    return { ts: tick.ts, benign: Math.max(tick.flows_per_s - attacks, 0), attacks };
  });
  return (
    <div>
      <Legend
        items={[
          { label: "Benign flows/s", color: BENIGN },
          { label: "Attack flows/s", color: ATTACK },
        ]}
      />
      <div className="mt-3 h-56" role="img" aria-label="Live flows per second, benign and attack">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="ts" tickFormatter={clock} minTickGap={48} {...AXIS} />
            <YAxis allowDecimals={false} tickFormatter={formatCount} {...AXIS} />
            <Tooltip
              isAnimationActive={false}
              cursor={{ stroke: "var(--axis)" }}
              content={({ active, payload, label }) =>
                active && payload?.length ? (
                  <TooltipBox
                    title={clock(String(label))}
                    unit="/s"
                    rows={[
                      { name: "Attack flows", value: Number(payload[0].payload.attacks), color: ATTACK },
                      { name: "Benign flows", value: Number(payload[0].payload.benign), color: BENIGN },
                    ]}
                  />
                ) : null
              }
            />
            <Area
              type="monotone"
              dataKey="benign"
              name="Benign flows/s"
              stackId="flows"
              stroke="var(--surface)"
              strokeWidth={2}
              fill={BENIGN}
              fillOpacity={0.85}
              isAnimationActive={false}
            />
            <Area
              type="monotone"
              dataKey="attacks"
              name="Attack flows/s"
              stackId="flows"
              stroke="var(--surface)"
              strokeWidth={2}
              fill={ATTACK}
              fillOpacity={0.9}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/** Flows analysed per bucket, split into benign and attack. */
export function ActivityChart({ series }: { series: Timeseries }) {
  const long = series.window === "7d";
  const label = (iso: string) =>
    new Date(iso).toLocaleString("en-GB", long
      ? { day: "2-digit", month: "short", hour: "2-digit" }
      : { hour: "2-digit", minute: "2-digit" });
  const data = series.points.map((p) => ({
    ts: p.ts,
    benign: Math.max(p.events - p.attacks, 0),
    attacks: p.attacks,
  }));
  return (
    <div>
      <Legend
        items={[
          { label: "Benign flows", color: BENIGN },
          { label: "Attack flows", color: ATTACK },
        ]}
      />
      <div className="mt-3 h-56" role="img" aria-label="Flows analysed over time, benign and attack">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -12 }} barCategoryGap={1}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="ts" tickFormatter={label} minTickGap={40} {...AXIS} />
            <YAxis allowDecimals={false} tickFormatter={formatCount} {...AXIS} />
            <Tooltip
              cursor={{ fill: "var(--grid)", opacity: 0.5 }}
              content={({ active, payload, label: ts }) =>
                active && payload?.length ? (
                  <TooltipBox
                    title={new Date(String(ts)).toLocaleString("en-GB", {
                      day: "2-digit",
                      month: "short",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                    rows={[
                      { name: "Attack flows", value: Number(payload[0].payload.attacks), color: ATTACK },
                      { name: "Benign flows", value: Number(payload[0].payload.benign), color: BENIGN },
                    ]}
                  />
                ) : null
              }
            />
            <Bar dataKey="benign" stackId="flows" fill={BENIGN} isAnimationActive={false} />
            <Bar
              dataKey="attacks"
              stackId="flows"
              fill={ATTACK}
              radius={[3, 3, 0, 0]}
              isAnimationActive={false}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function share(count: number, total: number): string {
  const percent = (count / total) * 100;
  return percent > 0 && percent < 1 ? "<1%" : `${percent.toFixed(0)}%`;
}

/** Attack flows per type; one colour, the label carries identity. */
export function DistributionBars({ distribution }: { distribution: Distribution }) {
  const items = distribution.items
    .filter((item) => item.label !== "benign" && item.count > 0)
    .sort((a, b) => b.count - a.count);
  if (!items.length) {
    return <p className="py-8 text-center text-sm text-muted">No attack flows in this window.</p>;
  }
  const max = Math.max(...items.map((item) => item.count));
  const total = items.reduce((sum, item) => sum + item.count, 0);
  return (
    <ul className="space-y-3">
      {items.map((item) => (
        <li key={item.label} title={`${attackName(item.label)}: ${item.count} flows`}>
          <div className="flex justify-between text-xs">
            <span className="text-ink">{attackName(item.label)}</span>
            <span className="tabular text-ink-2">
              {formatCount(item.count)} · {share(item.count, total)}
            </span>
          </div>
          <div className="mt-1 h-2 rounded-full bg-ink/5">
            <div
              className="h-2 rounded-full bg-accent"
              style={{ width: `${Math.max((item.count / max) * 100, 1.5)}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}
