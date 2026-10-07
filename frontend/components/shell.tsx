"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import useSWR from "swr";
import { logoutAction } from "@/app/actions";
import {
  AlertIcon,
  BellIcon,
  LogIcon,
  PowerIcon,
  RadarIcon,
  EyeIcon,
  SlidersIcon,
  UsersIcon,
} from "@/components/icons";
import { useLive, type LiveStatus } from "@/lib/live";
import { hasRole, useMe } from "@/lib/user";
import type { Role, StatsSummary } from "@/lib/types";

const NAV: { href: string; label: string; role: Role; icon: typeof RadarIcon }[] = [
  { href: "/", label: "Overview", role: "viewer", icon: RadarIcon },
  { href: "/alerts", label: "Alerts", role: "viewer", icon: AlertIcon },
  { href: "/audit", label: "Audit log", role: "admin", icon: LogIcon },
  { href: "/notifications", label: "Notifications", role: "admin", icon: BellIcon },
  { href: "/users", label: "Users", role: "admin", icon: UsersIcon },
  { href: "/settings", label: "Settings", role: "viewer", icon: SlidersIcon },
];

const LIVE: Record<LiveStatus, { label: string; color: string }> = {
  connecting: { label: "Connecting", color: "var(--status-neutral)" },
  live: { label: "Live", color: "var(--live)" },
  offline: { label: "Reconnecting", color: "var(--status-warning)" },
};

const THREAT = {
  NOMINAL: { label: "Nominal", color: "var(--status-good)", level: 0 },
  LOW: { label: "Guarded", color: "var(--status-neutral)", level: 1 },
  MEDIUM: { label: "Elevated", color: "var(--status-warning)", level: 2 },
  HIGH: { label: "High", color: "var(--status-serious)", level: 3 },
  CRITICAL: { label: "Critical", color: "var(--status-critical)", level: 4 },
} as const;

function Brand() {
  return (
    <Link href="/" className="group flex items-center gap-2.5">
      <span className="relative grid size-9 place-items-center rounded-sm border border-accent/50 bg-accent/10 text-accent shadow-[0_0_18px_-6px_var(--accent)]">
        <EyeIcon className="size-5" />
      </span>
      <span className="leading-tight">
        <span className="block font-display text-base font-bold tracking-[0.18em] text-ink">
          AR<span className="text-accent">GUS</span>
        </span>
        <span className="label-caps block text-[0.6rem] text-muted">SOC console</span>
      </span>
    </Link>
  );
}

function ThreatLevel() {
  const { data } = useSWR<StatsSummary>("stats/summary?window=24h", { refreshInterval: 30_000 });
  const key = !data ? null : data.alerts_open ? data.severity : "NOMINAL";
  const threat = key ? THREAT[key] : null;
  return (
    <div className="flex items-center gap-2" role="status" aria-label="Threat level">
      <span className="label-caps hidden text-muted sm:inline">Threat level</span>
      <span
        className="inline-flex items-center gap-2 rounded-sm border px-2 py-1 font-mono text-xs font-semibold uppercase tracking-wider text-ink"
        style={{
          borderColor: threat ? `color-mix(in oklab, ${threat.color} 60%, transparent)` : "var(--border)",
          background: threat ? `color-mix(in oklab, ${threat.color} 14%, transparent)` : undefined,
        }}
      >
        <span aria-hidden className="flex gap-0.5">
          {[1, 2, 3, 4].map((i) => (
            <span
              key={i}
              className="h-3 w-1 rounded-[1px]"
              style={{
                background: threat && threat.level >= i ? threat.color : "var(--border-strong)",
              }}
            />
          ))}
        </span>
        {threat ? threat.label : "…"}
      </span>
    </div>
  );
}

function Clock() {
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <span className="tabular hidden font-mono text-xs text-ink-2 md:inline" aria-label="Current UTC time">
      {now ? `${now.toISOString().slice(11, 19)} UTC` : "--:--:-- UTC"}
    </span>
  );
}

function LiveLink({ status }: { status: LiveStatus }) {
  return (
    <span className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-ink-2" role="status">
      <span
        aria-hidden
        className={`size-2 rounded-full ${status === "live" ? "pulse" : ""}`}
        style={{ background: LIVE[status].color, color: LIVE[status].color }}
      />
      {LIVE[status].label}
    </span>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: me } = useMe();
  const { status } = useLive();
  const active = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));
  const items = NAV.filter((item) => !me || hasRole(me, item.role));

  return (
    <div className="flex min-h-full flex-1">
      {/* Desktop rail */}
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-sunken/80 px-4 py-5 backdrop-blur lg:flex">
        <Brand />
        <nav aria-label="Main" className="mt-8 flex flex-col gap-1">
          {items.map(({ href, label, icon: Icon }) => (
            <Link
              key={href}
              href={href}
              aria-current={active(href) ? "page" : undefined}
              className={`group relative flex items-center gap-3 rounded-sm px-3 py-2 text-sm transition ${
                active(href)
                  ? "bg-accent/10 text-accent-strong"
                  : "text-ink-2 hover:bg-accent/5 hover:text-ink"
              }`}
            >
              <span
                aria-hidden
                className={`absolute inset-y-1 left-0 w-[2px] ${active(href) ? "bg-accent shadow-[0_0_10px_var(--accent)]" : "bg-transparent"}`}
              />
              <Icon className="size-4" />
              {label}
            </Link>
          ))}
        </nav>
        <div className="mt-auto space-y-3 border-t border-line pt-4">
          <LiveLink status={status} />
          <p className="font-mono text-[11px] leading-relaxed text-muted">
            Detection &amp; alerting only.
            <br />
            No traffic is blocked.
          </p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 border-b border-line bg-page/85 backdrop-blur">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3 sm:px-6">
            <div className="lg:hidden">
              <Brand />
            </div>
            <ThreatLevel />
            <div className="ml-auto flex items-center gap-4 text-sm">
              <Clock />
              <span className="lg:hidden">
                <LiveLink status={status} />
              </span>
              {me && (
                <span className="flex items-center gap-2 font-mono text-xs text-ink-2">
                  <span className="text-ink">{me.username}</span>
                  <span className="rounded-sm border border-line-strong px-1.5 py-0.5 uppercase tracking-wider text-accent">
                    {me.role}
                  </span>
                </span>
              )}
              <form action={logoutAction}>
                <button
                  type="submit"
                  className="flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-ink-2 hover:text-critical"
                >
                  <PowerIcon className="size-3.5" />
                  Sign out
                </button>
              </form>
            </div>
          </div>
          {/* Mobile and tablet navigation */}
          <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-3 pb-2 lg:hidden">
            {items.map(({ href, label, icon: Icon }) => (
              <Link
                key={href}
                href={href}
                aria-current={active(href) ? "page" : undefined}
                className={`flex shrink-0 items-center gap-1.5 rounded-sm px-2.5 py-1.5 text-sm ${
                  active(href) ? "bg-accent/10 text-accent-strong" : "text-ink-2"
                }`}
              >
                <Icon className="size-3.5" />
                {label}
              </Link>
            ))}
          </nav>
        </header>
        <main className="w-full max-w-[1600px] flex-1 px-4 py-6 sm:px-6">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <p className="label-caps text-accent">
          <span aria-hidden>{"// "}</span>Argus
        </p>
        <h1 className="mt-1 font-display text-2xl font-bold uppercase tracking-[0.08em] text-ink">
          {title}
        </h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-ink-2">{description}</p>}
      </div>
      {actions}
    </div>
  );
}
