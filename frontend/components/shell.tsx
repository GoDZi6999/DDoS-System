"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { logoutAction } from "@/app/actions";
import { useLive, type LiveStatus } from "@/lib/live";
import { hasRole, useMe } from "@/lib/user";
import type { Role } from "@/lib/types";

const NAV: { href: string; label: string; role: Role }[] = [
  { href: "/", label: "Overview", role: "viewer" },
  { href: "/alerts", label: "Alerts", role: "viewer" },
  { href: "/audit", label: "Audit log", role: "admin" },
  { href: "/users", label: "Users", role: "admin" },
  { href: "/settings", label: "Settings", role: "viewer" },
];

const LIVE: Record<LiveStatus, { label: string; dot: string }> = {
  connecting: { label: "Connecting", dot: "bg-[var(--status-neutral)]" },
  live: { label: "Live", dot: "bg-good" },
  offline: { label: "Reconnecting", dot: "bg-warning" },
};

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: me } = useMe();
  const { status } = useLive();

  const active = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  return (
    <div className="flex min-h-full flex-1 flex-col">
      <header className="sticky top-0 z-10 border-b border-line bg-page/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <Link href="/" className="text-sm font-semibold tracking-wide text-ink">
            <span className="text-accent">Sentinel</span>AI
          </Link>
          <nav aria-label="Main" className="-mx-1 flex flex-1 gap-1 overflow-x-auto">
            {NAV.filter((item) => !me || hasRole(me, item.role)).map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active(item.href) ? "page" : undefined}
                className={`whitespace-nowrap rounded-md px-2.5 py-1.5 text-sm ${
                  active(item.href)
                    ? "bg-ink/5 font-medium text-ink"
                    : "text-ink-2 hover:bg-ink/5 hover:text-ink"
                }`}
              >
                {item.label}
              </Link>
            ))}
          </nav>
          <div className="flex items-center gap-4 text-sm">
            <span className="flex items-center gap-1.5 text-ink-2" role="status">
              <span aria-hidden className={`size-2 rounded-full ${LIVE[status].dot}`} />
              {LIVE[status].label}
            </span>
            {me && (
              <span className="text-ink-2">
                <span className="font-medium text-ink">{me.username}</span>{" "}
                <span className="rounded bg-ink/5 px-1.5 py-0.5 text-xs">{me.role}</span>
              </span>
            )}
            <form action={logoutAction}>
              <button type="submit" className="text-ink-2 hover:text-ink hover:underline">
                Sign out
              </button>
            </form>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">{children}</main>
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
        <h1 className="text-xl font-semibold text-ink">{title}</h1>
        {description && <p className="mt-1 text-sm text-ink-2">{description}</p>}
      </div>
      {actions}
    </div>
  );
}
