import type { AlertStatus, Severity } from "@/lib/types";

// Status colours always come with a text label and a glyph, never alone.
const SEVERITY: Record<Severity, { label: string; glyph: string; color: string }> = {
  LOW: { label: "Low", glyph: "▽", color: "var(--status-neutral)" },
  MEDIUM: { label: "Medium", glyph: "◇", color: "var(--status-warning)" },
  HIGH: { label: "High", glyph: "◆", color: "var(--status-serious)" },
  CRITICAL: { label: "Critical", glyph: "▲", color: "var(--status-critical)" },
};

export function severityColor(severity: Severity): string {
  return SEVERITY[severity].color;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { label, glyph, color } = SEVERITY[severity];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-ink"
      style={{
        borderColor: `color-mix(in oklab, ${color} 60%, transparent)`,
        background: `color-mix(in oklab, ${color} 14%, transparent)`,
      }}
    >
      <span aria-hidden style={{ color }}>
        {glyph}
      </span>
      {label}
    </span>
  );
}

export const STATUS_LABEL: Record<AlertStatus, string> = {
  NEW: "New",
  INVESTIGATING: "Investigating",
  CONTAINED: "Contained",
  RESOLVED: "Resolved",
  FALSE_POSITIVE: "False positive",
};

export function StatusBadge({ status }: { status: AlertStatus }) {
  const open = status === "NEW" || status === "INVESTIGATING" || status === "CONTAINED";
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider ${
        status === "NEW" ? "text-accent" : open ? "text-ink" : "text-muted"
      }`}
    >
      <span
        aria-hidden
        className={`size-1.5 rounded-full ${open ? "bg-current" : "border border-current"} ${
          status === "NEW" ? "pulse" : ""
        }`}
      />
      {STATUS_LABEL[status]}
    </span>
  );
}

export function Card({
  title,
  description,
  actions,
  children,
  className = "",
  tone,
}: {
  title?: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  tone?: "critical";
}) {
  return (
    <section className={`hud p-4 sm:p-5 ${tone === "critical" ? "hud-critical" : ""} ${className}`}>
      {(title || actions) && (
        <header className="mb-4 flex flex-wrap items-start justify-between gap-2">
          <div>
            {title && (
              <h2 className="font-display text-sm font-semibold uppercase tracking-[0.12em] text-ink">
                <span aria-hidden className="mr-2 text-accent">
                  ▍
                </span>
                {title}
              </h2>
            )}
            {description && <p className="mt-1 text-xs text-muted">{description}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function StatTile({
  label,
  value,
  detail,
  accent = "var(--accent)",
}: {
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="hud overflow-hidden p-4">
      <span
        aria-hidden
        className="absolute inset-y-0 left-0 w-[3px]"
        style={{ background: accent, boxShadow: `0 0 14px ${accent}` }}
      />
      <p className="label-caps text-muted">{label}</p>
      <p className="tabular mt-2 font-mono text-3xl font-semibold text-ink">{value}</p>
      {detail && <div className="mt-1.5 text-xs text-ink-2">{detail}</div>}
    </div>
  );
}

export function Notice({
  tone = "info",
  children,
}: {
  tone?: "info" | "error";
  children: React.ReactNode;
}) {
  return (
    <p
      role={tone === "error" ? "alert" : "status"}
      className={`rounded-sm border px-3 py-2 font-mono text-xs ${
        tone === "error"
          ? "border-critical/50 bg-critical/10 text-ink"
          : "border-line bg-sunken text-ink-2"
      }`}
    >
      <span aria-hidden className={tone === "error" ? "text-critical" : "text-accent"}>
        {tone === "error" ? "✕ " : "› "}
      </span>
      {children}
    </p>
  );
}

export function Skeleton({ className = "h-24" }: { className?: string }) {
  return <div aria-hidden className={`animate-pulse rounded-sm bg-accent/5 ${className}`} />;
}

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger";
};

export function Button({ variant = "secondary", className = "", ...props }: ButtonProps) {
  const styles = {
    primary:
      "border-accent/70 bg-accent/15 text-accent-strong hover:bg-accent/25 hover:shadow-[0_0_18px_-4px_var(--accent)]",
    secondary: "border-line-strong bg-sunken text-ink hover:border-accent/60 hover:text-accent-strong",
    danger: "border-critical/60 bg-critical/10 text-ink hover:bg-critical/20",
  }[variant];
  return (
    <button
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 rounded-sm border px-3 py-1.5 font-mono text-xs font-medium uppercase tracking-wider transition disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${styles} ${className}`}
    />
  );
}

/** Input styling without a width, for controls that size themselves. */
export const inputBase =
  "rounded-sm border border-line-strong bg-sunken px-3 py-1.5 font-mono text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none focus:shadow-[0_0_0_1px_var(--accent),0_0_16px_-6px_var(--accent)]";
export const inputClass = `${inputBase} w-full`;

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="label-caps text-ink-2">{label}</span>
      <div className="mt-1.5">{children}</div>
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export function Pagination({
  offset,
  limit,
  total,
  onChange,
}: {
  offset: number;
  limit: number;
  total: number;
  onChange: (offset: number) => void;
}) {
  if (total <= limit) return null;
  return (
    <nav aria-label="Pagination" className="mt-4 flex items-center justify-between text-sm">
      <span className="tabular font-mono text-xs text-muted">
        {offset + 1}–{Math.min(offset + limit, total)} / {total}
      </span>
      <div className="flex gap-2">
        <Button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
          Previous
        </Button>
        <Button disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>
          Next
        </Button>
      </div>
    </nav>
  );
}
