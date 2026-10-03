import type { AlertStatus, Severity } from "@/lib/types";

// Status colours always come with a text label (and a shape), never alone.
const SEVERITY: Record<Severity, { dot: string; label: string }> = {
  LOW: { dot: "bg-[var(--status-neutral)]", label: "Low" },
  MEDIUM: { dot: "bg-warning", label: "Medium" },
  HIGH: { dot: "bg-serious", label: "High" },
  CRITICAL: { dot: "bg-critical", label: "Critical" },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { dot, label } = SEVERITY[severity];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-line bg-raised px-2 py-0.5 text-xs font-medium text-ink">
      <span aria-hidden className={`size-2 rotate-45 rounded-[2px] ${dot}`} />
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
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${
        status === "NEW" ? "bg-accent/15 text-ink" : "bg-ink/5 text-ink-2"
      }`}
    >
      <span
        aria-hidden
        className={`size-1.5 rounded-full ${open ? "bg-accent" : "border border-current"}`}
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
}: {
  title?: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl border border-line bg-surface p-4 sm:p-5 ${className}`}>
      {(title || actions) && (
        <header className="mb-4 flex flex-wrap items-start justify-between gap-2">
          <div>
            {title && <h2 className="text-sm font-semibold text-ink">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-muted">{description}</p>}
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
}: {
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-line bg-surface p-4">
      <p className="text-xs font-medium text-ink-2">{label}</p>
      <p className="tabular mt-1 text-2xl font-semibold text-ink">{value}</p>
      {detail && <div className="mt-1 text-xs text-muted">{detail}</div>}
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
      className={`rounded-lg border px-3 py-2 text-sm ${
        tone === "error"
          ? "border-critical/40 bg-critical/10 text-ink"
          : "border-line bg-raised text-ink-2"
      }`}
    >
      {children}
    </p>
  );
}

export function Skeleton({ className = "h-24" }: { className?: string }) {
  return <div aria-hidden className={`animate-pulse rounded-lg bg-ink/5 ${className}`} />;
}

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger";
};

export function Button({ variant = "secondary", className = "", ...props }: ButtonProps) {
  const styles = {
    primary: "bg-accent text-white hover:brightness-110 border-transparent",
    secondary: "bg-raised text-ink border-line hover:bg-ink/5",
    danger: "bg-raised text-critical border-critical/40 hover:bg-critical/10",
  }[variant];
  return (
    <button
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${styles} ${className}`}
    />
  );
}

export const inputClass =
  "w-full rounded-lg border border-line bg-raised px-3 py-1.5 text-sm text-ink placeholder:text-muted focus:outline-2 focus:outline-accent";

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
      <span className="text-xs font-medium text-ink-2">{label}</span>
      <div className="mt-1">{children}</div>
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
      <span className="tabular text-muted">
        {offset + 1}–{Math.min(offset + limit, total)} of {total}
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
