"use client";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useRef, useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell";
import { Button, Card, Notice, Pagination, Skeleton, StatTile } from "@/components/ui";
import { ApiError, send, uploadCapture } from "@/lib/api";
import { attackName, formatCount, formatTime, timeAgo } from "@/lib/format";
import type { Capture, CaptureStatus, Page } from "@/lib/types";
import { hasRole, useMe } from "@/lib/user";

const LIMIT = 20;
const MAX_MB = 100;

const STATUS: Record<CaptureStatus, { label: string; dot: string }> = {
  queued: { label: "Queued", dot: "bg-[var(--status-neutral)]" },
  analyzing: { label: "Analyzing", dot: "bg-warning animate-pulse" },
  done: { label: "Done", dot: "bg-good" },
  failed: { label: "Failed", dot: "bg-critical" },
};

function formatSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

function CaptureStatusBadge({ status }: { status: CaptureStatus }) {
  const { label, dot } = STATUS[status];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-ink/5 px-2 py-0.5 text-xs font-medium text-ink">
      <span aria-hidden className={`size-2 rounded-full ${dot}`} />
      {label}
    </span>
  );
}

function Upload({ onUploaded }: { onUploaded: (capture: Capture) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [raiseAlerts, setRaiseAlerts] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!file) return;
    if (file.size > MAX_MB * 1024 * 1024) {
      setError(`The file is ${formatSize(file.size)}; captures are limited to ${MAX_MB} MB.`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const capture = await uploadCapture<Capture>(file, raiseAlerts);
      setFile(null);
      if (input.current) input.current.value = "";
      onUploaded(capture);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Analyze a capture"
      description={
        <>
          In Wireshark: File › Save As, format pcapng or pcap. Up to {MAX_MB} MB. The file is
          replayed through the same engine as live traffic.
        </>
      }
    >
      <form onSubmit={submit} className="flex flex-wrap items-center gap-3">
        <input
          ref={input}
          type="file"
          accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
          aria-label="Capture file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="max-w-full text-sm text-ink-2 file:mr-3 file:rounded-sm file:border file:border-line-strong file:bg-sunken file:px-3 file:py-1.5 file:font-mono file:text-xs file:uppercase file:tracking-wider file:text-ink"
        />
        <label className="inline-flex items-center gap-2 text-sm text-ink-2">
          <input
            type="checkbox"
            checked={raiseAlerts}
            onChange={(e) => setRaiseAlerts(e.target.checked)}
            className="accent-[var(--accent)]"
          />
          Raise alerts for attacks found
        </label>
        <Button type="submit" variant="primary" disabled={!file || busy}>
          {busy ? "Uploading…" : "Upload and analyze"}
        </Button>
      </form>
      {error && (
        <div className="mt-3">
          <Notice tone="error">{error}</Notice>
        </div>
      )}
    </Card>
  );
}

function Ranked({ title, rows }: { title: string; rows: { name: string; count: number }[] }) {
  return (
    <div>
      <p className="label-caps mb-2 text-muted">{title}</p>
      {rows.length ? (
        <ul className="space-y-1 text-sm">
          {rows.map((row) => (
            <li key={row.name} className="flex justify-between gap-3">
              <span className="truncate font-mono text-ink">{row.name}</span>
              <span className="tabular text-ink-2">{formatCount(row.count)}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted">None</p>
      )}
    </div>
  );
}

function Report({ capture, canDelete, onDeleted }: { capture: Capture; canDelete: boolean; onDeleted: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const report = capture.report;

  async function remove() {
    if (!window.confirm(`Delete ${capture.filename}? Its alerts stay, but lose their packet evidence.`)) return;
    setBusy(true);
    setError(null);
    try {
      await send("DELETE", `captures/${capture.id}`);
      onDeleted();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Delete failed");
      setBusy(false);
    }
  }

  return (
    <Card
      title={capture.filename}
      description={`${capture.file_format} · ${formatSize(capture.size_bytes)} · uploaded ${formatTime(capture.created_at)} · SHA-256 ${capture.sha256.slice(0, 16)}…`}
      actions={
        canDelete && capture.status !== "analyzing" ? (
          <Button variant="danger" disabled={busy} onClick={remove}>
            Delete
          </Button>
        ) : undefined
      }
    >
      {error && (
        <div className="mb-3">
          <Notice tone="error">{error}</Notice>
        </div>
      )}
      {capture.status === "failed" ? (
        <Notice tone="error">{capture.error ?? "Analysis failed"}</Notice>
      ) : !report ? (
        <Notice>
          {capture.status === "queued" ? "Waiting for the capture worker…" : "Analyzing the capture…"}{" "}
          This page updates on its own.
        </Notice>
      ) : (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-4">
            <StatTile label="Packets" value={formatCount(report.packets)} detail={formatDuration(report.duration_s) + " of traffic"} />
            <StatTile label="Flows" value={formatCount(report.flows)} detail="Classified by the model" />
            <StatTile
              label="Attack detections"
              value={formatCount(report.attacks)}
              accent={report.attacks ? "var(--status-critical)" : "var(--status-good)"}
              detail={report.attacks ? "Flows and rule hits" : "Nothing suspicious found"}
            />
            <StatTile label="Highest risk" value={report.max_risk} detail="0–100" />
          </div>
          <div className="grid gap-5 sm:grid-cols-3">
            <Ranked
              title="Attack types"
              rows={Object.entries(report.attack_types).map(([label, count]) => ({ name: attackName(label), count }))}
            />
            <Ranked title="Top attack sources" rows={report.top_sources.map((s) => ({ name: s.ip, count: s.detections }))} />
            <Ranked title="Top targets" rows={report.top_targets.map((t) => ({ name: t.target, count: t.detections }))} />
          </div>
          <p className="text-xs text-muted">
            Traffic from {formatTime(report.first_packet_at)} to {formatTime(report.last_packet_at)} (capture time),
            analyzed in {report.analysis_s} s with {report.model_version}.{" "}
            {capture.raise_alerts ? (
              report.attacks ? (
                <>
                  Its alerts are in <Link href="/alerts" className="text-accent hover:underline">Alerts</Link>, timed as
                  if the capture ended at upload, and carry the packets for Wireshark.
                </>
              ) : null
            ) : (
              "Uploaded without raising alerts."
            )}
          </p>
        </div>
      )}
    </Card>
  );
}

export function CapturesView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const { data: me } = useMe();
  const [offset, setOffset] = useState(0);
  const selected = Number(params.get("id")) || null;

  const busy = (page?: Page<Capture>) => !!page?.items.some((c) => c.status === "queued" || c.status === "analyzing");
  const { data, error, mutate } = useSWR<Page<Capture>>(`captures?limit=${LIMIT}&offset=${offset}`, {
    refreshInterval: (page) => (busy(page) ? 2_000 : 30_000),
  });
  const current = useSWR<Capture>(selected ? `captures/${selected}` : null, {
    refreshInterval: (c) => (c && (c.status === "queued" || c.status === "analyzing") ? 2_000 : 0),
  });

  const select = (id: number | null) => router.replace(id ? `${pathname}?id=${id}` : pathname, { scroll: false });

  return (
    <>
      <PageHeader
        title="Captures"
        description="Packet captures from Wireshark or tcpdump, analyzed offline by the detection engine."
      />
      <div className="space-y-4">
        {hasRole(me, "analyst") && (
          <Upload
            onUploaded={(capture) => {
              setOffset(0);
              mutate();
              select(capture.id);
            }}
          />
        )}
        {selected && current.data && (
          <Report
            capture={current.data}
            canDelete={hasRole(me, "admin")}
            onDeleted={() => {
              select(null);
              mutate();
            }}
          />
        )}
        {selected && current.error && <Notice tone="error">{current.error.message}</Notice>}
        <Card title="Uploaded captures">
          {error ? (
            <Notice tone="error">{error.message}</Notice>
          ) : !data ? (
            <Skeleton className="h-40" />
          ) : data.items.length ? (
            <>
              <div className="-mx-4 overflow-x-auto sm:mx-0">
                <table className="w-full min-w-[720px] text-left text-sm">
                  <thead className="text-xs text-muted">
                    <tr className="border-b border-line">
                      <th className="px-4 py-2 font-medium sm:pl-0">File</th>
                      <th className="px-2 py-2 font-medium">Status</th>
                      <th className="px-2 py-2 text-right font-medium">Size</th>
                      <th className="px-2 py-2 text-right font-medium">Packets</th>
                      <th className="px-2 py-2 text-right font-medium">Attacks</th>
                      <th className="px-4 py-2 font-medium sm:pr-0">Uploaded</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((capture) => (
                      <tr
                        key={capture.id}
                        aria-selected={capture.id === selected}
                        className={`border-b border-line last:border-0 ${capture.id === selected ? "bg-accent/5" : ""}`}
                      >
                        <td className="px-4 py-2 sm:pl-0">
                          <button
                            type="button"
                            onClick={() => select(capture.id)}
                            className="text-left font-medium text-ink hover:text-accent-strong"
                          >
                            {capture.filename}
                          </button>
                        </td>
                        <td className="px-2 py-2">
                          <CaptureStatusBadge status={capture.status} />
                        </td>
                        <td className="tabular px-2 py-2 text-right text-ink-2">{formatSize(capture.size_bytes)}</td>
                        <td className="tabular px-2 py-2 text-right text-ink-2">
                          {capture.report ? formatCount(capture.report.packets) : "–"}
                        </td>
                        <td className="tabular px-2 py-2 text-right text-ink">
                          {capture.report ? formatCount(capture.report.attacks) : "–"}
                        </td>
                        <td className="tabular whitespace-nowrap px-4 py-2 text-ink-2 sm:pr-0">
                          {timeAgo(capture.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
            </>
          ) : (
            <p className="py-6 text-sm text-ink-2">
              No captures yet. Save a capture in Wireshark and upload it above to see what ArgusAI finds in it.
            </p>
          )}
        </Card>
      </div>
    </>
  );
}
