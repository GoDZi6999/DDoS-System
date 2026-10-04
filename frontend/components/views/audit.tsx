"use client";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell";
import { Button, Card, Notice, Pagination, Skeleton, inputBase } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { hasRole, useMe } from "@/lib/user";
import type { AuditEntry, Page } from "@/lib/types";

const LIMIT = 50;
const ACTIONS = [
  "auth.login",
  "auth.login_failed",
  "auth.locked",
  "auth.logout",
  "auth.password_changed",
  "auth.refresh_reuse_detected",
  "user.created",
  "user.updated",
  "alert.created",
  "alert.escalated",
  "alert.acknowledged",
  "alert.status_changed",
  "alert.note_added",
  "alert.assigned",
  "config.updated",
];
const SECURITY = new Set(["auth.login_failed", "auth.locked", "auth.refresh_reuse_detected"]);

function Change({ before, after }: Pick<AuditEntry, "before" | "after">) {
  if (!before && !after) return <span className="text-muted">–</span>;
  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-ink-2 hover:text-ink">Show change</summary>
      <div className="mt-2 grid gap-2 sm:grid-cols-2">
        {before && (
          <pre className="overflow-x-auto rounded bg-ink/5 p-2 text-ink-2">
            <span className="text-muted">before </span>
            {JSON.stringify(before, null, 2)}
          </pre>
        )}
        {after && (
          <pre className="overflow-x-auto rounded bg-ink/5 p-2 text-ink">
            <span className="text-muted">after </span>
            {JSON.stringify(after, null, 2)}
          </pre>
        )}
      </div>
    </details>
  );
}

export function AuditView() {
  const { data: me } = useMe();
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [actorDraft, setActorDraft] = useState("");
  const [offset, setOffset] = useState(0);

  const query = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
  if (action) query.set("action", action);
  if (actor) query.set("actor", actor);
  const isAdmin = hasRole(me, "admin");
  const { data, error } = useSWR<Page<AuditEntry>>(isAdmin ? `audit?${query}` : null, {
    keepPreviousData: true,
  });

  if (me && !isAdmin) return <Notice>The audit log is available to administrators.</Notice>;

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every security-relevant action. Entries are append-only: the database rejects edits and deletions."
      />
      <Card>
        <div className="mb-3 flex flex-wrap gap-2">
          <select
            aria-label="Action"
            value={action}
            onChange={(e) => {
              setAction(e.target.value);
              setOffset(0);
            }}
            className={`${inputBase} w-auto`}
          >
            <option value="">All actions</option>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setActor(actorDraft.trim());
              setOffset(0);
            }}
          >
            <input
              aria-label="Actor"
              placeholder="Actor (username)"
              value={actorDraft}
              onChange={(e) => setActorDraft(e.target.value)}
              className={`${inputBase} w-48`}
            />
            <Button type="submit">Filter</Button>
          </form>
        </div>
        {error ? (
          <Notice tone="error">{error.message}</Notice>
        ) : !data ? (
          <Skeleton className="h-64" />
        ) : data.items.length ? (
          <>
            <div className="-mx-4 overflow-x-auto sm:mx-0">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="text-xs text-muted">
                  <tr className="border-b border-line">
                    <th className="px-4 py-2 font-medium sm:pl-0">Time</th>
                    <th className="px-2 py-2 font-medium">Actor</th>
                    <th className="px-2 py-2 font-medium">Action</th>
                    <th className="px-2 py-2 font-medium">Entity</th>
                    <th className="px-2 py-2 font-medium">IP</th>
                    <th className="px-4 py-2 font-medium sm:pr-0">Change</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((entry) => (
                    <tr key={entry.id} className="border-b border-line align-top last:border-0">
                      <td className="tabular whitespace-nowrap px-4 py-2 text-ink-2 sm:pl-0">
                        {formatTime(entry.ts)}
                      </td>
                      <td className="px-2 py-2 text-ink">{entry.actor}</td>
                      <td className="px-2 py-2">
                        <code className="text-xs text-ink">{entry.action}</code>
                        {SECURITY.has(entry.action) && (
                          <span className="ml-2 rounded bg-warning/20 px-1.5 py-0.5 text-[11px] text-ink">
                            security
                          </span>
                        )}
                      </td>
                      <td className="px-2 py-2 text-ink-2">
                        {entry.entity_type ? `${entry.entity_type} ${entry.entity_id ?? ""}` : "–"}
                      </td>
                      <td className="tabular px-2 py-2 text-ink-2">{entry.ip ?? "–"}</td>
                      <td className="px-4 py-2 sm:pr-0">
                        <Change before={entry.before} after={entry.after} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
          </>
        ) : (
          <p className="py-10 text-center text-sm text-muted">No entries match.</p>
        )}
      </Card>
    </>
  );
}
