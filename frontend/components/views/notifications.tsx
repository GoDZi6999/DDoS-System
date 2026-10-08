"use client";
import Link from "next/link";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell";
import { Button, Card, Field, Notice, Pagination, Skeleton, inputBase, inputClass } from "@/components/ui";
import { send } from "@/lib/api";
import { formatTime, timeAgo } from "@/lib/format";
import { hasRole, useMe } from "@/lib/user";
import type { Channel, ChannelKind, Delivery, DeliveryStatus, Page, Severity } from "@/lib/types";

const KINDS: { value: ChannelKind; label: string }[] = [
  { value: "email", label: "Email" },
  { value: "slack", label: "Slack" },
  { value: "webhook", label: "Webhook" },
];
const SEVERITIES: Severity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const sevLabel = (s: Severity) => s.charAt(0) + s.slice(1).toLowerCase();

const STATUS: Record<DeliveryStatus, { label: string; dot: string }> = {
  pending: { label: "Pending", dot: "bg-[var(--status-neutral)]" },
  sent: { label: "Sent", dot: "bg-good" },
  failed: { label: "Failed", dot: "bg-critical" },
  suppressed: { label: "Suppressed", dot: "bg-warning" },
};

function DeliveryBadge({ status }: { status: DeliveryStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-ink">
      <span aria-hidden className={`size-2 rounded-full ${STATUS[status].dot}`} />
      {STATUS[status].label}
    </span>
  );
}

function target(channel: Channel): string {
  if (channel.kind === "email") return (channel.config.recipients ?? []).join(", ");
  if (channel.kind === "slack") return channel.config.webhook_url ?? "";
  return `${channel.config.url ?? ""}${channel.config.secret_set ? " · signed" : " · unsigned"}`;
}

export function NotificationsView() {
  const { data: me } = useMe();
  const isAdmin = hasRole(me, "admin");
  const channels = useSWR<Channel[]>(isAdmin ? "notifications/channels" : null, {
    refreshInterval: 15_000,
  });
  if (me && !isAdmin) return <Notice>Notification settings are available to administrators.</Notice>;

  return (
    <>
      <PageHeader
        title="Notifications"
        description="Alerts are sent to each enabled channel once per severity band, so a flood does not flood your inbox. Messages are advisory; ArgusAI does not block traffic."
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Channels">
          {channels.error ? (
            <Notice tone="error">{channels.error.message}</Notice>
          ) : !channels.data ? (
            <Skeleton className="h-40" />
          ) : channels.data.length ? (
            <ul className="divide-y divide-line">
              {channels.data.map((channel) => (
                <ChannelRow key={channel.id} channel={channel} onChange={() => channels.mutate()} />
              ))}
            </ul>
          ) : (
            <p className="py-6 text-center text-sm text-muted">
              No channels yet. Add one to receive alerts by email, Slack or webhook.
            </p>
          )}
        </Card>
        <CreateChannel onCreated={() => channels.mutate()} />
      </div>
      <DeliveryLog />
    </>
  );
}

function ChannelRow({ channel, onChange }: { channel: Channel; onChange: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const patch = async (body: object) => {
    setError(null);
    try {
      await send("PATCH", `notifications/channels/${channel.id}`, body);
      onChange();
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Update failed.");
      return false;
    }
  };
  return (
    <li className="py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className={`font-medium ${channel.enabled ? "text-ink" : "text-muted line-through"}`}>
            {channel.name}{" "}
            <span className="rounded bg-accent/5 px-1.5 py-0.5 text-xs font-normal text-ink-2">
              {KINDS.find((k) => k.value === channel.kind)?.label}
            </span>
          </p>
          <p className="mt-0.5 break-all text-xs text-muted">{target(channel)}</p>
          <p className="mt-1 text-xs text-ink-2">
            {channel.last_delivery_status && channel.last_delivery_at ? (
              <>
                Last delivery <DeliveryBadge status={channel.last_delivery_status} />{" "}
                {timeAgo(channel.last_delivery_at)}
              </>
            ) : (
              "No deliveries yet"
            )}
            {" · "}max {channel.max_per_hour}/hour
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label={`Minimum severity for ${channel.name}`}
            value={channel.min_severity}
            onChange={(e) => patch({ min_severity: e.target.value })}
            className={`${inputBase} w-auto py-1`}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {sevLabel(s)} and above
              </option>
            ))}
          </select>
          <Button
            className="py-1"
            disabled={!channel.enabled}
            onClick={async () => {
              setError(null);
              try {
                await send("POST", `notifications/channels/${channel.id}/test`);
                setInfo("Test queued; its result appears in the delivery log.");
              } catch (e) {
                setError(e instanceof Error ? e.message : "Could not queue a test.");
              }
            }}
          >
            Send test
          </Button>
          <Button className="py-1" onClick={() => setEditing(!editing)}>
            {editing ? "Close" : "Edit"}
          </Button>
          <Button
            className="py-1"
            variant={channel.enabled ? "danger" : "secondary"}
            onClick={() => patch({ enabled: !channel.enabled })}
          >
            {channel.enabled ? "Disable" : "Enable"}
          </Button>
        </div>
      </div>
      {editing && (
        <EditTarget
          channel={channel}
          onSave={async (body) => {
            if (await patch(body)) setEditing(false);
          }}
        />
      )}
      {info && <p className="mt-2 text-xs text-ink-2" role="status">{info}</p>}
      {error && <div className="mt-2"><Notice tone="error">{error}</Notice></div>}
    </li>
  );
}

/** Target fields for one kind; secrets are write-only (blank keeps the stored value). */
function TargetFields({
  kind,
  values,
  setValues,
  editing = false,
}: {
  kind: ChannelKind;
  values: Record<string, string>;
  setValues: (v: Record<string, string>) => void;
  editing?: boolean;
}) {
  const set = (key: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setValues({ ...values, [key]: e.target.value });
  if (kind === "email") {
    return (
      <Field label="Recipients" hint="Comma-separated addresses, up to 20">
        <input required value={values.recipients ?? ""} onChange={set("recipients")} className={inputClass} placeholder="soc@example.com" />
      </Field>
    );
  }
  if (kind === "slack") {
    return (
      <Field label="Slack webhook URL" hint={editing ? "Enter the full URL again to change it" : "https://hooks.slack.com/services/…"}>
        <input required type="url" autoComplete="off" value={values.webhook_url ?? ""} onChange={set("webhook_url")} className={inputClass} />
      </Field>
    );
  }
  return (
    <>
      <Field label="Webhook URL" hint="Public https address; receives a JSON POST per notification">
        <input required type="url" autoComplete="off" value={values.url ?? ""} onChange={set("url")} className={inputClass} />
      </Field>
      <Field
        label="Signing secret (optional)"
        hint={editing ? "Leave blank to keep the current secret" : "16+ characters; adds an X-Sentinel-Signature HMAC header"}
      >
        <input type="password" autoComplete="new-password" minLength={16} maxLength={256} value={values.secret ?? ""} onChange={set("secret")} className={inputClass} />
      </Field>
    </>
  );
}

function toConfig(kind: ChannelKind, values: Record<string, string>, editing: boolean) {
  if (kind === "email") {
    return { recipients: (values.recipients ?? "").split(/[,\s]+/).filter(Boolean) };
  }
  if (kind === "slack") return { webhook_url: values.webhook_url };
  const config: Record<string, string | null> = { url: values.url };
  if (values.secret) config.secret = values.secret;
  else if (!editing) config.secret = null;
  return config;
}

function EditTarget({ channel, onSave }: { channel: Channel; onSave: (body: object) => void }) {
  const [values, setValues] = useState<Record<string, string>>(
    channel.kind === "email" ? { recipients: (channel.config.recipients ?? []).join(", ") } : {},
  );
  const [max, setMax] = useState(String(channel.max_per_hour));
  return (
    <form
      className="mt-3 space-y-3 rounded-sm bg-sunken border border-line p-3"
      onSubmit={(e) => {
        e.preventDefault();
        onSave({ config: toConfig(channel.kind, values, true), max_per_hour: Number(max) });
      }}
    >
      <TargetFields kind={channel.kind} values={values} setValues={setValues} editing />
      <Field label="Maximum per hour">
        <input type="number" min={1} max={1000} required value={max} onChange={(e) => setMax(e.target.value)} className={`${inputBase} w-32`} />
      </Field>
      <Button type="submit" variant="primary">Save</Button>
    </form>
  );
}

function CreateChannel({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<ChannelKind>("email");
  const [severity, setSeverity] = useState<Severity>("HIGH");
  const [values, setValues] = useState<Record<string, string>>({});
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Card title="Add channel">
      <form
        className="space-y-3"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setMessage(null);
          try {
            await send("POST", "notifications/channels", {
              name,
              kind,
              min_severity: severity,
              config: toConfig(kind, values, false),
            });
            setName("");
            setValues({});
            setMessage({ tone: "info", text: `Added ${name}. Send a test to check it.` });
            onCreated();
          } catch (err) {
            setMessage({ tone: "error", text: err instanceof Error ? err.message : "Could not add the channel." });
          } finally {
            setBusy(false);
          }
        }}
      >
        <Field label="Name">
          <input required maxLength={64} value={name} onChange={(e) => setName(e.target.value)} className={inputClass} placeholder="SOC on-call" />
        </Field>
        <Field label="Type">
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as ChannelKind);
              setValues({});
            }}
            className={inputClass}
          >
            {KINDS.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </select>
        </Field>
        <TargetFields kind={kind} values={values} setValues={setValues} />
        <Field label="Send alerts of">
          <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={inputClass}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {sevLabel(s)} severity and above
              </option>
            ))}
          </select>
        </Field>
        {message && <Notice tone={message.tone}>{message.text}</Notice>}
        <Button type="submit" variant="primary" disabled={busy}>Add channel</Button>
      </form>
    </Card>
  );
}

const LIMIT = 25;

function DeliveryLog() {
  const [status, setStatus] = useState<DeliveryStatus | "">("");
  const [offset, setOffset] = useState(0);
  const query = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
  if (status) query.set("status", status);
  const { data, error } = useSWR<Page<Delivery>>(`notifications/deliveries?${query}`, {
    refreshInterval: 5000,
    keepPreviousData: true,
  });
  return (
    <Card
      title="Delivery log"
      description="Every notification attempt: failures are retried with backoff (5 attempts) unless the target refuses permanently."
      className="mt-4"
      actions={
        <select
          aria-label="Delivery status"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value as DeliveryStatus | "");
            setOffset(0);
          }}
          className={`${inputBase} w-auto py-1`}
        >
          <option value="">All statuses</option>
          {(Object.keys(STATUS) as DeliveryStatus[]).map((s) => (
            <option key={s} value={s}>
              {STATUS[s].label}
            </option>
          ))}
        </select>
      }
    >
      {error ? (
        <Notice tone="error">{error.message}</Notice>
      ) : !data ? (
        <Skeleton className="h-40" />
      ) : data.items.length ? (
        <>
          <div className="-mx-4 overflow-x-auto sm:mx-0">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="label-caps text-muted">
                <tr className="border-b border-line">
                  <th className="px-4 py-2 font-medium sm:pl-0">Queued</th>
                  <th className="px-2 py-2 font-medium">Channel</th>
                  <th className="px-2 py-2 font-medium">Message</th>
                  <th className="px-2 py-2 font-medium">Status</th>
                  <th className="px-4 py-2 font-medium sm:pr-0">Detail</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((d) => (
                  <tr key={d.id} className="border-b border-line align-top last:border-0">
                    <td className="tabular whitespace-nowrap px-4 py-2 text-ink-2 sm:pl-0">{formatTime(d.created_at)}</td>
                    <td className="px-2 py-2 text-ink">{d.channel.name}</td>
                    <td className="px-2 py-2 text-ink">
                      {d.alert_id ? (
                        <Link href={`/alerts/${d.alert_id}`} className="hover:underline">{d.title}</Link>
                      ) : (
                        d.title
                      )}
                    </td>
                    <td className="whitespace-nowrap px-2 py-2">
                      <DeliveryBadge status={d.status} />
                      <span className="tabular block text-xs text-muted">
                        {d.attempts} attempt{d.attempts === 1 ? "" : "s"}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs text-ink-2 sm:pr-0">
                      {d.status === "sent" && d.sent_at
                        ? `Sent ${formatTime(d.sent_at)}`
                        : d.status === "pending" && d.attempts > 0
                          ? `Retry at ${formatTime(d.next_attempt_at)}: ${d.last_error ?? ""}`
                          : (d.last_error ?? "–")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
        </>
      ) : (
        <p className="py-6 text-center text-sm text-muted">No deliveries.</p>
      )}
    </Card>
  );
}
