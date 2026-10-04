"use client";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell";
import { Button, Card, Field, Notice, Skeleton, inputBase, inputClass } from "@/components/ui";
import { send } from "@/lib/api";
import { formatTime } from "@/lib/format";
import { hasRole, useMe } from "@/lib/user";
import type { Page, Role, User } from "@/lib/types";

const ROLES: { value: Role; label: string; hint: string }[] = [
  { value: "viewer", label: "Viewer", hint: "Reads dashboards and alerts" },
  { value: "analyst", label: "Analyst", hint: "Also works alerts and reads settings" },
  { value: "admin", label: "Admin", hint: "Also manages users, settings and the audit log" },
];

export function UsersView() {
  const { data: me } = useMe();
  const isAdmin = hasRole(me, "admin");
  const { data, error, mutate } = useSWR<Page<User>>(isAdmin ? "users?limit=200" : null);
  const [rowError, setRowError] = useState<string | null>(null);

  if (me && !isAdmin) return <Notice>User management is available to administrators.</Notice>;

  const update = async (user: User, change: Partial<Pick<User, "role" | "is_active">>) => {
    setRowError(null);
    try {
      await send("PATCH", `users/${user.id}`, change);
    } catch (err) {
      setRowError(err instanceof Error ? `${user.username}: ${err.message}` : "Update failed.");
    }
    await mutate();
  };

  return (
    <>
      <PageHeader
        title="Users"
        description="Accounts are deactivated rather than deleted, so the audit trail keeps its references."
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Accounts">
          {rowError && <div className="mb-3"><Notice tone="error">{rowError}</Notice></div>}
          {error ? (
            <Notice tone="error">{error.message}</Notice>
          ) : !data ? (
            <Skeleton className="h-48" />
          ) : (
            <div className="-mx-4 overflow-x-auto sm:mx-0">
              <table className="w-full min-w-[560px] text-left text-sm">
                <thead className="text-xs text-muted">
                  <tr className="border-b border-line">
                    <th className="px-4 py-2 font-medium sm:pl-0">User</th>
                    <th className="px-2 py-2 font-medium">Role</th>
                    <th className="px-2 py-2 font-medium">Last login</th>
                    <th className="px-4 py-2 text-right font-medium sm:pr-0">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((user) => (
                    <tr key={user.id} className="border-b border-line last:border-0">
                      <td className="px-4 py-2 sm:pl-0">
                        <span className={`font-medium ${user.is_active ? "text-ink" : "text-muted line-through"}`}>
                          {user.username}
                        </span>
                        {user.id === me?.id && <span className="ml-1.5 text-xs text-muted">(you)</span>}
                        {user.email && <span className="block text-xs text-muted">{user.email}</span>}
                      </td>
                      <td className="px-2 py-2">
                        <select
                          aria-label={`Role of ${user.username}`}
                          value={user.role}
                          onChange={(e) => update(user, { role: e.target.value as Role })}
                          className={`${inputBase} w-auto py-1`}
                        >
                          {ROLES.map((r) => (
                            <option key={r.value} value={r.value}>
                              {r.label}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="tabular px-2 py-2 text-ink-2">
                        {user.last_login_at ? formatTime(user.last_login_at) : "Never"}
                      </td>
                      <td className="px-4 py-2 text-right sm:pr-0">
                        <Button
                          variant={user.is_active ? "danger" : "secondary"}
                          onClick={() => update(user, { is_active: !user.is_active })}
                          className="py-1"
                        >
                          {user.is_active ? "Deactivate" : "Reactivate"}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <CreateUser onCreated={() => mutate()} />
      </div>
    </>
  );
}

function CreateUser({ onCreated }: { onCreated: () => void }) {
  const empty = { username: "", email: "", password: "", role: "viewer" as Role };
  const [form, setForm] = useState(empty);
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Card title="Add user" description="Share the initial password securely; the user can change it in Settings.">
      <form
        className="space-y-3"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setMessage(null);
          try {
            const user = await send<User>("POST", "users", {
              username: form.username,
              password: form.password,
              role: form.role,
              ...(form.email.trim() ? { email: form.email.trim() } : {}),
            });
            setForm(empty);
            setMessage({ tone: "info", text: `Created ${user.username}.` });
            onCreated();
          } catch (err) {
            setMessage({ tone: "error", text: err instanceof Error ? err.message : "Could not create the user." });
          } finally {
            setBusy(false);
          }
        }}
      >
        <Field label="Username" hint="3–64 characters: letters, digits, . _ -">
          <input required pattern="[A-Za-z0-9_.\-]{3,64}" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} className={inputClass} />
        </Field>
        <Field label="Email (optional)">
          <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className={inputClass} />
        </Field>
        <Field label="Initial password" hint="12–128 characters">
          <input type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} className={inputClass} />
        </Field>
        <Field label="Role" hint={ROLES.find((r) => r.value === form.role)?.hint}>
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })} className={inputClass}>
            {ROLES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        {message && <Notice tone={message.tone}>{message.text}</Notice>}
        <Button type="submit" variant="primary" disabled={busy}>Create user</Button>
      </form>
    </Card>
  );
}
