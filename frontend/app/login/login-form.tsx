"use client";
import { useActionState } from "react";
import { loginAction, type LoginState } from "@/app/actions";
import { Button, Field, Notice, inputClass } from "@/components/ui";

export function LoginForm({ next }: { next: string }) {
  const [state, action, pending] = useActionState<LoginState, FormData>(loginAction, {});
  return (
    <form action={action} className="mt-6 space-y-4 rounded-xl border border-line bg-surface p-5">
      <input type="hidden" name="next" value={next} />
      <Field label="Username">
        <input
          name="username"
          autoComplete="username"
          required
          autoFocus
          defaultValue={state.username}
          className={inputClass}
        />
      </Field>
      <Field label="Password">
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          className={inputClass}
        />
      </Field>
      {state.error && <Notice tone="error">{state.error}</Notice>}
      <Button type="submit" variant="primary" disabled={pending} className="w-full">
        {pending ? "Signing in…" : "Sign in"}
      </Button>
    </form>
  );
}
