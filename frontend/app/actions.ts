"use server";
import { redirect } from "next/navigation";
import { login, logout } from "@/lib/session";

export type LoginState = { error?: string; username?: string };

/** Only same-site paths, so the login form cannot be used as an open redirect. */
function safeNext(value: FormDataEntryValue | null): string {
  if (typeof value !== "string" || !value.startsWith("/")) return "/";
  if (value.startsWith("//") || value.startsWith("/\\") || value.startsWith("/login")) return "/";
  return value;
}

export async function loginAction(_previous: LoginState, form: FormData): Promise<LoginState> {
  const username = String(form.get("username") ?? "").trim();
  const password = String(form.get("password") ?? "");
  if (!username || !password) return { error: "Enter your username and password.", username };
  const result = await login(username.slice(0, 64), password.slice(0, 256));
  if (!result.ok) return { error: result.error, username };
  redirect(safeNext(form.get("next")));
}

export async function logoutAction() {
  await logout();
  redirect("/login");
}
