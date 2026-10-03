import type { Metadata } from "next";
import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Sign in · SentinelAI" };

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const { next } = await searchParams;
  return (
    <main className="flex flex-1 items-center justify-center px-4 py-16">
      <div className="w-full max-w-sm">
        <p className="text-sm font-semibold uppercase tracking-widest text-accent">SentinelAI</p>
        <h1 className="mt-2 text-2xl font-semibold text-ink">Sign in to the SOC</h1>
        <p className="mt-1 text-sm text-ink-2">Real-time network threat detection.</p>
        <LoginForm next={typeof next === "string" ? next : "/"} />
      </div>
    </main>
  );
}
