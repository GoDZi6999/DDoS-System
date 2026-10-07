import type { Metadata } from "next";
import { EyeIcon } from "@/components/icons";
import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Sign in · Argus" };

function Radar() {
  return (
    <svg viewBox="0 0 200 200" className="size-64 text-accent sm:size-80" aria-hidden>
      <defs>
        <radialGradient id="radar-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="currentColor" stopOpacity="0.18" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
        </radialGradient>
        <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="currentColor" stopOpacity="0" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0.55" />
        </linearGradient>
      </defs>
      <circle cx="100" cy="100" r="96" fill="url(#radar-glow)" />
      {[96, 72, 48, 24].map((r) => (
        <circle key={r} cx="100" cy="100" r={r} fill="none" stroke="currentColor" strokeOpacity="0.25" />
      ))}
      <path d="M100 4v192M4 100h192" stroke="currentColor" strokeOpacity="0.18" />
      <g className="radar-sweep">
        <path d="M100 100 L196 100 A96 96 0 0 0 167.9 32.1 Z" fill="url(#sweep)" />
      </g>
      <circle cx="146" cy="70" r="3" fill="var(--status-critical)">
        <animate attributeName="opacity" values="1;0.2;1" dur="1.6s" repeatCount="indefinite" />
      </circle>
      <circle cx="62" cy="128" r="2.5" fill="var(--status-warning)" opacity="0.8" />
      <circle cx="120" cy="150" r="2" fill="currentColor" opacity="0.7" />
    </svg>
  );
}

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const { next } = await searchParams;
  return (
    <main className="relative grid flex-1 lg:grid-cols-[1.1fr_1fr]">
      <section className="relative hidden flex-col justify-between overflow-hidden border-r border-line p-10 lg:flex">
        <div className="scanline" />
        <p className="label-caps text-accent">
          <span aria-hidden>{"// "}</span>Security operations
        </p>
        <div className="flex flex-col items-center gap-8">
          <Radar />
          <div className="max-w-md text-center">
            <h2 className="font-display text-3xl font-bold uppercase tracking-[0.12em] text-ink">
              Every flow, <span className="text-accent glow-text">explained</span>
            </h2>
            <p className="mt-3 text-sm text-ink-2">
              Real-time classification of network flows with an explainable model, risk scoring
              and a SOC workflow. Detection and alerting only: Argus never blocks traffic.
            </p>
          </div>
        </div>
        <dl className="grid grid-cols-3 gap-4 font-mono text-xs">
          {[
            ["Model", "XGBoost + SHAP"],
            ["Latency", "≈1.7 s to alert"],
            ["Audit", "Append-only"],
          ].map(([k, v]) => (
            <div key={k} className="border-l border-accent/40 pl-3">
              <dt className="label-caps text-muted">{k}</dt>
              <dd className="mt-1 text-ink">{v}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="flex items-center justify-center px-4 py-16">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3">
            <span className="grid size-11 place-items-center rounded-sm border border-accent/50 bg-accent/10 text-accent shadow-[0_0_24px_-6px_var(--accent)]">
              <EyeIcon className="size-6" />
            </span>
            <div>
              <p className="font-display text-xl font-bold tracking-[0.18em] text-ink">
                AR<span className="text-accent">GUS</span>
              </p>
              <p className="label-caps text-muted">SOC console</p>
            </div>
          </div>
          <h1 className="font-display text-2xl font-bold uppercase tracking-[0.08em] text-ink">
            Sign in to the SOC
          </h1>
          <p className="mt-1 font-mono text-xs text-muted">
            Authorised personnel only. Sessions and actions are audited.
          </p>
          <LoginForm next={typeof next === "string" ? next : "/"} />
        </div>
      </section>
    </main>
  );
}
