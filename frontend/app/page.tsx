import { connection } from "next/server";

type ServiceState = "ok" | "error" | "unknown";

type Readiness = {
  status: "ready" | "unavailable";
  checks: Record<string, "ok" | "error">;
};

// Called from the server, so the backend does not need to be reachable from
// the browser. API_INTERNAL_URL is the in-network address set by docker-compose.
async function getReadiness(): Promise<Readiness | null> {
  const baseUrl = process.env.API_INTERNAL_URL ?? "http://localhost:8000";
  try {
    const response = await fetch(`${baseUrl}/health/ready`, {
      signal: AbortSignal.timeout(5000),
    });
    // A 503 still carries a body saying which dependency is down.
    return (await response.json()) as Readiness;
  } catch {
    return null;
  }
}

const badge: Record<ServiceState, { label: string; className: string }> = {
  ok: { label: "Online", className: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30" },
  error: { label: "Offline", className: "bg-red-500/15 text-red-300 ring-red-500/30" },
  unknown: { label: "Unknown", className: "bg-slate-500/15 text-slate-300 ring-slate-500/30" },
};

export default async function Home() {
  // Render on every request: without this, the build would prerender the page
  // and freeze whatever health status the backend had at build time.
  await connection();
  const readiness = await getReadiness();

  const services: { name: string; state: ServiceState }[] = [
    { name: "API", state: readiness ? "ok" : "error" },
    { name: "PostgreSQL", state: readiness?.checks.database ?? "unknown" },
    { name: "Redis", state: readiness?.checks.redis ?? "unknown" },
  ];

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col gap-8 px-6 py-16">
      <header>
        <p className="text-sm font-semibold uppercase tracking-widest text-cyan-400">SentinelAI</p>
        <h1 className="mt-2 text-3xl font-bold">Security Operations Center</h1>
        <p className="mt-3 text-slate-400">
          Real-time network threat detection. The SOC dashboard arrives in Phase 6; until then
          this page confirms that every service in the stack is reachable.
        </p>
      </header>

      <section
        aria-labelledby="status-heading"
        className="rounded-xl border border-slate-800 bg-slate-900/60 p-6"
      >
        <h2 id="status-heading" className="text-lg font-semibold">
          {readiness?.status === "ready"
            ? "All systems operational"
            : "Degraded: some services are unavailable"}
        </h2>
        <ul className="mt-4 divide-y divide-slate-800">
          {services.map(({ name, state }) => (
            <li key={name} className="flex items-center justify-between py-3">
              <span>{name}</span>
              <span
                className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset ${badge[state].className}`}
              >
                {badge[state].label}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
