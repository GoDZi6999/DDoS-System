"use client";
// One Server-Sent Events connection per tab (app/api/live), shared by every
// widget. Alert notifications revalidate the SWR caches that show alerts and
// statistics; traffic ticks feed the live chart.
import { createContext, useContext, useEffect, useRef, useState } from "react";
import { useSWRConfig } from "swr";
import { fetcher } from "@/lib/api";
import type { LiveMessage, TrafficTick } from "@/lib/types";

export type LiveStatus = "connecting" | "live" | "offline";

type LiveState = { status: LiveStatus; ticks: TrafficTick[]; lastAlertAt: number };

const LiveContext = createContext<LiveState>({ status: "connecting", ticks: [], lastAlertAt: 0 });

/** Ticks kept for the live chart: one per second, so five minutes. */
const MAX_TICKS = 300;
const REVALIDATE_MS = 2000;

type Buckets = Map<number, Map<string, TrafficTick>>;

/** Several engines can publish ticks (e.g. `inject` next to the main engine):
 * keep the latest tick per engine per second and add them up. */
function aggregate(buckets: Buckets): TrafficTick[] {
  const seconds = [...buckets.entries()].sort(([a], [b]) => a - b);
  // The newest second may still be missing other engines' ticks; show it only
  // once a later second has started (unless it is all there is).
  return (seconds.length > 1 ? seconds.slice(0, -1) : seconds)
    .map(([second, sources]) => {
      const ticks = [...sources.values()];
      const sum = (key: keyof TrafficTick) => ticks.reduce((t, x) => t + Number(x[key] ?? 0), 0);
      return {
        ts: new Date(second * 1000).toISOString(),
        flows_per_s: sum("flows_per_s"),
        packets_per_s: sum("packets_per_s"),
        attacks: sum("attacks"),
        attacks_per_s: ticks.reduce((t, x) => t + (x.attacks_per_s ?? x.attacks), 0),
        max_risk: Math.max(...ticks.map((x) => x.max_risk)),
        active_flows: sum("active_flows"),
      };
    });
}

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const { mutate } = useSWRConfig();
  const buckets = useRef<Buckets>(new Map());
  const [state, setState] = useState<LiveState>({
    status: "connecting",
    ticks: [],
    lastAlertAt: 0,
  });

  useEffect(() => {
    let source: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let pending: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    // Bursts of alert updates (a flood updates its alert on every detection)
    // collapse into one refresh every couple of seconds.
    const revalidate = () => {
      if (pending) return;
      pending = setTimeout(() => {
        pending = undefined;
        mutate((key) => typeof key === "string" && /^(alerts|stats\/)/.test(key));
      }, REVALIDATE_MS);
    };

    const connect = () => {
      source = new EventSource("/api/live");
      source.onmessage = (event) => {
        let message: LiveMessage;
        try {
          message = JSON.parse(event.data);
        } catch {
          return;
        }
        if (message.type === "auth.ok") {
          setState((s) => ({ ...s, status: "live" }));
        } else if (message.type === "traffic.tick") {
          const tick = message.data;
          const second = Math.floor(Date.parse(tick.ts) / 1000);
          if (Number.isNaN(second)) return;
          const sources = buckets.current.get(second) ?? new Map<string, TrafficTick>();
          sources.set(tick.source_id ?? "engine", tick);
          buckets.current.set(second, sources);
          for (const key of buckets.current.keys()) {
            if (key <= second - MAX_TICKS) buckets.current.delete(key);
          }
          const ticks = aggregate(buckets.current);
          setState((s) => ({ ...s, ticks }));
        } else if (message.type === "alert.new" || message.type === "alert.updated") {
          setState((s) => ({ ...s, lastAlertAt: Date.now() }));
          revalidate();
        }
      };
      source.onerror = () => {
        setState((s) => ({ ...s, status: "offline" }));
        // EventSource retries by itself unless the server refused the stream
        // (e.g. 401). Then check the session (redirects to login if it ended)
        // and reconnect after a pause.
        if (source?.readyState === EventSource.CLOSED && !closed) {
          fetcher("auth/me").catch(() => undefined);
          retry = setTimeout(connect, 5000);
        }
      };
    };

    connect();
    return () => {
      closed = true;
      source?.close();
      clearTimeout(retry);
      clearTimeout(pending);
    };
  }, [mutate]);

  return <LiveContext.Provider value={state}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveState {
  return useContext(LiveContext);
}
