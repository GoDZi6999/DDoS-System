"use client";
// One Server-Sent Events connection per tab (app/api/live), shared by every
// widget. Alert notifications revalidate the SWR caches that show alerts and
// statistics; traffic ticks feed the live chart.
import { createContext, useContext, useEffect, useState } from "react";
import { useSWRConfig } from "swr";
import { fetcher } from "@/lib/api";
import type { LiveMessage, TrafficTick } from "@/lib/types";

export type LiveStatus = "connecting" | "live" | "offline";

type LiveState = { status: LiveStatus; ticks: TrafficTick[]; lastAlertAt: number };

const LiveContext = createContext<LiveState>({ status: "connecting", ticks: [], lastAlertAt: 0 });

/** Ticks kept for the live chart: one per second, so five minutes. */
const MAX_TICKS = 300;
const REVALIDATE_MS = 2000;

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const { mutate } = useSWRConfig();
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
          setState((s) => ({ ...s, ticks: [...s.ticks, message.data].slice(-MAX_TICKS) }));
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
