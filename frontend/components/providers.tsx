"use client";
import { SWRConfig } from "swr";
import { fetcher } from "@/lib/api";
import { LiveProvider } from "@/lib/live";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig value={{ fetcher, revalidateOnFocus: false, shouldRetryOnError: false }}>
      <LiveProvider>{children}</LiveProvider>
    </SWRConfig>
  );
}
