import type { Metadata } from "next";
import { Suspense } from "react";
import { AlertsList } from "@/components/views/alerts-list";

export const metadata: Metadata = { title: "Alerts · Argus" };

export default function AlertsPage() {
  return (
    <Suspense>
      <AlertsList />
    </Suspense>
  );
}
