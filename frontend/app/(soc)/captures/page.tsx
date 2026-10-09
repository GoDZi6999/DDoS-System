import type { Metadata } from "next";
import { Suspense } from "react";
import { CapturesView } from "@/components/views/captures";

export const metadata: Metadata = { title: "Captures · ArgusAI" };

export default function CapturesPage() {
  return (
    <Suspense>
      <CapturesView />
    </Suspense>
  );
}
