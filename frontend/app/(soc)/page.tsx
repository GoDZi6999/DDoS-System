import type { Metadata } from "next";
import { Overview } from "@/components/views/overview";

export const metadata: Metadata = { title: "Overview · Argus" };

export default function OverviewPage() {
  return <Overview />;
}
