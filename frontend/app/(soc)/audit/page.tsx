import type { Metadata } from "next";
import { AuditView } from "@/components/views/audit";

export const metadata: Metadata = { title: "Audit log · SentinelAI" };

export default function AuditPage() {
  return <AuditView />;
}
