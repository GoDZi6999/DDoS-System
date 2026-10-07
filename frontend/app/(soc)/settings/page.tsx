import type { Metadata } from "next";
import { SettingsView } from "@/components/views/settings";

export const metadata: Metadata = { title: "Settings · Argus" };

export default function SettingsPage() {
  return <SettingsView />;
}
