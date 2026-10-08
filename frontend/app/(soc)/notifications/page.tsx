import type { Metadata } from "next";
import { NotificationsView } from "@/components/views/notifications";

export const metadata: Metadata = { title: "Notifications · SentinelAI" };

export default function NotificationsPage() {
  return <NotificationsView />;
}
