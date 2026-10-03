import type { Metadata } from "next";
import { UsersView } from "@/components/views/users";

export const metadata: Metadata = { title: "Users · SentinelAI" };

export default function UsersPage() {
  return <UsersView />;
}
