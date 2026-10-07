import type { Metadata } from "next";
import { UsersView } from "@/components/views/users";

export const metadata: Metadata = { title: "Users · Argus" };

export default function UsersPage() {
  return <UsersView />;
}
