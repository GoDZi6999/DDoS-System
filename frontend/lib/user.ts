"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";
import type { Role, User } from "@/lib/types";

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

export function useMe() {
  return useSWR<User>("auth/me", fetcher, { revalidateOnFocus: true });
}

/** Mirrors the API's hierarchical roles; the API enforces them regardless. */
export function hasRole(user: User | undefined, role: Role): boolean {
  return !!user && RANK[user.role] >= RANK[role];
}
