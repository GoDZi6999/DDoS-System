import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { AlertDetailView } from "@/components/views/alert-detail";

export async function generateMetadata({ params }: PageProps<"/alerts/[id]">): Promise<Metadata> {
  const { id } = await params;
  return { title: `Alert #${id} · ArgusAI` };
}

export default async function AlertPage({ params }: PageProps<"/alerts/[id]">) {
  const { id } = await params;
  if (!/^\d{1,12}$/.test(id)) notFound();
  return <AlertDetailView id={Number(id)} />;
}
