import type { Metadata } from "next";
import { SensorsView } from "@/components/views/sensors";

export const metadata: Metadata = { title: "Sensors · SentinelAI" };

export default function SensorsPage() {
  return <SensorsView />;
}
