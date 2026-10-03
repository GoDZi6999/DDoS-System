import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emits .next/standalone with a minimal server.js, used by the Docker image.
  output: "standalone",
  poweredByHeader: false,
};

export default nextConfig;
