import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import "./globals.css";

// Fonts are vendored (app/fonts, SIL Open Font License) so builds need no
// network access and the same-origin CSP (font-src 'self') holds.
const display = localFont({
  src: [
    { path: "./fonts/chakra-petch-latin-500-normal.woff2", weight: "500" },
    { path: "./fonts/chakra-petch-latin-600-normal.woff2", weight: "600" },
    { path: "./fonts/chakra-petch-latin-700-normal.woff2", weight: "700" },
  ],
  variable: "--font-display-face",
});
const body = localFont({
  src: "./fonts/inter-latin-wght-normal.woff2",
  weight: "100 900",
  variable: "--font-body",
});
const mono = localFont({
  src: "./fonts/jetbrains-mono-latin-wght-normal.woff2",
  weight: "100 800",
  variable: "--font-mono-face",
});

export const metadata: Metadata = {
  title: "ArgusAI",
  description: "Real-time network threat detection and security monitoring",
};

export const viewport: Viewport = { themeColor: "#04070c", colorScheme: "dark" };

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      data-theme="dark"
      className={`${display.variable} ${body.variable} ${mono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col font-sans">{children}</body>
    </html>
  );
}
