import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "IntentGuard | Financial Agent Governance",
  description:
    "A real-time governance control plane for safe, bounded and auditable financial agents.",
  keywords: [
    "financial agents",
    "AI governance",
    "policy enforcement",
    "agent security",
    "hackathon",
  ],
  openGraph: {
    title: "IntentGuard | Financial Agent Governance",
    description:
      "Every agent action bounded before execution—with permissions, budgets, revocation and verifiable audit evidence.",
    images: ["/og.png"],
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "IntentGuard | Financial Agent Governance",
    description:
      "A real-time control plane for safe, bounded and auditable financial agents.",
    images: ["/og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
