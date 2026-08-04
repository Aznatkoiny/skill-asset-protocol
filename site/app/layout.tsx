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
  metadataBase: new URL("https://neverhandedover.com"),
  title: {
    default: "Skill Asset Protocol — Spending controls for AI Agents",
    template: "%s · Skill Asset Protocol",
  },
  description:
    "Pre-release offline preview of a customer-hosted Wallet Kernel for policy-bound Agent spending, exact human approvals, and planned signed receipts.",
  openGraph: {
    title: "Give AI Agents a wallet without giving them the keys",
    description:
      "Pre-release offline preview of a wallet-native Agent Spend Control Plane with budgets, seller policy, approvals, and planned signed receipts.",
    url: "https://neverhandedover.com",
    siteName: "SKILL ASSET PROTOCOL",
    type: "website",
  },
  alternates: { canonical: "https://neverhandedover.com" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
