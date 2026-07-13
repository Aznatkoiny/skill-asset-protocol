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
  title: "“NEVER HANDED OVER” — SKILL ASSET PROTOCOL",
  description:
    "A manifesto for the sovereignty of authored work. Pay $0.25 in testnet USDC and the hosted skill runs for you — you get the output, never the skill.",
  openGraph: {
    title: "“THE PROOF” — a manifesto for the sovereignty of authored work",
    description:
      "Ten principles. Real on-chain receipts. A live x402 endpoint: the artifact is never handed over.",
    url: "https://neverhandedover.com",
    siteName: "SKILL ASSET PROTOCOL",
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
