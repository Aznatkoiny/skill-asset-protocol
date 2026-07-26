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
    default: "Skill Asset Protocol — Attribute and reward internal AI work",
    template: "%s · Skill Asset Protocol",
  },
  description:
    "Register employee-authored AI Skills, verify real team reuse, and close a transparent employer-funded reward program.",
  openGraph: {
    title: "Make the people behind your AI leverage visible",
    description:
      "A product preview for registering internal AI Skills, verifying reuse, and creating reviewable Creator reward statements.",
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
