import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  metadataBase: new URL('https://neverhandedover.com'),
  title: {
    default: 'Human Choice — More room for a life you value',
    template: '%s · Human Choice',
  },
  description: 'Research and tools for human flourishing in the age of AI. Exploring capability, agency, and how the benefits of automation are shared.',
  openGraph: {
    title: 'Human Choice — More room for a life you value',
    description: 'Research and tools for human flourishing in the age of AI. Exploring capability, agency, and how the benefits of automation are shared.',
    url: '/',
    siteName: 'Human Choice',
    type: 'website',
  },
  alternates: { canonical: '/' },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" data-scroll-behavior="smooth"><body>{children}</body></html>;
}
