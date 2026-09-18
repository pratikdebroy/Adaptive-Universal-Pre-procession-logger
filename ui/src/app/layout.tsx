import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AegisLog | Autonomous SOC Pipeline & Provenance Dashboard',
  description: 'Self-Healing, High-Throughput OCSF Log Pipeline with Merkle Provenance & BDPT Architecture',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-100 antialiased">{children}</body>
    </html>
  );
}
