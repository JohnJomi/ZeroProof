/** Root layout. */

import type { ReactNode } from "react";
import "./globals.css";

export const metadata = {
  title: "ZeroProof — Prove it. Don't reveal it.",
  description:
    "Prove you know a secret without ever sending it. A zero-knowledge authentication demo built on Schnorr proofs.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
