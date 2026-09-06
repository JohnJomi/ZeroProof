/** Minimal App Router root layout. */

import type { ReactNode } from "react";
import "./globals.css";

export const metadata = {
  title: "ZeroProof",
  description: "Prove knowledge of a secret without ever sending it",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
