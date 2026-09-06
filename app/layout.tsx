/** Minimal App Router root layout. The Phase 4 UI replaces this shell. */

import type { ReactNode } from "react";

export const metadata = {
  title: "ZeroProof",
  description: "Zero-knowledge proof of knowledge of a secret",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
