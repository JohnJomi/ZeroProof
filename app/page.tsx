/** The demo shell. All interactivity lives in the client component. */

import ZeroProofDemo from "./ZeroProofDemo.tsx";

export default function Home() {
  return (
    <div className="wrap">
      <header>
        <h1>ZeroProof</h1>
        <p>
          Prove you know a secret without ever sending it. The browser holds the secret,
          derives a proof locally, and the server checks that proof against a public
          commitment it cannot invert.
        </p>
      </header>
      <ZeroProofDemo />
    </div>
  );
}
