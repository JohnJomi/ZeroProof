/** The application. Calmer than the landing page: clarity over expression. */

import ZeroProofDemo from "../ZeroProofDemo.tsx";
import { Mark } from "../icons.tsx";

export default function AppPage() {
  return (
    <>
      <header className="shell">
        <nav className="nav">
          <a href="/" className="brand">
            <Mark />
            ZeroProof
          </a>
          <div className="nav-right">
            <a href="/" className="btn btn-ghost">Back to overview</a>
          </div>
        </nav>
      </header>

      <main className="shell app-main">
        <div className="app-head">
          <div>
            <span className="label label-accent">Live demo</span>
            <h1 style={{ marginTop: "1rem", maxWidth: "16ch" }}>
              Prove knowledge of a secret.
            </h1>
            <p className="lede" style={{ marginTop: "1rem" }}>
              Register a commitment, then prove you know the secret behind it. Nothing you
              type here is transmitted.
            </p>
          </div>
        </div>
        <ZeroProofDemo />
      </main>
    </>
  );
}
