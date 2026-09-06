/** Landing page. Editorial, static — no client JS beyond the shared layout. */

import { Mark, Tick, Cross, Lock, Device, Server, Shield, ArrowRight } from "./icons.tsx";

export default function Landing() {
  return (
    <>
      <header className="shell">
        <nav className="nav">
          <a href="/" className="brand">
            <Mark />
            ZeroProof
          </a>
          <div className="nav-right">
            <a href="#how" className="btn btn-ghost hide-sm">How it works</a>
            <a href="/app" className="btn">Open the demo</a>
          </div>
        </nav>
      </header>

      {/* ---------------------------------------------------------- hero */}
      <section className="shell hero">
        <div className="hero-grid">
          <div>
            <span className="label label-accent">Zero-knowledge authentication</span>
            <h1>
              Prove it.
              <em>Don&rsquo;t reveal it.</em>
            </h1>
            <p className="lede">
              ZeroProof lets you prove you know a secret without ever sending it. Your
              password stays on your device — the server receives only a{" "}
              <span className="mark">mathematical proof</span> that you know it.
            </p>
            <div className="hero-actions">
              <a href="/app" className="btn btn-accent btn-lg">
                Try the live demo <ArrowRight className="tick" />
              </a>
              <a href="#how" className="btn btn-ghost btn-lg">See how it works</a>
            </div>
          </div>

          {/* The brand idea, stated once, visually. */}
          <div className="split-card" aria-label="What stays local and what is sent">
            <div className="split-half split-stays">
              <Lock className="split-icon" />
              <h4>Your secret</h4>
              <p>Never leaves this device. Not stored, not transmitted, not recoverable.</p>
            </div>
            <div className="barrier">
              <span className="barrier-line" />
              network
              <span className="barrier-line" />
            </div>
            <div className="split-half">
              <Server className="split-icon" />
              <h4>The proof</h4>
              <p>A single-use transcript the server can check but cannot learn from.</p>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------- the comparison */}
      <section className="band band-sunk">
        <div className="shell">
          <span className="label">The difference</span>
          <h2 style={{ fontSize: "var(--t-h1)", marginTop: "1rem", maxWidth: "18ch" }}>
            Most logins hand over the thing you&rsquo;re protecting.
          </h2>
          <div className="compare">
            <div className="compare-col">
              <span className="label">Password authentication</span>
              <h3 style={{ marginTop: "0.7rem" }}>You send the secret</h3>
              <ul className="compare-list">
                {[
                  "Your password travels to the server on every login.",
                  "The server stores something sufficient to impersonate you.",
                  "A breach of that store exposes every account in it.",
                  "You have to trust the server to handle it correctly.",
                ].map((t) => (
                  <li key={t}><Cross className="x" />{t}</li>
                ))}
              </ul>
            </div>
            <div className="compare-col is-zk">
              <span className="label label-accent">ZeroProof</span>
              <h3 style={{ marginTop: "0.7rem" }}>You send a proof</h3>
              <ul className="compare-list">
                {[
                  "The secret is used on your device and never sent.",
                  "The server stores a public commitment it cannot invert.",
                  "A stolen database yields no usable credential.",
                  "Verification needs no trust in what the server sees.",
                ].map((t) => (
                  <li key={t}><Tick className="y" />{t}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------ the flow */}
      <section className="band shell" id="how">
        <span className="label">How a login works</span>
        <h2 style={{ fontSize: "var(--t-h1)", marginTop: "1rem", maxWidth: "20ch" }}>
          Three steps. The secret is involved in only one of them.
        </h2>
        <div className="steps">
          {[
            {
              n: "Step 01",
              h: "The server sets a puzzle",
              p: "It issues a single-use challenge that expires in sixty seconds. Reusing one is impossible.",
            },
            {
              n: "Step 02",
              h: "Your device answers it",
              p: "Your browser combines the secret with the challenge to build a proof. This is the only moment the secret is used, and it happens locally.",
            },
            {
              n: "Step 03",
              h: "The server checks the answer",
              p: "It runs one equation. If the proof holds, you knew the secret — and that is all the server learns.",
            },
          ].map((s) => (
            <div className="step" key={s.n}>
              <span className="step-n">{s.n}</span>
              <h3>{s.h}</h3>
              <p>{s.p}</p>
            </div>
          ))}
        </div>
      </section>

      {/* --------------------------------------------- editorial features */}
      <section className="band band-sunk">
        <div className="shell">
          <div className="feature">
            <div>
              <Device className="split-icon" />
              <h2>The secret never leaves the browser.</h2>
              <p className="lede">
                It lives in page memory for as long as you are typing, and nowhere else. Not
                in local storage, not in a cookie, not in the URL, not in any log.
              </p>
            </div>
            <div className="feature-visual">
              <span className="label">Sent when you register</span>
              <pre className="payload" style={{ marginTop: "0.8rem" }}>{`{
  "username": "alice",
  "scheme":   "schnorr-dlog-v1",
  "salt":     "9f2c…7b04",
  "y":        "c41e…"
}`}</pre>
              <ul className="assurances" style={{ marginTop: "1.1rem" }}>
                <li><Tick />No secret field exists in this request.</li>
              </ul>
            </div>
          </div>

          <div className="feature feature-flip">
            <div className="feature-visual">
              <span className="label">Sent when you prove</span>
              <pre className="payload" style={{ marginTop: "0.8rem" }}>{`{
  "username": "alice",
  "nonce":    "4a7f…c1",
  "t":        "8b02…",
  "s":        "1de9…"
}`}</pre>
              <ul className="assurances" style={{ marginTop: "1.1rem" }}>
                <li><Tick />A fresh transcript every time. Replays are rejected.</li>
              </ul>
            </div>
            <div>
              <Shield className="split-icon" />
              <h2>The server verifies what it cannot read.</h2>
              <p className="lede">
                One equation decides it. The transcript is simulatable — anyone could produce
                a convincing-looking one without the secret — so it carries no information
                about the secret at all.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------ final CTA */}
      <section className="band shell">
        <div className="cta">
          <h2>See it refuse a bad proof.</h2>
          <p>
            Register a secret, prove you know it, then try the wrong one and watch the
            server turn it down. Open your network tab while you do — the secret is not in it.
          </p>
          <a href="/app" className="btn btn-accent btn-lg">
            Open the demo <ArrowRight className="tick" />
          </a>
        </div>
        <div className="foot">
          <span>ZeroProof — Schnorr proof of knowledge over RFC 3526 Group 14.</span>
          <span>A demonstration system, not a production identity provider.</span>
        </div>
      </section>
    </>
  );
}
