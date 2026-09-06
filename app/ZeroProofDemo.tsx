"use client";

/**
 * The interactive demo: Register, Prove, Audit, Privacy.
 *
 * The secret lives in React state and nowhere else — no localStorage, no
 * cookies, no URL parameters, never in a request body. Every request this
 * component sends is built by `lib/client.ts`, which is the only code that
 * touches the secret, and which discards `x` as soon as the proof is made.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  register,
  proveKnowledge,
  fetchLog,
  validateCredentials,
  ApiError,
  SCHEME,
  type CredentialProblem,
  type RegisterBody,
  type VerifyBody,
  type VerifyResponse,
  type LogEntry,
} from "../lib/client.ts";

type Tab = "register" | "prove" | "audit" | "privacy";

const TABS: { id: Tab; label: string }[] = [
  { id: "register", label: "Register" },
  { id: "prove", label: "Prove" },
  { id: "audit", label: "Audit" },
  { id: "privacy", label: "Privacy" },
];

/** Long hex is unreadable in full; show the ends. */
function abbreviate(hex: string, keep = 16): string {
  return hex.length <= keep * 2 ? hex : `${hex.slice(0, keep)}…${hex.slice(-keep)}`;
}

/** Stable server reasons rendered as something a person can act on. */
const PROBLEM_TEXT: Record<CredentialProblem, string> = {
  missing_username: "Enter a username.",
  missing_secret: "Enter your secret.",
};

const REASON_TEXT: Record<string, string> = {
  username_taken: "That username is already registered. Pick a different one.",
  invalid_username: "Usernames may contain only letters, digits, and . _ - @",
  invalid_public_key: "The generated public key was rejected. Please try again.",
  unsupported_scheme: "This build does not support the requested proof scheme.",
  unknown_user: "No such user. Register that username first.",
  nonce_invalid: "The challenge expired or was already used. Try again.",
  verification_failed: "The proof did not check out — the secret does not match.",
  malformed_request: "The request was rejected as malformed.",
  internal_error: "The server hit an internal error. Please try again.",
};

/** Every failure path the UI can hit, turned into a useful message. */
function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    return REASON_TEXT[error.reason] ?? `Request failed (${error.status}): ${error.reason}`;
  }
  if (error instanceof Error) {
    // Web Crypto is absent outside a secure context — the usual cause is
    // opening the app over plain http on a LAN address instead of localhost.
    if (error.message.includes("Web Crypto")) {
      return (
        "Web Crypto is unavailable, so no proof can be generated. " +
        "Open this page over https, or on http://localhost."
      );
    }
    if (error.name === "TypeError") {
      return "Could not reach the server. Check that it is running and try again.";
    }
    return error.message;
  }
  return "Something went wrong. Please try again.";
}

export default function ZeroProofDemo() {
  const [tab, setTab] = useState<Tab>("register");

  // The secret is component state only. It is never persisted anywhere.
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  // Masked by default; toggled only in memory, never persisted.
  const [secretVisible, setSecretVisible] = useState(false);

  // Read as a fallback on submit. React state is the source of truth, but if
  // anything writes to the input without firing onChange — browser autofill, a
  // password manager, a bundle that failed to hydrate — the state goes stale
  // while the field looks filled. Reading the element directly means the user
  // gets a real attempt or a real error, never a dead button.
  const regUserRef = useRef<HTMLInputElement>(null);
  const regSecretRef = useRef<HTMLInputElement>(null);
  const proveUserRef = useRef<HTMLInputElement>(null);
  const proveSecretRef = useRef<HTMLInputElement>(null);

  const [registering, setRegistering] = useState(false);
  const [registered, setRegistered] = useState<RegisterBody | null>(null);
  const [registerError, setRegisterError] = useState<string | null>(null);

  const [proving, setProving] = useState(false);
  const [proof, setProof] = useState<{ sent: VerifyBody; result: VerifyResponse } | null>(null);
  const [proveError, setProveError] = useState<string | null>(null);

  const [log, setLog] = useState<LogEntry[]>([]);
  const [loadingLog, setLoadingLog] = useState(false);
  const [logError, setLogError] = useState<string | null>(null);

  /**
   * The submit buttons are gated only on a request being in flight. Emptiness
   * is reported on submit instead of disabling the control: a disabled button
   * cannot tell the user what is wrong.
   */
  const readInputs = (
    userRef: React.RefObject<HTMLInputElement | null>,
    secretRef: React.RefObject<HTMLInputElement | null>,
  ) => validateCredentials(username || userRef.current?.value || "", secret || secretRef.current?.value || "");

  const loadLog = useCallback(async () => {
    setLoadingLog(true);
    setLogError(null);
    try {
      setLog(await fetchLog());
    } catch (error) {
      setLogError(messageFor(error));
    } finally {
      setLoadingLog(false);
    }
  }, []);

  useEffect(() => {
    if (tab === "audit") void loadLog();
  }, [tab, loadLog]);

  async function onRegister(event: React.FormEvent) {
    event.preventDefault();
    const input = readInputs(regUserRef, regSecretRef);
    if (!input.ok) {
      setRegisterError(PROBLEM_TEXT[input.problem]);
      return;
    }
    setRegistering(true);
    setRegisterError(null);
    setRegistered(null);
    try {
      // Salt, x and y are all computed in the browser; only y and salt are sent.
      setRegistered(await register(input.username, input.secret));
    } catch (error) {
      setRegisterError(messageFor(error));
    } finally {
      setRegistering(false);
    }
  }

  async function onProve(event: React.FormEvent) {
    event.preventDefault();
    const input = readInputs(proveUserRef, proveSecretRef);
    if (!input.ok) {
      setProveError(PROBLEM_TEXT[input.problem]);
      return;
    }
    setProving(true);
    setProveError(null);
    setProof(null);
    try {
      const { sent, result } = await proveKnowledge(input.username, input.secret);
      setProof({ sent, result });
    } catch (error) {
      setProveError(messageFor(error));
    } finally {
      setProving(false);
    }
  }

  return (
    <>
      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "register" && (
        <section className="panel">
          <h2>Register</h2>
          <p className="hint">
            The browser generates a random salt, derives <code>x = SHA256(salt ‖ secret) mod q</code>,
            and sends only the commitment <code>y = g^x mod p</code>. Your secret never leaves this page.
          </p>
          <form onSubmit={onRegister}>
            <div className="field">
              <label htmlFor="reg-user">Username</label>
              <input
                id="reg-user"
                ref={regUserRef}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
                placeholder="alice"
              />
            </div>
            <div className="field">
              <label htmlFor="reg-secret">Secret</label>
              <div className="secret-row">
                <input
                  id="reg-secret"
                  ref={regSecretRef}
                  type={secretVisible ? "text" : "password"}
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  autoComplete="new-password"
                  placeholder="a long, high-entropy passphrase"
                />
                <button
                  type="button"
                  className="reveal"
                  onClick={() => setSecretVisible((v) => !v)}
                  aria-pressed={secretVisible}
                  aria-label={secretVisible ? "Hide secret" : "Show secret"}
                >
                  {secretVisible ? "Hide" : "Show"}
                </button>
              </div>
            </div>
            <button className="action" type="submit" disabled={registering}>
              {registering ? "Registering…" : "Register"}
            </button>
          </form>

          {registerError && (
            <div className="status bad">
              <span className="verdict">Registration failed</span>
              <code>{registerError}</code>
            </div>
          )}

          {registered && (
            <div className="status ok">
              <span className="verdict">Registered</span>
              This exact JSON was sent — inspect it, there is no secret in it.
              <pre className="trunc">
{JSON.stringify(
  { ...registered, y: abbreviate(registered.y, 24) },
  null,
  2,
)}
              </pre>
            </div>
          )}
        </section>
      )}

      {tab === "prove" && (
        <section className="panel">
          <h2>Prove knowledge</h2>
          <p className="hint">
            Fetches a single-use nonce, re-derives <code>x</code> from the stored salt and your
            typed secret, and builds a Schnorr proof in the browser. Only <code>t</code> and{" "}
            <code>s</code> are transmitted.
          </p>
          <form onSubmit={onProve}>
            <div className="field">
              <label htmlFor="prove-user">Username</label>
              <input
                id="prove-user"
                ref={proveUserRef}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
                placeholder="alice"
              />
            </div>
            <div className="field">
              <label htmlFor="prove-secret">Secret</label>
              <div className="secret-row">
                <input
                  id="prove-secret"
                  ref={proveSecretRef}
                  type={secretVisible ? "text" : "password"}
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  autoComplete="off"
                  placeholder="type the wrong one to see it rejected"
                />
                <button
                  type="button"
                  className="reveal"
                  onClick={() => setSecretVisible((v) => !v)}
                  aria-pressed={secretVisible}
                  aria-label={secretVisible ? "Hide secret" : "Show secret"}
                >
                  {secretVisible ? "Hide" : "Show"}
                </button>
              </div>
            </div>
            <button className="action" type="submit" disabled={proving}>
              {proving ? "Proving…" : "Prove knowledge"}
            </button>
          </form>

          {proveError && (
            <div className="status bad">
              <span className="verdict">Could not complete</span>
              <code>{proveError}</code>
            </div>
          )}

          {proof && (
            <div className={`status ${proof.result.verified ? "ok" : "bad"}`}>
              <span className="verdict">
                {proof.result.verified ? "✓ Verified" : "✗ Not verified"}
              </span>
              reason: <code>{proof.result.reason}</code>
              <pre className="trunc">
{JSON.stringify(
  {
    username: proof.sent.username,
    scheme: proof.sent.scheme,
    nonce: proof.sent.nonce,
    t: abbreviate(proof.sent.t),
    s: abbreviate(proof.sent.s),
  },
  null,
  2,
)}
              </pre>
            </div>
          )}
        </section>
      )}

      {tab === "audit" && (
        <section className="panel">
          <h2>Verification log</h2>
          <p className="hint">The 20 most recent verification attempts recorded by the server.</p>
          <div className="row">
            <button className="action secondary" onClick={loadLog} disabled={loadingLog}>
              {loadingLog ? "Refreshing…" : "Refresh"}
            </button>
          </div>

          {logError && (
            <div className="status bad">
              <code>{logError}</code>
            </div>
          )}

          {!logError && log.length === 0 && !loadingLog && (
            <p className="muted" style={{ marginTop: 16 }}>
              No verification attempts yet.
            </p>
          )}

          {log.length > 0 && (
            <div className="table-scroll" style={{ marginTop: 16 }}>
              <table>
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Scheme</th>
                    <th>Result</th>
                    <th>Reason</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {log.map((entry) => (
                    <tr key={entry.id}>
                      <td>{entry.username}</td>
                      <td><code>{entry.scheme}</code></td>
                      <td>
                        <span className={`pill ${entry.verified ? "ok" : "bad"}`}>
                          {entry.verified ? "verified" : "rejected"}
                        </span>
                      </td>
                      <td><code>{entry.reason ?? "—"}</code></td>
                      <td>{new Date(entry.at).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {tab === "privacy" && (
        <section className="panel privacy">
          <h2>What is sent to the server?</h2>
          <p className="hint">
            Open DevTools → Network and run the flow. The secret appears in no request body.
          </p>
          <ul>
            <li>
              <strong>The secret stays in the browser.</strong> It is held in page memory only —
              <span className="never"> never</span> written to localStorage, cookies, the URL, or
              any server-side store.
            </li>
            <li>
              <strong>Registration sends the public key and salt, not the secret.</strong> The
              browser computes <code>x = SHA256(salt ‖ secret) mod q</code> and sends only{" "}
              <code>y = g^x mod p</code>. Recovering <code>x</code> from <code>y</code> is the
              discrete logarithm problem in a 2048-bit group.
            </li>
            <li>
              <strong>Verification sends the proof, not the secret.</strong> The browser picks a
              fresh random <code>k</code>, sends <code>t = g^k</code> and{" "}
              <code>s = k + c·x</code>. Because <code>k</code> is fresh and uniform,{" "}
              <code>s</code> perfectly masks <code>x</code>.
            </li>
            <li>
              <strong>The server verifies without receiving the secret.</strong> It checks{" "}
              <code>g^s ≡ t · y^c (mod p)</code>. It learns only that the proof holds — a
              transcript it could have simulated by itself.
            </li>
          </ul>

          <div className="wire">
            <div>
              <h4>Sent on register</h4>
              <pre>{JSON.stringify({ username: "alice", scheme: SCHEME, salt: "…", y: "…" }, null, 2)}</pre>
            </div>
            <div>
              <h4>Sent on verify</h4>
              <pre>{JSON.stringify({ username: "alice", scheme: SCHEME, nonce: "…", t: "…", s: "…" }, null, 2)}</pre>
            </div>
          </div>
          <p className="muted" style={{ marginTop: 14, fontSize: 13 }}>
            Note: a stolen database still allows offline guessing of a weak secret, so ZeroProof
            requires a high-entropy passphrase. See <code>architecture.md</code> §6.
          </p>
        </section>
      )}
    </>
  );
}
