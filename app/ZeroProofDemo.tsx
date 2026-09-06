"use client";

/**
 * The ZeroProof application.
 *
 * The secret lives in React state and nowhere else — no localStorage, no
 * cookies, no URL parameters, never in a request body. Every request is built
 * by `lib/client.ts`, the only module that touches the secret.
 *
 * This file is presentation only; the protocol lives in lib/zk and lib/client.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  register,
  proveKnowledge,
  fetchLog,
  validateCredentials,
  ApiError,
  SCHEME,
  type ProofStage,
  type RegisterBody,
  type VerifyBody,
  type VerifyResponse,
  type LogEntry,
  type CredentialProblem,
} from "../lib/client.ts";
import { Tick, Cross, Lock, Device, Server, Ledger, ArrowRight } from "./icons.tsx";

type Tab = "register" | "prove" | "audit";

const TABS: { id: Tab; label: string }[] = [
  { id: "register", label: "Register" },
  { id: "prove", label: "Prove" },
  { id: "audit", label: "Audit log" },
];

const PROBLEM_TEXT: Record<CredentialProblem, string> = {
  missing_username: "Enter a username.",
  missing_secret: "Enter your secret.",
};

/** Stable server reasons rendered as something a person can act on. */
const REASON_TEXT: Record<string, string> = {
  username_taken: "That username is already registered. Pick a different one.",
  invalid_username: "Usernames may contain only letters, digits, and . _ - @",
  invalid_public_key: "The generated public key was rejected. Please try again.",
  unsupported_scheme: "This build does not support the requested proof scheme.",
  unknown_user: "No such user yet. Register that username first.",
  nonce_invalid: "The challenge expired or was already used. Try again.",
  verification_failed: "The proof did not check out — that secret does not match.",
  malformed_request: "The request was rejected as malformed.",
  internal_error: "The server hit an internal error. Please try again.",
};

function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    return REASON_TEXT[error.reason] ?? `Request failed (${error.status}): ${error.reason}`;
  }
  if (error instanceof Error) {
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

/** Long hex is unreadable in full; show the ends. */
const abbreviate = (hex: string, keep = 10) =>
  hex.length <= keep * 2 ? hex : `${hex.slice(0, keep)}…${hex.slice(-keep)}`;

/* ------------------------------------------------------------------ pipeline */

type StageState = "idle" | "active" | "done" | "fail";

const PIPELINE: { key: ProofStage | "verified"; name: string; where: string }[] = [
  { key: "challenge", name: "Challenge issued", where: "server" },
  { key: "generating", name: "Proof generated", where: "this device" },
  { key: "verifying", name: "Proof sent for checking", where: "network" },
  { key: "verified", name: "Signature verified", where: "server" },
];

/** Where the flow has reached, so each row can show idle / active / done. */
function stageStates(stage: ProofStage | "verified" | null, failed: boolean) {
  const order = ["challenge", "generating", "verifying", "verified"];
  const reached = stage === null ? -1 : order.indexOf(stage === "generated" ? "generating" : stage);
  return PIPELINE.map((row, i): StageState => {
    if (reached < 0) return "idle";
    if (i < reached) return "done";
    if (i === reached) return failed ? "fail" : stage === "verified" ? "done" : "active";
    return "idle";
  });
}

function Pipeline({ stage, failed }: { stage: ProofStage | "verified" | null; failed: boolean }) {
  const states = stageStates(stage, failed);
  return (
    <ol className="pipeline">
      {PIPELINE.map((row, i) => (
        <li key={row.key} className={`stage stage-${states[i]}`}>
          <span className="dot" aria-hidden="true" />
          <span>
            <span className="stage-name">{row.name}</span>
            <br />
            <span className="stage-where">{row.where}</span>
          </span>
          <span className="stage-where">
            {states[i] === "done" ? "done" : states[i] === "active" ? "working" : states[i] === "fail" ? "failed" : ""}
          </span>
        </li>
      ))}
    </ol>
  );
}

/* ------------------------------------------------------------ secret field */

function SecretField({
  id,
  value,
  onChange,
  visible,
  onToggle,
  inputRef,
  placeholder,
  autoComplete,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  visible: boolean;
  onToggle: () => void;
  inputRef: React.RefObject<HTMLInputElement | null>;
  placeholder: string;
  autoComplete: string;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>Secret</label>
      <div className="input-row">
        <input
          id={id}
          ref={inputRef}
          type={visible ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          placeholder={placeholder}
        />
        <button
          type="button"
          className="reveal"
          onClick={onToggle}
          aria-pressed={visible}
          aria-label={visible ? "Hide secret" : "Show secret"}
        >
          {visible ? "Hide" : "Show"}
        </button>
      </div>
      <p className="field-note">Used on this device only. It is never sent.</p>
    </div>
  );
}

/* ------------------------------------------------------------------- page */

export default function ZeroProofDemo() {
  const [tab, setTab] = useState<Tab>("register");

  // The secret is component state only. It is never persisted anywhere.
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [secretVisible, setSecretVisible] = useState(false);

  // Read as a fallback on submit. React state is the source of truth, but if
  // anything writes to the input without firing onChange — autofill, a password
  // manager, a bundle that failed to hydrate — the state goes stale while the
  // field looks filled. Reading the element directly means the user always gets
  // a real attempt or a real error, never a dead button.
  const regUserRef = useRef<HTMLInputElement>(null);
  const regSecretRef = useRef<HTMLInputElement>(null);
  const proveUserRef = useRef<HTMLInputElement>(null);
  const proveSecretRef = useRef<HTMLInputElement>(null);

  const [registering, setRegistering] = useState(false);
  const [registered, setRegistered] = useState<RegisterBody | null>(null);
  const [registerError, setRegisterError] = useState<string | null>(null);

  const [proving, setProving] = useState(false);
  const [stage, setStage] = useState<ProofStage | "verified" | null>(null);
  const [proof, setProof] = useState<{ sent: VerifyBody; result: VerifyResponse } | null>(null);
  const [proveError, setProveError] = useState<string | null>(null);

  const [log, setLog] = useState<LogEntry[]>([]);
  const [loadingLog, setLoadingLog] = useState(false);
  const [logError, setLogError] = useState<string | null>(null);

  const readInputs = (
    userRef: React.RefObject<HTMLInputElement | null>,
    secretRef: React.RefObject<HTMLInputElement | null>,
  ) =>
    validateCredentials(
      username || userRef.current?.value || "",
      secret || secretRef.current?.value || "",
    );

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
      // Salt, x and y are all computed here; only y and salt are sent.
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
    setStage(null);
    try {
      const { sent, result } = await proveKnowledge(input.username, input.secret, setStage);
      // The proof did reach the server either way; it is the final check that failed.
      setStage("verified");
      setProof({ sent, result });
    } catch (error) {
      setProveError(messageFor(error));
    } finally {
      setProving(false);
    }
  }

  const statusWord = proving
    ? stage === "challenge"
      ? "Requesting challenge"
      : stage === "verifying"
        ? "Verifying"
        : "Generating proof"
    : proof
      ? proof.result.verified
        ? "Verified"
        : "Verification failed"
      : "Ready";

  return (
    <>
      <div className="app-head">
        <div className="tabs" role="tablist" aria-label="ZeroProof sections">
          {TABS.map((t) => (
            <button key={t.id} role="tab" aria-selected={tab === t.id} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* ------------------------------------------------------- register */}
      {tab === "register" && (
        <div className="work">
          <div className="card card-lift">
            <div className="centred-action">
              <span className="label label-accent">Step one</span>
              <h2 style={{ marginTop: "0.9rem" }}>Create a commitment</h2>
              <p className="muted" style={{ fontSize: "var(--t-small)", marginBottom: "2rem" }}>
                Your browser derives a public commitment from your secret and sends only that.
                The secret itself stays here.
              </p>

              <form onSubmit={onRegister} noValidate>
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
                <SecretField
                  id="reg-secret"
                  value={secret}
                  onChange={setSecret}
                  visible={secretVisible}
                  onToggle={() => setSecretVisible((v) => !v)}
                  inputRef={regSecretRef}
                  autoComplete="new-password"
                  placeholder="a long, high-entropy passphrase"
                />
                <button className="btn btn-accent btn-lg btn-block" type="submit" disabled={registering}>
                  {registering ? "Creating commitment…" : "Register"}
                </button>
              </form>

              {registerError && (
                <div className="banner banner-bad" role="alert">
                  <Cross className="banner-icon" />
                  <div>
                    <h3>Registration failed</h3>
                    <p>{registerError}</p>
                  </div>
                </div>
              )}

              {registered && (
                <div className="banner banner-ok">
                  <Tick className="banner-icon" />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <h3>Registered</h3>
                    <p>This is the entire request that was sent. There is no secret in it.</p>
                    <pre className="payload" style={{ marginTop: "0.85rem" }}>
{JSON.stringify(
  { username: registered.username, scheme: registered.scheme,
    salt: abbreviate(registered.salt), y: abbreviate(registered.y) },
  null,
  2,
)}
                    </pre>
                    <button className="btn btn-ghost" style={{ marginTop: "1rem" }} onClick={() => setTab("prove")}>
                      Now prove it <ArrowRight className="tick" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
          <Assurances />
        </div>
      )}

      {/* ---------------------------------------------------------- prove */}
      {tab === "prove" && (
        <div className="work">
          <div className="card card-lift">
            <div className="centred-action">
              <span className={`label ${proof && !proof.result.verified ? "label-fail" : "label-accent"}`}>
                {statusWord}
              </span>
              <h2 style={{ marginTop: "0.9rem" }}>Prove your secret</h2>
              <p className="muted" style={{ fontSize: "var(--t-small)", marginBottom: "2rem" }}>
                Your secret never leaves this device. Type the wrong one to watch the server
                turn it down.
              </p>

              <form onSubmit={onProve} noValidate>
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
                <SecretField
                  id="prove-secret"
                  value={secret}
                  onChange={setSecret}
                  visible={secretVisible}
                  onToggle={() => setSecretVisible((v) => !v)}
                  inputRef={proveSecretRef}
                  autoComplete="off"
                  placeholder="your secret"
                />
                <button className="btn btn-accent btn-lg btn-block" type="submit" disabled={proving}>
                  {proving ? "Generating proof…" : "Generate proof"}
                </button>
              </form>

              {(proving || proof) && (
                <div style={{ marginTop: "1.75rem" }}>
                  <span className="label">Progress</span>
                  <div style={{ marginTop: "0.6rem" }}>
                    <Pipeline stage={stage} failed={Boolean(proof && !proof.result.verified)} />
                  </div>
                </div>
              )}

              {proveError && (
                <div className="banner banner-bad" role="alert">
                  <Cross className="banner-icon" />
                  <div>
                    <h3>Could not complete</h3>
                    <p>{proveError}</p>
                  </div>
                </div>
              )}

              {proof && (
                <div className={`banner ${proof.result.verified ? "banner-ok" : "banner-bad"}`} role="status">
                  {proof.result.verified ? <Tick className="banner-icon" /> : <Cross className="banner-icon" />}
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <h3>{proof.result.verified ? "Verified" : "Not verified"}</h3>
                    <p>
                      {proof.result.verified
                        ? "Knowledge successfully proven without revealing the secret."
                        : REASON_TEXT[proof.result.reason] ?? proof.result.reason}
                    </p>
                    <pre className="payload" style={{ marginTop: "0.85rem" }}>
{JSON.stringify(
  { username: proof.sent.username, nonce: abbreviate(proof.sent.nonce),
    t: abbreviate(proof.sent.t), s: abbreviate(proof.sent.s) },
  null,
  2,
)}
                    </pre>
                    <button className="btn btn-ghost" style={{ marginTop: "1rem" }} onClick={() => setTab("audit")}>
                      {proof.result.verified ? "See the audit log" : "Try again, then see the log"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
          <Assurances />
        </div>
      )}

      {/* ---------------------------------------------------------- audit */}
      {tab === "audit" && (
        <div className="card card-lift">
          <div style={{ display: "flex", flexWrap: "wrap", gap: "1rem", justifyContent: "space-between", alignItems: "baseline" }}>
            <div>
              <span className="label">Server record</span>
              <h2 style={{ fontSize: "var(--t-h2)", marginTop: "0.6rem" }}>Audit log</h2>
              <p className="muted" style={{ fontSize: "var(--t-small)", marginTop: "0.4rem" }}>
                The last twenty verification attempts. Outcomes only — no secrets, no proofs.
              </p>
            </div>
            <button className="btn btn-ghost" onClick={loadLog} disabled={loadingLog}>
              {loadingLog ? "Refreshing…" : "Refresh"}
            </button>
          </div>

          {logError && (
            <div className="banner banner-bad" role="alert">
              <Cross className="banner-icon" />
              <div><h3>Could not load the log</h3><p>{logError}</p></div>
            </div>
          )}

          {!logError && log.length === 0 && !loadingLog && (
            <div className="empty">
              <Ledger />
              <p>No verification attempts yet. Prove a secret and it will appear here.</p>
            </div>
          )}

          {log.length > 0 && (
            <div className="table-wrap" style={{ marginTop: "1.75rem" }}>
              <table>
                <thead>
                  <tr><th>User</th><th>Result</th><th>Reason</th><th>Scheme</th><th>Time</th></tr>
                </thead>
                <tbody>
                  {log.map((entry) => (
                    <tr key={entry.id}>
                      <td>{entry.username}</td>
                      <td>
                        <span className={`verdict ${entry.verified ? "verdict-ok" : "verdict-bad"}`}>
                          {entry.verified ? "Verified" : "Rejected"}
                        </span>
                      </td>
                      <td className="muted">{entry.reason ?? "—"}</td>
                      <td className="mono muted">{entry.scheme}</td>
                      <td className="muted">{new Date(entry.at).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </>
  );
}

/* --------------------------------------------------------- side assurances */

function Assurances() {
  return (
    <aside className="aside">
      <div className="aside-card">
        <h3>What happens on this device</h3>
        <ul className="assurances">
          <li><Tick />Secret remains local</li>
          <li><Tick />Proof generated in browser</li>
          <li><Tick />Server verifies proof only</li>
        </ul>
      </div>
      <div className="aside-card">
        <h3>What crosses the network</h3>
        <ul className="assurances">
          <li><Device className="tick" />On register — a salt and a public commitment</li>
          <li><Server className="tick" />On prove — a single-use proof transcript</li>
          <li><Lock className="tick" />Never — the secret, in any form</li>
        </ul>
        <p className="field-note" style={{ marginTop: "1rem" }}>
          Open DevTools → Network and run the flow. Scheme <code>{SCHEME}</code>.
        </p>
      </div>
    </aside>
  );
}
