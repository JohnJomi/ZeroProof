/**
 * Single-use challenge lifecycle.
 *
 * A nonce binds a proof to one verification attempt: it is issued by the
 * server, lives for 60 seconds, and can be consumed exactly once. Consumption
 * is a single conditional UPDATE — a SELECT-then-UPDATE would leave a window in
 * which two concurrent replays both observe an unconsumed row.
 */

import { getStore, type Store, type Timestamp } from "./db.ts";

/** Challenge lifetime, per architecture.md §3.2. */
export const NONCE_TTL_MS = 60_000;

/** 128 bits, per architecture.md §3.2. */
const NONCE_BYTES = 16;

export interface IssuedChallenge {
  nonce: string;
  expiresAt: Timestamp;
}

export type ConsumeFailure =
  /** Unknown, already consumed, expired, or owned by another user. */
  | "nonce_invalid"
  /** Rejected before touching the database. */
  | "malformed_input";

export type ConsumeResult = { ok: true } | { ok: false; reason: ConsumeFailure };

/** A fresh 128-bit nonce as lowercase hex, from the platform CSPRNG. */
export function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Issue a challenge for `username`, expiring `NONCE_TTL_MS` from now.
 *
 * The caller is expected to have checked that the user exists; the foreign key
 * on `challenges.username` enforces it regardless.
 */
export function issue(
  username: string,
  store: Store = getStore(),
  now: Timestamp = Date.now(),
): IssuedChallenge {
  if (typeof username !== "string" || username.length === 0) {
    throw new TypeError("issue: username must be a non-empty string");
  }

  const nonce = generateNonce();
  const expiresAt = now + NONCE_TTL_MS;
  store.statements.insertChallenge.run({ nonce, username, expires_at: expiresAt });
  return { nonce, expiresAt };
}

/**
 * Atomically consume a challenge.
 *
 * The conditional UPDATE is the only database statement here. It checks all
 * four conditions at once — existence, ownership, not already consumed, not
 * expired — so exactly one of any number of concurrent callers can ever see
 * `changes === 1`.
 *
 * Every failure returns the same `nonce_invalid`. The four causes are
 * deliberately not distinguished: telling them apart would need a second
 * statement, and the single conditional UPDATE is the whole of the replay
 * guarantee. A uniform reason also leaks nothing about whether a nonce exists
 * or who owns it.
 */
export function consume(
  nonce: string,
  username: string,
  store: Store = getStore(),
  now: Timestamp = Date.now(),
): ConsumeResult {
  if (typeof nonce !== "string" || nonce.length === 0) {
    return { ok: false, reason: "malformed_input" };
  }
  if (typeof username !== "string" || username.length === 0) {
    return { ok: false, reason: "malformed_input" };
  }

  const { changes } = store.statements.consumeChallenge.run(nonce, username, now);
  return changes === 1 ? { ok: true } : { ok: false, reason: "nonce_invalid" };
}
