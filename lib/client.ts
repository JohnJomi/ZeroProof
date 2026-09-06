/**
 * Browser-side flow for ZeroProof.
 *
 * This is the only place the secret is ever handled. It builds the request
 * bodies the page sends, and every one of them is derived from public values:
 * the secret is used locally to compute `x`, and `x` never leaves this module.
 *
 * All cryptography is delegated to `lib/zk`; nothing is reimplemented here.
 * This module must never import `lib/db` or anything else Node-only, because it
 * runs in the browser bundle.
 */

import { bigIntToHex } from "./zk/bigint.ts";
import { deriveSecret, publicKey, prove } from "./zk/schnorr.ts";
import { SCHNORR_DLOG_V1 } from "./zk/scheme.ts";

export const SCHEME = SCHNORR_DLOG_V1;

/** Salt length in bytes, per architecture.md §3.1. */
const SALT_BYTES = 16;

export interface RegisterBody {
  username: string;
  scheme: string;
  salt: string;
  y: string;
}

export interface VerifyBody {
  username: string;
  scheme: string;
  nonce: string;
  t: string;
  s: string;
}

export interface ChallengeResponse {
  nonce: string;
  salt: string;
  expiresAt: number;
}

export interface VerifyResponse {
  verified: boolean;
  reason: string;
}

export interface LogEntry {
  id: number;
  username: string;
  scheme: string;
  verified: boolean;
  reason: string | null;
  at: number;
}

/** Why the typed credentials were refused, before any request is built. */
export type CredentialProblem = "missing_username" | "missing_secret";

export type CredentialCheck =
  | { ok: true; username: string; secret: string }
  | { ok: false; problem: CredentialProblem };

/**
 * The only rule the UI enforces on input: both fields must be non-empty.
 *
 * The protocol imposes no minimum secret length — `deriveSecret` hashes
 * whatever it is given — so no length requirement is invented here. The
 * username is trimmed because surrounding space is always a typo; the secret is
 * never trimmed, because leading or trailing space is legitimately part of it.
 */
export function validateCredentials(username: string, secret: string): CredentialCheck {
  const trimmed = username.trim();
  if (trimmed === "") return { ok: false, problem: "missing_username" };
  if (secret === "") return { ok: false, problem: "missing_secret" };
  return { ok: true, username: trimmed, secret };
}

/** A fresh 128-bit salt from the browser CSPRNG. */
export function randomSalt(): string {
  const bytes = new Uint8Array(SALT_BYTES);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Build the registration body.
 *
 * `x` is computed here and discarded; only the commitment `y` and the salt go
 * into the body. There is no field in `RegisterBody` that could carry a secret.
 */
export async function buildRegisterBody(
  username: string,
  secret: string,
  salt: string = randomSalt(),
): Promise<RegisterBody> {
  const x = await deriveSecret(salt, secret);
  const y = publicKey(x);
  return { username, scheme: SCHEME, salt, y: bigIntToHex(y) };
}

/**
 * Build the verification body: re-derive `x` from the server's salt, produce a
 * fresh proof, and send only the transcript `(t, s)`.
 */
export async function buildVerifyBody(
  username: string,
  secret: string,
  salt: string,
  nonce: string,
): Promise<VerifyBody> {
  const x = await deriveSecret(salt, secret);
  const y = publicKey(x);
  const proof = await prove(x, y, nonce, username);
  return { username, scheme: SCHEME, nonce, t: proof.t, s: proof.s };
}

/** Thrown for a non-2xx API response; carries the server's stable reason. */
export class ApiError extends Error {
  readonly status: number;
  readonly reason: string;
  constructor(status: number, reason: string) {
    super(reason);
    this.name = "ApiError";
    this.status = status;
    this.reason = reason;
  }
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  try {
    return (await response.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

async function postJson(path: string, body: unknown): Promise<Record<string, unknown>> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await readJson(response);
  if (!response.ok) {
    throw new ApiError(response.status, String(payload.reason ?? "request_failed"));
  }
  return payload;
}

async function getJson(path: string): Promise<Record<string, unknown>> {
  const response = await fetch(path);
  const payload = await readJson(response);
  if (!response.ok) {
    throw new ApiError(response.status, String(payload.reason ?? "request_failed"));
  }
  return payload;
}

/** Register a commitment. Returns the body that was sent, for the UI to show. */
export async function register(username: string, secret: string): Promise<RegisterBody> {
  const body = await buildRegisterBody(username, secret);
  await postJson("/api/register", body);
  return body;
}

export async function requestChallenge(username: string): Promise<ChallengeResponse> {
  const payload = await getJson(`/api/challenge?username=${encodeURIComponent(username)}`);
  return {
    nonce: String(payload.nonce),
    salt: String(payload.salt),
    expiresAt: Number(payload.expiresAt),
  };
}

/**
 * The full prove step: fetch a challenge, build the proof locally, submit it.
 *
 * Returns the verdict alongside the body that went over the wire, so the UI can
 * show exactly what was transmitted.
 */
export async function proveKnowledge(
  username: string,
  secret: string,
): Promise<{ sent: VerifyBody; result: VerifyResponse; expiresAt: number }> {
  const challenge = await requestChallenge(username);
  const sent = await buildVerifyBody(username, secret, challenge.salt, challenge.nonce);
  const payload = await postJson("/api/verify", sent);
  return {
    sent,
    result: { verified: Boolean(payload.verified), reason: String(payload.reason) },
    expiresAt: challenge.expiresAt,
  };
}

export async function fetchLog(): Promise<LogEntry[]> {
  const payload = await getJson("/api/log");
  return (payload.entries ?? []) as LogEntry[];
}
