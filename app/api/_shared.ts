/**
 * Small helpers shared by the four route handlers.
 *
 * Deliberately not an error framework: four routes do not need one. Everything
 * here is either JSON shaping or input validation. All cryptography is
 * delegated to `lib/zk`; none of it is reimplemented.
 */

import { hexToBigInt } from "../../lib/zk/bigint.ts";
import { MAX_HEX_DIGITS, validatePublicKey } from "../../lib/zk/schnorr.ts";

/** Stable, machine-readable reasons. The UI and tests match on these. */
export type Reason =
  | "ok"
  | "malformed_request"
  | "missing_username"
  | "invalid_username"
  | "missing_field"
  | "invalid_public_key"
  | "unsupported_scheme"
  | "username_taken"
  | "unknown_user"
  | "nonce_invalid"
  | "verification_failed"
  | "internal_error";

export const MAX_USERNAME_LENGTH = 64;
export const MAX_SALT_LENGTH = 128;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** An error body carries only a stable reason — never an exception message. */
export function fail(reason: Reason, status: number): Response {
  return json({ reason }, status);
}

/** Parse a JSON object body, or undefined if it is malformed or not an object. */
export async function readJsonObject(
  request: Request,
): Promise<Record<string, unknown> | undefined> {
  try {
    const body: unknown = await request.json();
    if (typeof body !== "object" || body === null || Array.isArray(body)) return undefined;
    return body as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

export function isNonEmptyString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

/** Usernames are printable, single-line, and bounded. */
export function isValidUsername(value: unknown): value is string {
  return isNonEmptyString(value, MAX_USERNAME_LENGTH) && /^[\w.@-]+$/.test(value);
}

/** Bounded canonical hex, matching what the Phase 1 verifier accepts on the wire. */
export function isValidHex(value: unknown, maxDigits = MAX_HEX_DIGITS): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxDigits &&
    /^[0-9a-fA-F]+$/.test(value)
  );
}

/**
 * The Phase 1 public-key rules, applied at registration.
 *
 * The rules themselves live in `lib/zk/schnorr.ts` and are shared with
 * `verify()`; this only decodes the hex before handing the value over, so the
 * two paths cannot drift apart.
 */
export function isValidPublicKey(yHex: string): boolean {
  if (!isValidHex(yHex)) return false;
  try {
    return validatePublicKey(hexToBigInt(yHex)).ok;
  } catch {
    return false;
  }
}
