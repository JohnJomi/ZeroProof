/**
 * Schnorr proof of knowledge of a discrete logarithm, made non-interactive by
 * the Fiat–Shamir transform. See architecture.md §3.
 *
 * This module never sees, stores, or transmits the original secret beyond the
 * one-way derivation in `deriveSecret`.
 */

import { p, g, q } from "./params.ts";
import { modPow, randomBigIntInRange, bigIntToHex, hexToBigInt } from "./bigint.ts";
import { sha256ToBigInt } from "./hash.ts";

/** The wire form of a proof. Big integers travel as hex strings. */
export interface SchnorrProof {
  /** Commitment `t = g^k mod p`, hex. */
  t: string;
  /** Response `s = (k + c·x) mod q`, hex. */
  s: string;
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Length-prefixed framing so that two different tuples can never produce the
 * same byte sequence: `"<utf8 byte length>:<value>"`. Without it, hashing
 * ("ab","c") and ("a","bc") would collide.
 */
function encodeField(value: string): string {
  return `${new TextEncoder().encode(value).length}:${value}`;
}

/**
 * `x = SHA256(salt ‖ secret) mod q`.
 *
 * Concatenation is direct, as specified in architecture.md §3.1; `salt` is a
 * fixed-length hex string, which keeps the encoding unambiguous.
 */
export async function deriveSecret(salt: string, secret: string): Promise<bigint> {
  const h = await sha256ToBigInt(salt, secret);
  return h % q;
}

/** The public commitment `y = g^x mod p`. */
export function publicKey(x: bigint): bigint {
  return modPow(g, x, p);
}

/** Fiat–Shamir challenge `c = SHA256(p ‖ g ‖ y ‖ t ‖ nonce ‖ subject) mod q`. */
async function challenge(
  y: bigint,
  t: bigint,
  nonce: string,
  subject: string,
): Promise<bigint> {
  const h = await sha256ToBigInt(
    encodeField(bigIntToHex(p)),
    encodeField(bigIntToHex(g)),
    encodeField(bigIntToHex(y)),
    encodeField(bigIntToHex(t)),
    encodeField(nonce),
    encodeField(subject),
  );
  return h % q;
}

/**
 * Produce a proof that the prover knows `x` with `g^x = y`.
 *
 * `k` is sampled freshly for every call — reusing it across two proofs leaks
 * `x` outright.
 */
export async function prove(
  x: bigint,
  y: bigint,
  nonce: string,
  subject: string,
): Promise<SchnorrProof> {
  const k = randomBigIntInRange(q);
  const t = modPow(g, k, p);
  const c = await challenge(y, t, nonce, subject);
  const s = (k + c * (x % q)) % q;
  return { t: bigIntToHex(t), s: bigIntToHex(s) };
}

/**
 * Check `g^s ≡ t · y^c (mod p)`.
 *
 * Every range check happens before any exponentiation, so a malformed or
 * out-of-range proof costs nothing and returns a failure rather than throwing.
 */
export async function verify(
  proof: SchnorrProof,
  y: bigint,
  nonce: string,
  subject: string,
): Promise<VerifyResult> {
  if (!proof || typeof proof.t !== "string" || typeof proof.s !== "string") {
    return { ok: false, reason: "malformed_proof" };
  }

  let t: bigint;
  let s: bigint;
  try {
    t = hexToBigInt(proof.t);
    s = hexToBigInt(proof.s);
  } catch {
    return { ok: false, reason: "malformed_proof" };
  }

  // Range checks first — no exponentiation until these pass.
  if (t <= 1n || t >= p) return { ok: false, reason: "t_out_of_range" };
  if (s < 0n || s >= q) return { ok: false, reason: "s_out_of_range" };
  if (y <= 1n || y >= p) return { ok: false, reason: "y_out_of_range" };

  const c = await challenge(y, t, nonce, subject);
  const lhs = modPow(g, s, p);
  const rhs = (t * modPow(y, c, p)) % p;

  return lhs === rhs ? { ok: true } : { ok: false, reason: "verification_failed" };
}
