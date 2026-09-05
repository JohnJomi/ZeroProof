/**
 * Scheme registry. `/api/verify` will dispatch on a scheme id rather than
 * hard-coding Schnorr; adding a scheme is one file and one `registry.set`.
 *
 * No API wiring lives here — this is the lookup table only.
 */

import { hexToBigInt } from "./bigint.ts";
import { verify as schnorrVerify, type SchnorrProof } from "./schnorr.ts";

export interface VerificationContext {
  nonce: string;
  subject: string;
}

export interface ProofScheme<Pub, Proof> {
  /** e.g. "schnorr-dlog-v1" */
  id: string;
  verify(
    proof: Proof,
    pub: Pub,
    ctx: VerificationContext,
  ): Promise<{ ok: boolean; reason?: string }>;
}

/** The public commitment as it is stored and transported: `y` in hex. */
export interface SchnorrPublic {
  y: string;
}

export const SCHNORR_DLOG_V1 = "schnorr-dlog-v1";

export const schnorrScheme: ProofScheme<SchnorrPublic, SchnorrProof> = {
  id: SCHNORR_DLOG_V1,
  async verify(proof, pub, ctx) {
    let y: bigint;
    try {
      y = hexToBigInt(pub.y);
    } catch {
      return { ok: false, reason: "malformed_public_key" };
    }
    return schnorrVerify(proof, y, ctx.nonce, ctx.subject);
  },
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const registry = new Map<string, ProofScheme<any, any>>();
registry.set(schnorrScheme.id, schnorrScheme);
