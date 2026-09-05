/**
 * SHA-256 over Web Crypto. Browser and Node run the identical code path —
 * no `node:crypto` here.
 */

import { bytesToBigInt, webcrypto } from "./bigint.ts";

/**
 * SHA-256 of the ordered concatenation of `parts` (UTF-8), as a big-endian
 * BigInt.
 *
 * The concatenation is exact: no separators are inserted. Callers that hash
 * more than one variable-length value are responsible for framing their parts
 * unambiguously — see `encodeField` in `schnorr.ts`.
 */
export async function sha256ToBigInt(...parts: string[]): Promise<bigint> {
  const bytes = new TextEncoder().encode(parts.join(""));
  const digest = await webcrypto.subtle.digest("SHA-256", bytes);
  return bytesToBigInt(new Uint8Array(digest));
}
