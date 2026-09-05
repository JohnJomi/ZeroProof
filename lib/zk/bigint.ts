/**
 * Dependency-free BigInt helpers: modular exponentiation, uniform random
 * sampling over Web Crypto, and hex conversion.
 *
 * Nothing here imports Next.js, the database, or any Node-only module, so the
 * same code runs in the browser (prover) and in Node (verifier).
 */

/** Web Crypto, resolved the same way in browsers and in the Node runtime. */
const webcrypto: Crypto = globalThis.crypto;
if (!webcrypto?.getRandomValues || !webcrypto?.subtle) {
  throw new Error("Web Crypto (crypto.getRandomValues / crypto.subtle) is unavailable");
}
export { webcrypto };

/**
 * `base ** exponent mod modulus` by square-and-multiply.
 * Requires a positive modulus and a non-negative exponent.
 */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new RangeError("modPow: modulus must be positive");
  if (exponent < 0n) throw new RangeError("modPow: exponent must be non-negative");
  if (modulus === 1n) return 0n;

  let result = 1n;
  // Normalise into [0, modulus) so negative bases behave.
  let b = ((base % modulus) + modulus) % modulus;
  let e = exponent;

  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/**
 * A uniformly random BigInt in `[0, bound)`.
 *
 * Rejection sampling, not modulo reduction: reducing a random 256-bit value mod
 * `bound` biases the low residues whenever `bound` is not a power of two.
 */
export function randomBigIntBelow(bound: bigint): bigint {
  if (bound <= 0n) throw new RangeError("randomBigIntBelow: bound must be positive");
  if (bound === 1n) return 0n;

  const bits = bound.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  // Bits above the bound's length are masked off, so each draw lands below
  // 2^bits — at most one rejection in two on average.
  const excessBits = BigInt(bytes * 8 - bits);
  const buf = new Uint8Array(bytes);

  for (;;) {
    webcrypto.getRandomValues(buf);
    const candidate = bytesToBigInt(buf) >> excessBits;
    if (candidate < bound) return candidate;
  }
}

/** A uniformly random BigInt in `[1, bound)`. Used for the blinding factor `k`. */
export function randomBigIntInRange(bound: bigint): bigint {
  if (bound <= 1n) throw new RangeError("randomBigIntInRange: bound must exceed 1");
  for (;;) {
    const candidate = randomBigIntBelow(bound);
    if (candidate !== 0n) return candidate;
  }
}

/** Big-endian bytes to BigInt. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** BigInt to lowercase hex, no `0x` prefix. Zero renders as `"0"`. */
export function bigIntToHex(value: bigint): string {
  if (value < 0n) throw new RangeError("bigIntToHex: value must be non-negative");
  return value.toString(16);
}

/** Hex (with or without a `0x` prefix) to BigInt. Rejects anything else. */
export function hexToBigInt(hex: string): bigint {
  const cleaned = hex.trim().replace(/^0x/i, "");
  if (cleaned.length === 0 || !/^[0-9a-fA-F]+$/.test(cleaned)) {
    throw new SyntaxError(`hexToBigInt: not a hex string: ${JSON.stringify(hex)}`);
  }
  return BigInt("0x" + cleaned);
}
