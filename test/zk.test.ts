import test from "node:test";
import assert from "node:assert/strict";

import { p, g, q, P_HEX } from "../lib/zk/params.ts";
import {
  modPow,
  randomBigIntBelow,
  randomBigIntInRange,
  bigIntToHex,
  hexToBigInt,
  bytesToBigInt,
} from "../lib/zk/bigint.ts";
import { sha256ToBigInt } from "../lib/zk/hash.ts";
import {
  deriveSecret,
  publicKey,
  prove,
  verify,
  validatePublicKey,
  MAX_HEX_DIGITS,
} from "../lib/zk/schnorr.ts";
import { registry, SCHNORR_DLOG_V1 } from "../lib/zk/scheme.ts";

const SALT = "0123456789abcdef0123456789abcdef";
const SUBJECT = "alice";
const NONCE_A = "nonce-aaaaaaaaaaaaaaaa";
const NONCE_B = "nonce-bbbbbbbbbbbbbbbb";

// ---------------------------------------------------------------- parameters

test("params: p is the 2048-bit RFC 3526 Group 14 prime", () => {
  assert.equal(P_HEX.length, 512);
  assert.equal(p.toString(2).length, 2048);
  assert.equal(g, 2n);
  assert.equal(q, (p - 1n) / 2n);
  assert.equal(q * 2n + 1n, p);
  // Safe prime: p ≡ 7 (mod 8), which makes g = 2 a quadratic residue and
  // therefore a generator of the order-q subgroup.
  assert.equal(p % 8n, 7n);
  assert.equal(modPow(g, q, p), 1n);
});

// -------------------------------------------------------------------- modPow

test("modPow: known values and edge cases", () => {
  assert.equal(modPow(2n, 10n, 1000n), 24n);
  assert.equal(modPow(3n, 0n, 7n), 1n);
  assert.equal(modPow(0n, 5n, 7n), 0n);
  assert.equal(modPow(5n, 3n, 1n), 0n);
  assert.equal(modPow(-2n, 3n, 7n), 6n); // -8 mod 7
  assert.throws(() => modPow(2n, 3n, 0n), RangeError);
  assert.throws(() => modPow(2n, -1n, 7n), RangeError);
});

test("modPow: matches naive exponentiation for small inputs", () => {
  const m = 97n;
  for (let base = 0n; base < 20n; base++) {
    let expected = 1n;
    for (let i = 0n; i < 15n; i++) {
      assert.equal(modPow(base, i, m), expected);
      expected = (expected * base) % m;
    }
  }
});

test("modPow: Fermat's little theorem in the real group", () => {
  assert.equal(modPow(g, p - 1n, p), 1n);
});

// ------------------------------------------------------------ hex conversion

test("hex: BigInt round-trips", () => {
  for (const v of [0n, 1n, 15n, 16n, 255n, 256n, q, p, p - 1n]) {
    assert.equal(hexToBigInt(bigIntToHex(v)), v);
  }
  assert.equal(bigIntToHex(0n), "0");
  assert.equal(bigIntToHex(255n), "ff");
  assert.equal(hexToBigInt("0xFF"), 255n);
  assert.equal(hexToBigInt("  ff  "), 255n);
  assert.equal(hexToBigInt(P_HEX), p);
});

test("hex: rejects non-hex input", () => {
  for (const bad of ["", "0x", "xyz", "12g4", "-1", "1.5"]) {
    assert.throws(() => hexToBigInt(bad), SyntaxError, `should reject ${JSON.stringify(bad)}`);
  }
  assert.throws(() => bigIntToHex(-1n), RangeError);
});

test("bytesToBigInt is big-endian", () => {
  assert.equal(bytesToBigInt(new Uint8Array([])), 0n);
  assert.equal(bytesToBigInt(new Uint8Array([0x01, 0x00])), 256n);
  assert.equal(bytesToBigInt(new Uint8Array([0xff, 0xff])), 65535n);
});

// ---------------------------------------------------------- random sampling

test("randomBigIntBelow: stays in range and covers it", () => {
  assert.equal(randomBigIntBelow(1n), 0n);
  assert.throws(() => randomBigIntBelow(0n), RangeError);
  assert.throws(() => randomBigIntBelow(-5n), RangeError);

  const seen = new Set<string>();
  for (let i = 0; i < 3000; i++) {
    const v = randomBigIntBelow(5n); // not a power of two — exercises rejection
    assert.ok(v >= 0n && v < 5n, `out of range: ${v}`);
    seen.add(v.toString());
  }
  assert.equal(seen.size, 5, "every residue below the bound should appear");

  for (let i = 0; i < 50; i++) {
    const v = randomBigIntBelow(q);
    assert.ok(v >= 0n && v < q);
  }
});

test("randomBigIntInRange: never returns zero", () => {
  assert.throws(() => randomBigIntInRange(1n), RangeError);
  assert.equal(randomBigIntInRange(2n), 1n);
  for (let i = 0; i < 1000; i++) {
    const v = randomBigIntInRange(4n);
    assert.ok(v >= 1n && v < 4n, `out of range: ${v}`);
  }
});

test("randomBigIntInRange: fresh values over the real order", () => {
  const a = randomBigIntInRange(q);
  const b = randomBigIntInRange(q);
  assert.notEqual(a, b);
  assert.ok(a > 0n && a < q && b > 0n && b < q);
});

// ---------------------------------------------------------------------- hash

test("sha256ToBigInt: known digest, ordered concatenation", async () => {
  // SHA-256("abc")
  const expected =
    0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015adn;
  assert.equal(await sha256ToBigInt("abc"), expected);
  assert.equal(await sha256ToBigInt("a", "b", "c"), expected);
  assert.notEqual(await sha256ToBigInt("cba"), expected);
  assert.ok((await sha256ToBigInt("")) >= 0n);
});

// ---------------------------------------------------- the five protocol cases

test("1. honest proof verifies", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  assert.ok(x >= 0n && x < q);
  assert.ok(y > 1n && y < p);

  const proof = await prove(x, y, NONCE_A, SUBJECT);
  assert.deepEqual(await verify(proof, y, NONCE_A, SUBJECT), { ok: true });
});

test("1b. proofs are fresh — two proofs differ in t and s", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const a = await prove(x, y, NONCE_A, SUBJECT);
  const b = await prove(x, y, NONCE_A, SUBJECT);
  assert.notEqual(a.t, b.t, "k must be resampled per proof");
  assert.notEqual(a.s, b.s);
  assert.equal((await verify(a, y, NONCE_A, SUBJECT)).ok, true);
  assert.equal((await verify(b, y, NONCE_A, SUBJECT)).ok, true);
});

test("2. wrong secret rejects", async () => {
  const y = publicKey(await deriveSecret(SALT, "correct horse battery staple"));
  const wrongX = await deriveSecret(SALT, "Tr0ub4dor&3");
  const proof = await prove(wrongX, y, NONCE_A, SUBJECT);
  const result = await verify(proof, y, NONCE_A, SUBJECT);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "verification_failed");
});

test("3. tampered s rejects", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const proof = await prove(x, y, NONCE_A, SUBJECT);

  // Flip one bit of s, keeping it inside [0, q).
  const tampered = { ...proof, s: bigIntToHex((hexToBigInt(proof.s) ^ 1n) % q) };
  assert.notEqual(tampered.s, proof.s);
  assert.equal((await verify(tampered, y, NONCE_A, SUBJECT)).reason, "verification_failed");

  // Tampering with t breaks it too.
  const tamperedT = { ...proof, t: bigIntToHex((hexToBigInt(proof.t) ^ 1n) % p) };
  assert.equal((await verify(tamperedT, y, NONCE_A, SUBJECT)).ok, false);
});

test("4. a proof minted for nonce A rejects under nonce B", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const proof = await prove(x, y, NONCE_A, SUBJECT);
  assert.equal((await verify(proof, y, NONCE_A, SUBJECT)).ok, true);
  assert.equal((await verify(proof, y, NONCE_B, SUBJECT)).reason, "verification_failed");
});

test("4b. the proof is bound to the subject too", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const proof = await prove(x, y, NONCE_A, SUBJECT);
  assert.equal((await verify(proof, y, NONCE_A, "mallory")).reason, "verification_failed");
});

test("5. out-of-range t rejects before any exponentiation", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const proof = await prove(x, y, NONCE_A, SUBJECT);

  // Values that fit the encoding bound but fail the mathematical range check.
  // (Anything wider than MAX_HEX_DIGITS is refused earlier — see test 5e.)
  for (const t of [0n, 1n, p, p + 1n]) {
    const result = await verify({ ...proof, t: bigIntToHex(t) }, y, NONCE_A, SUBJECT);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "t_out_of_range", `t = ${t} should be rejected by range check`);
  }

  // A t far larger than p is refused on its encoding, before any conversion or
  // exponentiation: p^3 needs more than MAX_HEX_DIGITS digits.
  const huge = await verify({ ...proof, t: bigIntToHex(p ** 3n) }, y, NONCE_A, SUBJECT);
  assert.equal(huge.reason, "malformed_proof");

  // A t that is in-encoding but still out of range is caught by the range check.
  const justOver = await verify({ ...proof, t: bigIntToHex(p + 1n) }, y, NONCE_A, SUBJECT);
  assert.equal(justOver.reason, "t_out_of_range");
});

test("5b. out-of-range s and y reject", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const proof = await prove(x, y, NONCE_A, SUBJECT);

  for (const s of [q, q + 1n, p]) {
    const result = await verify({ ...proof, s: bigIntToHex(s) }, y, NONCE_A, SUBJECT);
    assert.equal(result.reason, "s_out_of_range", `s = ${s} should be rejected`);
  }
  // s = 0 is in range: it must fail the equation, not the range check.
  assert.equal(
    (await verify({ ...proof, s: "0" }, y, NONCE_A, SUBJECT)).reason,
    "verification_failed",
  );

  for (const badY of [0n, 1n, p, p + 1n]) {
    assert.equal((await verify(proof, badY, NONCE_A, SUBJECT)).reason, "y_out_of_range");
  }
});

test("5c. malformed proofs return a failure instead of throwing", async () => {
  const y = publicKey(await deriveSecret(SALT, "correct horse battery staple"));
  const bad = [
    { t: "zz", s: "01" },
    { t: "01", s: "not-hex" },
    { t: "", s: "" },
    { t: 1 as unknown as string, s: "01" },
    null as unknown as { t: string; s: string },
  ];
  for (const proof of bad) {
    const result = await verify(proof, y, NONCE_A, SUBJECT);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "malformed_proof");
  }
});

test("5d. y = p - 1 is rejected as a subgroup violation", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const honestY = publicKey(x);
  const proof = await prove(x, honestY, NONCE_A, SUBJECT);

  // p - 1 passes 1 < y < p but has order 2, not q.
  const rogue = p - 1n;
  assert.ok(rogue > 1n && rogue < p, "p-1 clears the plain range check");
  assert.notEqual(modPow(rogue, q, p), 1n, "p-1 is genuinely outside the subgroup");

  const result = await verify(proof, rogue, NONCE_A, SUBJECT);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "y_not_in_subgroup");

  // Every small-order element is refused the same way.
  for (const badY of [p - 1n, modPow(g, q, p) * (p - 1n) % p]) {
    if (badY <= 1n || badY >= p) continue;
    assert.equal((await verify(proof, badY, NONCE_A, SUBJECT)).ok, false);
  }

  // An honest y is in the subgroup and still verifies.
  assert.equal(modPow(honestY, q, p), 1n);
  assert.equal((await verify(proof, honestY, NONCE_A, SUBJECT)).ok, true);
});

test("5e. oversized encodings are rejected before conversion", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const proof = await prove(x, y, NONCE_A, SUBJECT);

  assert.equal(MAX_HEX_DIGITS, 512, "p is 2048 bits, so 512 hex digits is the ceiling");

  const tooLong = "f".repeat(MAX_HEX_DIGITS + 1);
  const enormous = "f".repeat(100_000);
  for (const bad of [tooLong, enormous]) {
    assert.equal((await verify({ ...proof, t: bad }, y, NONCE_A, SUBJECT)).reason, "malformed_proof");
    assert.equal((await verify({ ...proof, s: bad }, y, NONCE_A, SUBJECT)).reason, "malformed_proof");
  }

  // Exactly at the limit is an encoding the validator accepts; it is then
  // rejected on its value, proving the bound is not off by one.
  const atLimit = "f".repeat(MAX_HEX_DIGITS);
  assert.equal(atLimit.length, MAX_HEX_DIGITS);
  assert.equal((await verify({ ...proof, t: atLimit }, y, NONCE_A, SUBJECT)).reason, "t_out_of_range");
});

test("5f. malformed hex is rejected without throwing", async () => {
  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const proof = await prove(x, y, NONCE_A, SUBJECT);

  // Note "0x…" and whitespace are accepted by hexToBigInt but are not canonical
  // on the wire, so verify() refuses them.
  const malformed = ["", " ", "0x1f", " 1f ", "1f ", "zz", "12g4", "-1", "1.5", "١٢٣", "1f\n"];
  for (const bad of malformed) {
    const viaT = await verify({ ...proof, t: bad }, y, NONCE_A, SUBJECT);
    const viaS = await verify({ ...proof, s: bad }, y, NONCE_A, SUBJECT);
    assert.equal(viaT.reason, "malformed_proof", `t = ${JSON.stringify(bad)}`);
    assert.equal(viaS.reason, "malformed_proof", `s = ${JSON.stringify(bad)}`);
  }
});

test("validatePublicKey enforces range then subgroup membership", async () => {
  const honestY = publicKey(await deriveSecret(SALT, "correct horse battery staple"));
  assert.deepEqual(validatePublicKey(honestY), { ok: true });
  assert.deepEqual(validatePublicKey(modPow(g, 12345n, p)), { ok: true });

  for (const y of [0n, 1n, -1n, p, p + 1n]) {
    assert.deepEqual(validatePublicKey(y), { ok: false, reason: "y_out_of_range" }, `y = ${y}`);
  }

  // In range, wrong order: p - 1 has order 2.
  assert.deepEqual(validatePublicKey(p - 1n), { ok: false, reason: "y_not_in_subgroup" });

  // verify() reports exactly what the validator says, so the two cannot drift.
  const proof = await prove(await deriveSecret(SALT, "s"), honestY, NONCE_A, SUBJECT);
  for (const y of [p - 1n, p + 1n, 1n]) {
    const fromVerify = await verify(proof, y, NONCE_A, SUBJECT);
    const fromValidator = validatePublicKey(y);
    assert.equal(fromVerify.ok, false);
    assert.equal(fromVerify.reason, fromValidator.ok === false ? fromValidator.reason : undefined);
  }
});

// ------------------------------------------------------------------ registry

test("registry dispatches schnorr-dlog-v1", async () => {
  const scheme = registry.get(SCHNORR_DLOG_V1);
  assert.ok(scheme, "schnorr-dlog-v1 must be registered");
  assert.equal(scheme.id, SCHNORR_DLOG_V1);

  const x = await deriveSecret(SALT, "correct horse battery staple");
  const y = publicKey(x);
  const proof = await prove(x, y, NONCE_A, SUBJECT);
  const ctx = { nonce: NONCE_A, subject: SUBJECT };

  assert.deepEqual(await scheme.verify(proof, { y: bigIntToHex(y) }, ctx), { ok: true });
  assert.equal(
    (await scheme.verify(proof, { y: bigIntToHex(y) }, { ...ctx, nonce: NONCE_B })).ok,
    false,
  );
  assert.equal(
    (await scheme.verify(proof, { y: "nope" }, ctx)).reason,
    "malformed_public_key",
  );
});

test("deriveSecret is deterministic, salted, and reduced mod q", async () => {
  const a = await deriveSecret(SALT, "s3cret");
  assert.equal(a, await deriveSecret(SALT, "s3cret"));
  assert.notEqual(a, await deriveSecret(SALT, "s3cret!"));
  assert.notEqual(a, await deriveSecret("ffffffffffffffffffffffffffffffff", "s3cret"));
  assert.ok(a >= 0n && a < q);
});
