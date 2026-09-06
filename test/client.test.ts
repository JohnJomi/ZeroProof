/**
 * Phase 4 security tests: whatever the browser sends, it must not contain the
 * secret. These exercise the real request builders from `lib/client.ts` and the
 * real Phase 3 route handlers, with no browser automation.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { p, q } from "../lib/zk/params.ts";
import { modPow, hexToBigInt } from "../lib/zk/bigint.ts";
import { deriveSecret, publicKey, verify } from "../lib/zk/schnorr.ts";
import {
  randomSalt,
  buildRegisterBody,
  buildVerifyBody,
  SCHEME,
} from "../lib/client.ts";

const dir = mkdtempSync(join(tmpdir(), "zeroproof-client-"));
process.env.ZEROPROOF_DB = join(dir, "client.db");

const { POST: registerRoute } = await import("../app/api/register/route.ts");
const { GET: challengeRoute } = await import("../app/api/challenge/route.ts");
const { POST: verifyRoute } = await import("../app/api/verify/route.ts");

const SECRET = "a long high-entropy passphrase the server must never see";
const USERNAME = "alice";

// ------------------------------------------------------------- salt & bodies

test("randomSalt yields fresh 128-bit hex", () => {
  const salts = new Set(Array.from({ length: 200 }, randomSalt));
  assert.equal(salts.size, 200, "salts must not repeat");
  for (const salt of salts) assert.match(salt, /^[0-9a-f]{32}$/);
});

test("the registration body carries the commitment, never the secret", async () => {
  const salt = randomSalt();
  const body = await buildRegisterBody(USERNAME, SECRET, salt);

  assert.deepEqual(Object.keys(body).sort(), ["salt", "scheme", "username", "y"]);
  assert.equal(body.username, USERNAME);
  assert.equal(body.scheme, SCHEME);
  assert.equal(body.salt, salt);

  // y is exactly what the crypto core would produce, and is a subgroup member.
  const x = await deriveSecret(salt, SECRET);
  assert.equal(hexToBigInt(body.y), publicKey(x));
  assert.equal(modPow(hexToBigInt(body.y), q, p), 1n);

  // Nothing secret-derived is anywhere in the serialised body.
  const wire = JSON.stringify(body);
  assert.ok(!wire.includes(SECRET), "secret must not appear");
  assert.ok(!wire.includes(x.toString(16)), "x must not appear as hex");
  assert.ok(!wire.includes(x.toString(10)), "x must not appear as decimal");
});

test("the verification body carries the transcript, never the secret", async () => {
  const salt = randomSalt();
  const nonce = "a".repeat(32);
  const x = await deriveSecret(salt, SECRET);
  const y = publicKey(x);

  const body = await buildVerifyBody(USERNAME, SECRET, salt, nonce);
  assert.deepEqual(Object.keys(body).sort(), ["nonce", "s", "scheme", "t", "username"]);
  assert.equal(body.nonce, nonce);

  // The proof was genuinely generated locally: it verifies against y offline,
  // with no server involved.
  assert.deepEqual(await verify({ t: body.t, s: body.s }, y, nonce, USERNAME), { ok: true });

  const wire = JSON.stringify(body);
  assert.ok(!wire.includes(SECRET), "secret must not appear");
  assert.ok(!wire.includes(x.toString(16)), "x must not appear as hex");
  assert.ok(!wire.includes(x.toString(10)), "x must not appear as decimal");
});

test("k is fresh per proof — two proofs never repeat t or s", async () => {
  const salt = randomSalt();
  const nonce = "b".repeat(32);
  const first = await buildVerifyBody(USERNAME, SECRET, salt, nonce);
  const second = await buildVerifyBody(USERNAME, SECRET, salt, nonce);
  assert.notEqual(first.t, second.t);
  assert.notEqual(first.s, second.s);
});

test("a wrong secret produces a proof that does not verify", async () => {
  const salt = randomSalt();
  const nonce = "c".repeat(32);
  const y = publicKey(await deriveSecret(salt, SECRET));
  const body = await buildVerifyBody(USERNAME, "the wrong secret", salt, nonce);
  assert.equal((await verify({ t: body.t, s: body.s }, y, nonce, USERNAME)).ok, false);
});

// ------------------------------------------------- full flow through the API

test("the browser flow end to end leaks nothing across every request", async (t) => {
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  /** Every body the client would put on the wire. */
  const wire: string[] = [];
  const post = async (handler: (r: Request) => Promise<Response>, url: string, body: unknown) => {
    const serialised = JSON.stringify(body);
    wire.push(serialised);
    const response = await handler(
      new Request(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: serialised,
      }),
    );
    return { status: response.status, payload: (await response.json()) as Record<string, unknown> };
  };

  // 1. Register with a body built by the client module.
  const registerBody = await buildRegisterBody(USERNAME, SECRET);
  const registered = await post(registerRoute, "http://local/api/register", registerBody);
  assert.equal(registered.status, 201);

  // 2. Challenge.
  const challenge = await challengeRoute(
    new Request(`http://local/api/challenge?username=${USERNAME}`),
  );
  const issued = (await challenge.json()) as { nonce: string; salt: string };
  assert.equal(issued.salt, registerBody.salt);

  // 3. Prove locally and submit.
  const verifyBody = await buildVerifyBody(USERNAME, SECRET, issued.salt, issued.nonce);
  const verified = await post(verifyRoute, "http://local/api/verify", verifyBody);
  assert.equal(verified.status, 200);
  assert.equal(verified.payload.verified, true);
  assert.equal(verified.payload.reason, "ok");

  // 4. The whole point.
  const transcript = wire.join("\n");
  assert.ok(wire.length >= 2);
  assert.ok(!transcript.includes(SECRET), "the secret must not appear in any request body");
  for (const word of SECRET.split(" ")) {
    if (word.length >= 8) assert.ok(!transcript.includes(word), `leaked fragment: ${word}`);
  }
  const x = await deriveSecret(issued.salt, SECRET);
  assert.ok(!transcript.includes(x.toString(16)), "x must not appear");
  assert.ok(!transcript.includes(x.toString(10)), "x must not appear");

  // What did travel is exactly the public data.
  assert.ok(transcript.includes(registerBody.y));
  assert.ok(transcript.includes(verifyBody.t) && transcript.includes(verifyBody.s));
});

test("a wrong secret is rejected by the real API", async () => {
  const username = "bob";
  await registerRoute(
    new Request("http://local/api/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(await buildRegisterBody(username, SECRET)),
    }),
  );

  const challenge = await challengeRoute(
    new Request(`http://local/api/challenge?username=${username}`),
  );
  const issued = (await challenge.json()) as { nonce: string; salt: string };

  const body = await buildVerifyBody(username, "not the secret", issued.salt, issued.nonce);
  const response = await verifyRoute(
    new Request("http://local/api/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
  const payload = (await response.json()) as { verified: boolean; reason: string };
  assert.equal(payload.verified, false);
  assert.equal(payload.reason, "verification_failed");
});
