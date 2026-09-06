/**
 * Phase 3 check from PLAN.md: a hand-rolled prover walks
 * register → challenge → verify and gets `verified: true`.
 *
 * The prover derives `x` and builds the proof locally with `lib/zk`, exactly as
 * the browser will. Every request body is recorded so the test can assert the
 * secret never crosses the wire.
 *
 * This runs the route handlers in process, so no dev server is required. To
 * exercise the same flow over HTTP once Next.js is installed:
 *     npx next dev     # then POST/GET against http://localhost:3000/api/*
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bigIntToHex } from "../lib/zk/bigint.ts";
import { deriveSecret, publicKey, prove } from "../lib/zk/schnorr.ts";
import { SCHNORR_DLOG_V1 } from "../lib/zk/scheme.ts";

const dir = mkdtempSync(join(tmpdir(), "zeroproof-e2e-"));
process.env.ZEROPROOF_DB = join(dir, "e2e.db");

const { POST: register } = await import("../app/api/register/route.ts");
const { GET: challenge } = await import("../app/api/challenge/route.ts");
const { POST: verifyRoute } = await import("../app/api/verify/route.ts");

const SECRET = "a long high-entropy passphrase the server must never see";
const SALT = "fedcba9876543210fedcba9876543210";
const USERNAME = "alice";

/** Every body that would travel over the network, captured for inspection. */
const wire: string[] = [];

async function send(
  handler: (r: Request) => Promise<Response>,
  url: string,
  body?: unknown,
): Promise<Record<string, unknown>> {
  const init: RequestInit =
    body === undefined
      ? { method: "GET" }
      : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  if (body !== undefined) wire.push(init.body as string);
  const response = await handler(new Request(url, init));
  return { status: response.status, ...(await response.json()) };
}

test("register → challenge → prove → verify yields verified: true", async (t) => {
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  // --- 1. Registration. x and y are computed locally; only y and salt are sent.
  const x = await deriveSecret(SALT, SECRET);
  const y = publicKey(x);

  const registered = await send(register, "http://local/api/register", {
    username: USERNAME,
    y: bigIntToHex(y),
    salt: SALT,
    scheme: SCHNORR_DLOG_V1,
  });
  assert.equal(registered.status, 201, "registration should succeed");

  // --- 2. Challenge. The server returns a fresh nonce and the stored salt.
  const issued = await send(challenge, `http://local/api/challenge?username=${USERNAME}`);
  assert.equal(issued.status, 200);
  const nonce = issued.nonce as string;
  assert.match(nonce, /^[0-9a-f]{32}$/);
  assert.equal(issued.salt, SALT);

  // --- 3. Prove locally. The secret never leaves this scope.
  const rederived = await deriveSecret(issued.salt as string, SECRET);
  assert.equal(rederived, x, "the salt must let the prover re-derive x");
  const proof = await prove(x, y, nonce, USERNAME);

  // --- 4. Verify.
  const verified = await send(verifyRoute, "http://local/api/verify", {
    username: USERNAME,
    nonce,
    t: proof.t,
    s: proof.s,
  });
  assert.equal(verified.status, 200);
  assert.equal(verified.verified, true, "the honest proof must verify");
  assert.equal(verified.reason, "ok");

  // --- 5. The whole point: nothing secret ever crossed the wire.
  assert.ok(wire.length >= 2, "request bodies were captured");
  const transcript = wire.join("\n");
  assert.ok(!transcript.includes(SECRET), "the secret must not appear in any request body");
  for (const word of SECRET.split(" ")) {
    if (word.length >= 8) assert.ok(!transcript.includes(word), `leaked fragment: ${word}`);
  }
  assert.ok(!transcript.includes(x.toString(16)), "x must not appear in any request body");
  assert.ok(!transcript.includes(x.toString(10)), "x must not appear in any request body");

  // What did go over the wire is exactly the public transcript.
  assert.ok(transcript.includes(proof.t) && transcript.includes(proof.s));
  assert.ok(transcript.includes(bigIntToHex(y)));
});
