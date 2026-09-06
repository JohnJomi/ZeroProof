import test, { after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { p, q, g } from "../lib/zk/params.ts";
import { modPow, bigIntToHex } from "../lib/zk/bigint.ts";
import { deriveSecret, publicKey, prove } from "../lib/zk/schnorr.ts";
import { SCHNORR_DLOG_V1 } from "../lib/zk/scheme.ts";

// The store is a module-level singleton keyed off ZEROPROOF_DB, so the path
// must be set before lib/db.ts is evaluated. Hence the dynamic imports below.
const dir = mkdtempSync(join(tmpdir(), "zeroproof-api-"));
process.env.ZEROPROOF_DB = join(dir, "api-test.db");
after(() => rmSync(dir, { recursive: true, force: true }));

const { POST: register } = await import("../app/api/register/route.ts");
const { GET: challenge } = await import("../app/api/challenge/route.ts");
const { POST: verifyRoute } = await import("../app/api/verify/route.ts");
const { GET: log } = await import("../app/api/log/route.ts");
const { getStore } = await import("../lib/db.ts");

const SALT = "0123456789abcdef0123456789abcdef";
const SECRET = "correct horse battery staple";

let counter = 0;
/** A distinct username per test — one database is shared across the file. */
const uniqueUser = (label: string) => `${label}-${counter++}`;

function post(handler: (r: Request) => Promise<Response>, url: string, body: unknown) {
  return handler(
    new Request(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}

const get = (handler: (r: Request) => Promise<Response>, url: string) =>
  handler(new Request(url, { method: "GET" }));

async function body(response: Response): Promise<Record<string, never>> {
  return (await response.json()) as Record<string, never>;
}

/** Register a user and return everything the prover needs. */
async function enrol(username: string, secret = SECRET) {
  const x = await deriveSecret(SALT, secret);
  const y = publicKey(x);
  const response = await post(register, "http://t/api/register", {
    username,
    y: bigIntToHex(y),
    salt: SALT,
    scheme: SCHNORR_DLOG_V1,
  });
  assert.equal(response.status, 201);
  return { x, y, username };
}

// ------------------------------------------------------------------ runtime

test("every route declares the Node runtime, never edge", async () => {
  const modules = await Promise.all([
    import("../app/api/register/route.ts"),
    import("../app/api/challenge/route.ts"),
    import("../app/api/verify/route.ts"),
    import("../app/api/log/route.ts"),
  ]);
  for (const mod of modules) {
    assert.equal((mod as { runtime: string }).runtime, "nodejs");
  }
});

// ------------------------------------------------------------- registration

test("valid registration returns 201 and stores only public values", async () => {
  const username = uniqueUser("alice");
  const x = await deriveSecret(SALT, SECRET);
  const y = bigIntToHex(publicKey(x));

  const response = await post(register, "http://t/api/register", {
    username,
    y,
    salt: SALT,
    scheme: SCHNORR_DLOG_V1,
  });
  assert.equal(response.status, 201);
  assert.equal((await body(response)).username, username);

  const row = getStore().getUser(username);
  assert.ok(row);
  assert.equal(row.y, y);
  assert.equal(row.salt, SALT);
  assert.equal(row.scheme, SCHNORR_DLOG_V1);
});

test("duplicate username returns 409", async () => {
  const username = uniqueUser("dup");
  await enrol(username);
  const again = await post(register, "http://t/api/register", {
    username,
    y: bigIntToHex(publicKey(await deriveSecret(SALT, "other"))),
    salt: SALT,
    scheme: SCHNORR_DLOG_V1,
  });
  assert.equal(again.status, 409);
  assert.equal((await body(again)).reason, "username_taken");
});

test("a secret in the body is never accepted or stored", async () => {
  const username = uniqueUser("leaky");
  const x = await deriveSecret(SALT, SECRET);
  await post(register, "http://t/api/register", {
    username,
    y: bigIntToHex(publicKey(x)),
    salt: SALT,
    scheme: SCHNORR_DLOG_V1,
    secret: SECRET,
    x: x.toString(16),
  });

  // Nothing anywhere in the row resembles the secret or the private exponent.
  const row = getStore().getUser(username)!;
  const serialised = JSON.stringify(row);
  assert.ok(!serialised.includes(SECRET), "secret must not be stored");
  assert.ok(!serialised.includes(x.toString(16)), "x must not be stored");
  assert.deepEqual(Object.keys(row).sort(), ["created_at", "salt", "scheme", "username", "y"]);
});

test("out-of-range and non-subgroup public keys are rejected", async () => {
  const cases: Record<string, string> = {
    zero: "0",
    one: "1",
    p: bigIntToHex(p),
    "p-1 (order 2, not in subgroup)": bigIntToHex(p - 1n),
    "not hex": "zzzz",
    empty: "",
  };
  for (const [label, y] of Object.entries(cases)) {
    const response = await post(register, "http://t/api/register", {
      username: uniqueUser("bad"),
      y,
      salt: SALT,
      scheme: SCHNORR_DLOG_V1,
    });
    assert.equal(response.status, 400, `${label} should be refused`);
    assert.equal((await body(response)).reason, "invalid_public_key", label);
  }

  // Sanity: p - 1 really does pass the range check and fail only the subgroup test.
  assert.ok(p - 1n > 1n && p - 1n < p);
  assert.notEqual(modPow(p - 1n, q, p), 1n);
  assert.equal(modPow(publicKey(await deriveSecret(SALT, SECRET)), q, p), 1n);
});

test("unsupported scheme and malformed bodies are rejected", async () => {
  const y = bigIntToHex(publicKey(await deriveSecret(SALT, SECRET)));
  const base = { username: uniqueUser("scheme"), y, salt: SALT };

  const unsupported = await post(register, "http://t/api/register", {
    ...base,
    scheme: "groth16-v9",
  });
  assert.equal(unsupported.status, 400);
  assert.equal((await body(unsupported)).reason, "unsupported_scheme");

  const missingScheme = await post(register, "http://t/api/register", base);
  assert.equal(missingScheme.status, 400);

  for (const bad of [{ ...base, scheme: SCHNORR_DLOG_V1, username: "" }, { y, salt: SALT }]) {
    assert.equal((await post(register, "http://t/api/register", bad)).status, 400);
  }

  const notJson = await register(
    new Request("http://t/api/register", { method: "POST", body: "{oops" }),
  );
  assert.equal(notJson.status, 400);
  assert.equal((await body(notJson)).reason, "malformed_request");
});

// ---------------------------------------------------------------- challenge

test("unknown user gets 404", async () => {
  const response = await get(challenge, "http://t/api/challenge?username=ghost");
  assert.equal(response.status, 404);
  assert.equal((await body(response)).reason, "unknown_user");
});

test("known user gets a persisted nonce, salt and expiry", async () => {
  const username = uniqueUser("carol");
  await enrol(username);

  const before = Date.now();
  const response = await get(challenge, `http://t/api/challenge?username=${username}`);
  assert.equal(response.status, 200);
  const payload = await body(response);

  assert.match(payload.nonce as unknown as string, /^[0-9a-f]{32}$/);
  assert.equal(payload.salt as unknown as string, SALT);
  const expiresAt = payload.expiresAt as unknown as number;
  assert.ok(expiresAt >= before + 60_000 && expiresAt <= Date.now() + 60_000);

  // It is really in the database, unconsumed.
  const row = getStore().getChallenge(payload.nonce as unknown as string);
  assert.ok(row, "challenge must be persisted");
  assert.equal(row.username, username);
  assert.equal(row.consumed, 0);

  // No commitment or secret material comes back.
  assert.deepEqual(Object.keys(payload).sort(), ["expiresAt", "nonce", "salt"]);
});

test("a missing or malformed username is a 400", async () => {
  assert.equal((await get(challenge, "http://t/api/challenge")).status, 400);
  assert.equal((await get(challenge, "http://t/api/challenge?username=")).status, 400);
});

// ------------------------------------------------------------- verification

/** Walk challenge → prove → verify, returning the verify response body. */
async function proveAndVerify(
  username: string,
  x: bigint,
  y: bigint,
  opts: { tamper?: boolean; nonceOverride?: string } = {},
) {
  const challengeBody = await body(
    await get(challenge, `http://t/api/challenge?username=${username}`),
  );
  const nonce = opts.nonceOverride ?? (challengeBody.nonce as unknown as string);
  const proof = await prove(x, y, nonce, username);
  const s = opts.tamper ? bigIntToHex((BigInt("0x" + proof.s) ^ 1n) % q) : proof.s;
  const response = await post(verifyRoute, "http://t/api/verify", {
    username,
    nonce,
    t: proof.t,
    s,
  });
  return { response, payload: await body(response), nonce };
}

test("a valid proof verifies", async () => {
  const username = uniqueUser("valid");
  const { x, y } = await enrol(username);
  const { response, payload } = await proveAndVerify(username, x, y);
  assert.equal(response.status, 200);
  assert.equal(payload.verified as unknown as boolean, true);
  assert.equal(payload.reason as unknown as string, "ok");
});

test("a proof from the wrong secret is rejected", async () => {
  const username = uniqueUser("wrong");
  const { y } = await enrol(username);
  const wrongX = await deriveSecret(SALT, "Tr0ub4dor&3");
  const { response, payload } = await proveAndVerify(username, wrongX, y);
  assert.equal(response.status, 200, "a rejected proof is still a completed request");
  assert.equal(payload.verified as unknown as boolean, false);
  assert.equal(payload.reason as unknown as string, "verification_failed");
});

test("a tampered proof is rejected", async () => {
  const username = uniqueUser("tamper");
  const { x, y } = await enrol(username);
  const { payload } = await proveAndVerify(username, x, y, { tamper: true });
  assert.equal(payload.verified as unknown as boolean, false);
});

test("a proof minted for another nonce is rejected", async () => {
  const username = uniqueUser("nonce");
  const { x, y } = await enrol(username);

  // Two challenges: prove against the first, submit under the second.
  const first = await body(await get(challenge, `http://t/api/challenge?username=${username}`));
  const second = await body(await get(challenge, `http://t/api/challenge?username=${username}`));
  const proof = await prove(x, y, first.nonce as unknown as string, username);

  const response = await post(verifyRoute, "http://t/api/verify", {
    username,
    nonce: second.nonce as unknown as string,
    t: proof.t,
    s: proof.s,
  });
  const payload = await body(response);
  assert.equal(payload.verified as unknown as boolean, false);
  assert.equal(payload.reason as unknown as string, "verification_failed");
});

test("replaying a consumed nonce is rejected", async () => {
  const username = uniqueUser("replay");
  const { x, y } = await enrol(username);

  const challengeBody = await body(
    await get(challenge, `http://t/api/challenge?username=${username}`),
  );
  const nonce = challengeBody.nonce as unknown as string;
  const proof = await prove(x, y, nonce, username);
  const payload = { username, nonce, t: proof.t, s: proof.s };

  const first = await body(await post(verifyRoute, "http://t/api/verify", payload));
  assert.equal(first.verified as unknown as boolean, true);

  // The identical, still-valid proof is refused the second time.
  const replay = await body(await post(verifyRoute, "http://t/api/verify", payload));
  assert.equal(replay.verified as unknown as boolean, false);
  assert.equal(replay.reason as unknown as string, "nonce_invalid");
});

test("a failed proof still consumes the nonce", async () => {
  const username = uniqueUser("burn");
  const { x, y } = await enrol(username);
  const wrongX = await deriveSecret(SALT, "not the secret");

  const challengeBody = await body(
    await get(challenge, `http://t/api/challenge?username=${username}`),
  );
  const nonce = challengeBody.nonce as unknown as string;

  const bad = await prove(wrongX, y, nonce, username);
  const rejected = await body(
    await post(verifyRoute, "http://t/api/verify", { username, nonce, t: bad.t, s: bad.s }),
  );
  assert.equal(rejected.verified as unknown as boolean, false);
  assert.equal(getStore().getChallenge(nonce)?.consumed, 1, "nonce must be burnt");

  // A correct proof on that same nonce now fails: no second attempt.
  const good = await prove(x, y, nonce, username);
  const retry = await body(
    await post(verifyRoute, "http://t/api/verify", { username, nonce, t: good.t, s: good.s }),
  );
  assert.equal(retry.verified as unknown as boolean, false);
  assert.equal(retry.reason as unknown as string, "nonce_invalid");
});

test("verify rejects malformed shapes without touching the database", async () => {
  const username = uniqueUser("shape");
  await enrol(username);
  const bad = [
    { username, nonce: "zz", t: "01", s: "01" },
    { username, nonce: "a".repeat(32), t: 1, s: "01" },
    { username: "", nonce: "a".repeat(32), t: "01", s: "01" },
    { nonce: "a".repeat(32), t: "01", s: "01" },
  ];
  for (const payload of bad) {
    const response = await post(verifyRoute, "http://t/api/verify", payload);
    assert.equal(response.status, 400, JSON.stringify(payload));
  }
});

// -------------------------------------------------------------------- audit

test("the log records verification results, newest first, capped at 20", async () => {
  const username = uniqueUser("audit");
  const { x, y } = await enrol(username);

  await proveAndVerify(username, x, y);                       // pass
  await proveAndVerify(username, x, y, { tamper: true });     // fail

  const entries = (await body(await get(log, "http://t/api/log")))
    .entries as unknown as { username: string; verified: boolean; reason: string; at: number }[];

  const mine = entries.filter((e) => e.username === username);
  assert.equal(mine.length, 2);
  assert.equal(mine[0]!.verified, false, "newest first");
  assert.equal(mine[1]!.verified, true);
  assert.equal(mine[1]!.reason, "ok");

  for (let i = 0; i < 25; i++) await proveAndVerify(username, x, y);
  const capped = (await body(await get(log, "http://t/api/log")))
    .entries as unknown as { id: number }[];
  assert.equal(capped.length, 20, "at most 20 records");
  for (let i = 1; i < capped.length; i++) {
    assert.ok(capped[i - 1]!.id > capped[i]!.id, "ids must descend");
  }
});

test("log entries expose only audit fields", async () => {
  const entries = (await body(await get(log, "http://t/api/log")))
    .entries as unknown as Record<string, unknown>[];
  assert.ok(entries.length > 0);
  for (const entry of entries) {
    assert.deepEqual(
      Object.keys(entry).sort(),
      ["at", "id", "reason", "scheme", "username", "verified"],
    );
  }
});

test("the parameters the routes validate against are the Phase 1 ones", () => {
  assert.equal(g, 2n);
  assert.equal(p.toString(2).length, 2048);
  assert.equal(q, (p - 1n) / 2n);
});
