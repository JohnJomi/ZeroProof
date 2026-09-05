import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { openDatabase, createStore, type Store, type DB } from "../lib/db.ts";
import { issue, consume, generateNonce, NONCE_TTL_MS } from "../lib/nonce.ts";

const SCHEME = "schnorr-dlog-v1";
const Y_HEX = "a3f1c09b";
const SALT = "0123456789abcdef0123456789abcdef";

/** Each test gets its own database file, so the real zeroproof.db is untouched. */
function freshStore(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), "zeroproof-test-"));
  const store = createStore(openDatabase(join(dir, "test.db")));
  t.after(() => {
    store.db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return store;
}

function addUser(store: Store, username = "alice"): string {
  assert.equal(store.createUser({ username, y: Y_HEX, salt: SALT, scheme: SCHEME }), true);
  return username;
}

// ------------------------------------------------------------------- schema

test("pragmas and schema are applied on open", (t) => {
  const store = freshStore(t);
  const db = store.db as DB;
  assert.equal(String(db.pragma("journal_mode", { simple: true })).toLowerCase(), "wal");
  assert.equal(db.pragma("foreign_keys", { simple: true }), 1);

  const tables = (db
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`)
    .all() as { name: string }[]).map((r) => r.name);
  for (const expected of ["users", "challenges", "verification_log"]) {
    assert.ok(tables.includes(expected), `missing table ${expected}`);
  }
});

test("openDatabase is idempotent — reopening keeps the data", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "zeroproof-test-"));
  const path = join(dir, "test.db");
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const first = createStore(openDatabase(path));
  addUser(first, "bob");
  first.db.close();

  const second = createStore(openDatabase(path));
  assert.equal(second.getUser("bob")?.username, "bob");
  second.db.close();
});

// -------------------------------------------------------------------- users

test("1. a user row can be inserted and read back", (t) => {
  const store = freshStore(t);
  const before = Date.now();
  addUser(store);

  const row = store.getUser("alice");
  assert.ok(row, "user should be readable");
  assert.equal(row.username, "alice");
  assert.equal(row.y, Y_HEX);
  assert.equal(row.salt, SALT);
  assert.equal(row.scheme, SCHEME);
  assert.equal(typeof row.created_at, "number");
  assert.ok(row.created_at >= before && row.created_at <= Date.now());

  assert.equal(store.getUser("nobody"), undefined);
});

test("duplicate usernames are rejected without clobbering the original", (t) => {
  const store = freshStore(t);
  addUser(store);
  const duplicate = store.createUser({
    username: "alice",
    y: "deadbeef",
    salt: "ffff",
    scheme: SCHEME,
  });
  assert.equal(duplicate, false, "second registration must be refused");
  assert.equal(store.getUser("alice")?.y, Y_HEX, "original row must survive");
  const { n } = store.db.prepare(`SELECT count(*) n FROM users`).get() as { n: number };
  assert.equal(n, 1, "exactly one alice row");
});

test("the store persists no secret material", (t) => {
  const store = freshStore(t);
  addUser(store);
  const columns = (store.db.prepare(`PRAGMA table_info(users)`).all() as { name: string }[])
    .map((c) => c.name);
  assert.deepEqual(columns, ["username", "y", "salt", "scheme", "created_at"]);
  for (const forbidden of ["secret", "password", "x", "private"]) {
    assert.ok(!columns.includes(forbidden), `users must not have a ${forbidden} column`);
  }
});

// --------------------------------------------------------------- challenges

test("2. a challenge can be issued", (t) => {
  const store = freshStore(t);
  addUser(store);

  const now = Date.now();
  const { nonce, expiresAt } = issue("alice", store, now);
  assert.match(nonce, /^[0-9a-f]{32}$/, "nonce must be 128 random bits in hex");
  assert.equal(expiresAt, now + NONCE_TTL_MS);
  assert.equal(NONCE_TTL_MS, 60_000, "architecture specifies a 60s lifetime");

  const row = store.getChallenge(nonce);
  assert.ok(row);
  assert.equal(row.username, "alice");
  assert.equal(row.consumed, 0, "a fresh challenge must be unconsumed");
  assert.equal(row.expires_at, expiresAt);
});

test("nonces are unpredictable and unique", (t) => {
  const store = freshStore(t);
  addUser(store);
  const seen = new Set<string>();
  for (let i = 0; i < 200; i++) seen.add(issue("alice", store).nonce);
  assert.equal(seen.size, 200, "every issued nonce must be distinct");
  assert.equal(new Set(Array.from({ length: 100 }, generateNonce)).size, 100);
});

test("a challenge cannot be issued for an unknown user", (t) => {
  const store = freshStore(t);
  assert.throws(() => issue("ghost", store), /FOREIGN KEY/i);
  assert.throws(() => issue("", store), TypeError);
});

// ------------------------------------------------------------ consumption

test("3. a valid challenge can be consumed", (t) => {
  const store = freshStore(t);
  addUser(store);
  const { nonce } = issue("alice", store);

  assert.deepEqual(consume(nonce, "alice", store), { ok: true });
  assert.equal(store.getChallenge(nonce)?.consumed, 1, "row must be marked consumed");
});

test("4. the same challenge cannot be consumed twice", (t) => {
  const store = freshStore(t);
  addUser(store);
  const { nonce } = issue("alice", store);

  assert.equal(consume(nonce, "alice", store).ok, true);
  const replay = consume(nonce, "alice", store);
  assert.equal(replay.ok, false);
  assert.equal(replay.ok === false && replay.reason, "nonce_invalid");

  // Hammering it changes nothing.
  for (let i = 0; i < 10; i++) assert.equal(consume(nonce, "alice", store).ok, false);
});

test("5. a challenge cannot be consumed by the wrong username", (t) => {
  const store = freshStore(t);
  addUser(store, "alice");
  addUser(store, "mallory");
  const { nonce } = issue("alice", store);

  const stolen = consume(nonce, "mallory", store);
  assert.equal(stolen.ok, false);
  assert.equal(stolen.ok === false && stolen.reason, "nonce_invalid");
  assert.equal(store.getChallenge(nonce)?.consumed, 0, "a failed consume must not burn it");

  // The rightful owner can still use it.
  assert.equal(consume(nonce, "alice", store).ok, true);
});

test("6. an expired challenge cannot be consumed", (t) => {
  const store = freshStore(t);
  addUser(store);
  const issuedAt = Date.now();
  const { nonce, expiresAt } = issue("alice", store, issuedAt);

  // One millisecond before expiry it still works; at expiry it does not.
  const justExpired = consume(nonce, "alice", store, expiresAt);
  assert.equal(justExpired.ok, false);
  assert.equal(justExpired.ok === false && justExpired.reason, "nonce_invalid");
  assert.equal(consume(nonce, "alice", store, expiresAt + 60_000).ok, false);
  assert.equal(store.getChallenge(nonce)?.consumed, 0);

  assert.equal(consume(nonce, "alice", store, expiresAt - 1).ok, true, "valid just before TTL");
});

test("unknown and malformed nonces are refused", (t) => {
  const store = freshStore(t);
  addUser(store);
  const unknown = consume(generateNonce(), "alice", store);
  assert.equal(unknown.ok === false && unknown.reason, "nonce_invalid");
  for (const bad of ["", null, undefined, 42]) {
    const r = consume(bad as string, "alice", store);
    assert.equal(r.ok, false);
    assert.equal(r.ok === false && r.reason, "malformed_input");
  }
  const noUser = consume(generateNonce(), "" as string, store);
  assert.equal(noUser.ok === false && noUser.reason, "malformed_input");
});

test("all consume failures report the same generic reason", (t) => {
  const store = freshStore(t);
  addUser(store, "alice");
  addUser(store, "mallory");

  const consumed = issue("alice", store);
  consume(consumed.nonce, "alice", store);
  const expired = issue("alice", store, Date.now() - NONCE_TTL_MS - 1);
  const owned = issue("alice", store);

  // Unknown, already consumed, expired and wrong-owner are indistinguishable:
  // telling them apart would require a second statement.
  const failures = [
    consume(generateNonce(), "alice", store),
    consume(consumed.nonce, "alice", store),
    consume(expired.nonce, "alice", store),
    consume(owned.nonce, "mallory", store),
  ];
  for (const f of failures) {
    assert.equal(f.ok, false);
    assert.equal(f.ok === false && f.reason, "nonce_invalid");
  }
});

// -------------------------------------------------------------- atomicity

test("7. consumption is a single atomic statement", (t) => {
  const store = freshStore(t);

  // The statement itself carries all four conditions — no preliminary SELECT.
  const sql = store.statements.consumeChallenge.source.replace(/\s+/g, " ").trim();
  assert.match(sql, /^UPDATE challenges SET consumed = 1 WHERE/i);
  assert.doesNotMatch(sql, /SELECT/i, "replay protection must not depend on a SELECT");
  for (const condition of ["nonce = ?", "username = ?", "consumed = 0", "expires_at > ?"]) {
    assert.ok(sql.includes(condition), `consume must check ${condition}`);
  }

  // consume() must issue exactly one database statement, whatever the outcome.
  addUser(store, "carol");
  const solo = issue("carol", store);
  let statements = 0;
  const original = store.statements.consumeChallenge.run.bind(store.statements.consumeChallenge);
  const counted = {
    ...store,
    // Any read-back helper counts too, so a reintroduced diagnostic SELECT
    // would fail this test rather than slip past it.
    getChallenge: (...args: unknown[]) => {
      statements++;
      return (store.getChallenge as (...a: unknown[]) => unknown)(...args);
    },
    statements: {
      ...store.statements,
      consumeChallenge: {
        run: (...args: unknown[]) => {
          statements++;
          return (original as (...a: unknown[]) => { changes: number })(...args);
        },
      },
      getChallenge: {
        get: (...args: unknown[]) => {
          statements++;
          return (store.statements.getChallenge.get as (...a: unknown[]) => unknown)(...args);
        },
      },
    },
  } as unknown as Store;
  assert.equal(consume(solo.nonce, "carol", counted).ok, true);
  assert.equal(statements, 1, "the successful path runs one statement");
  assert.equal(consume(solo.nonce, "carol", counted).ok, false);
  assert.equal(statements, 2, "the failure path must not run a second statement");

  // Exactly one winner across many attempts on the same nonce.
  addUser(store);
  const { nonce } = issue("alice", store);
  const results = Array.from({ length: 50 }, () => consume(nonce, "alice", store));
  assert.equal(results.filter((r) => r.ok).length, 1, "exactly one consume may succeed");
});

test("7b. two connections racing the same nonce produce one winner", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "zeroproof-test-"));
  const path = join(dir, "test.db");
  const a = createStore(openDatabase(path));
  const b = createStore(openDatabase(path));
  t.after(() => {
    a.db.close();
    b.db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  addUser(a);
  const { nonce } = issue("alice", a);

  // Both connections see the unconsumed row; only one UPDATE can match it.
  assert.equal(a.getChallenge(nonce)?.consumed, 0);
  assert.equal(b.getChallenge(nonce)?.consumed, 0);

  const first = consume(nonce, "alice", a);
  const second = consume(nonce, "alice", b);
  assert.equal([first, second].filter((r) => r.ok).length, 1, "one winner only");
  assert.equal(first.ok, true);
  assert.equal(second.ok === false && second.reason, "nonce_invalid");
});

test("purging expired challenges leaves live ones alone", (t) => {
  const store = freshStore(t);
  addUser(store);
  const now = Date.now();
  const stale = issue("alice", store, now - NONCE_TTL_MS - 1);
  const live = issue("alice", store, now);

  assert.equal(store.purgeExpiredChallenges(now), 1);
  assert.equal(store.getChallenge(stale.nonce), undefined);
  assert.ok(store.getChallenge(live.nonce));
});

// ------------------------------------------------------------------ the log

test("verification_log appends and reads back newest first", (t) => {
  const store = freshStore(t);
  store.appendLog({ username: "alice", scheme: SCHEME, result: 1 });
  store.appendLog({ username: "alice", scheme: SCHEME, result: 0, reason: "nonce_consumed" });

  const rows = store.recentLog(20);
  assert.equal(rows.length, 2);
  assert.equal(rows[0]!.reason, "nonce_consumed");
  assert.equal(rows[0]!.result, 0);
  assert.equal(rows[1]!.result, 1);
  assert.equal(rows[1]!.reason, null, "reason defaults to NULL");
  assert.equal(typeof rows[0]!.id, "number");

  for (let i = 0; i < 30; i++) {
    store.appendLog({ username: "bob", scheme: SCHEME, result: 1 });
  }
  assert.equal(store.recentLog(20).length, 20, "limit is honoured");
});

test("verification_log rejects an out-of-range result", (t) => {
  const store = freshStore(t);
  assert.throws(
    () => store.appendLog({ username: "alice", scheme: SCHEME, result: 7 as 0 | 1 }),
    /CHECK constraint/i,
  );
});
