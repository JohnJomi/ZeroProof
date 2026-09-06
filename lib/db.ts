/**
 * SQLite persistence for ZeroProof.
 *
 * This layer imports nothing from Next.js and nothing from `lib/zk`. It stores
 * only public values: the commitment `y` and the registration salt. The secret
 * and the derived private exponent `x` never reach the server, so they are not
 * representable here.
 */

import Database from "better-sqlite3";

export type DB = Database.Database;

/** Default database file. Overridable so tests do not touch the real one. */
export const DB_PATH = process.env.ZEROPROOF_DB ?? "zeroproof.db";

/** Milliseconds since the Unix epoch. One time unit across every table. */
export type Timestamp = number;

export interface UserRow {
  username: string;
  y: string;
  salt: string;
  scheme: string;
  created_at: Timestamp;
}

export interface ChallengeRow {
  nonce: string;
  username: string;
  expires_at: Timestamp;
  consumed: 0 | 1;
}

export interface VerificationLogRow {
  id: number;
  username: string;
  scheme: string;
  result: 0 | 1;
  reason: string | null;
  at: Timestamp;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  username   TEXT    PRIMARY KEY,
  y          TEXT    NOT NULL,
  salt       TEXT    NOT NULL,
  scheme     TEXT    NOT NULL,
  created_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS challenges (
  nonce      TEXT    PRIMARY KEY,
  username   TEXT    NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1))
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_challenges_username ON challenges(username);

CREATE TABLE IF NOT EXISTS verification_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT    NOT NULL,
  scheme   TEXT    NOT NULL,
  result   INTEGER NOT NULL CHECK (result IN (0, 1)),
  reason   TEXT,
  at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_log_at ON verification_log(at DESC);
`;

/** Open a connection and apply pragmas and schema. Safe to call repeatedly. */
export function openDatabase(path: string = DB_PATH): DB {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  return db;
}

/**
 * Prepared statements and the small helpers built on them.
 *
 * Bound to one connection so tests can build a store over a temporary file
 * without disturbing the module-level default.
 */
export function createStore(db: DB) {
  const statements = {
    insertUser: db.prepare(
      `INSERT INTO users (username, y, salt, scheme, created_at)
       VALUES (@username, @y, @salt, @scheme, @created_at)`,
    ),
    getUser: db.prepare(`SELECT * FROM users WHERE username = ?`),
    insertChallenge: db.prepare(
      `INSERT INTO challenges (nonce, username, expires_at, consumed)
       VALUES (@nonce, @username, @expires_at, 0)`,
    ),
    getChallenge: db.prepare(`SELECT * FROM challenges WHERE nonce = ?`),
    // The whole of replay protection: one conditional UPDATE, no prior SELECT.
    consumeChallenge: db.prepare(
      `UPDATE challenges
          SET consumed = 1
        WHERE nonce = ?
          AND username = ?
          AND consumed = 0
          AND expires_at > ?`,
    ),
    deleteExpiredChallenges: db.prepare(`DELETE FROM challenges WHERE expires_at <= ?`),
    insertLog: db.prepare(
      `INSERT INTO verification_log (username, scheme, result, reason, at)
       VALUES (@username, @scheme, @result, @reason, @at)`,
    ),
    recentLog: db.prepare(
      `SELECT * FROM verification_log ORDER BY id DESC LIMIT ?`,
    ),
  };

  return {
    db,
    statements,

    /**
     * Register a user. Returns false when the username is taken rather than
     * throwing, so callers can map it to a 409 without inspecting error codes.
     */
    createUser(user: Omit<UserRow, "created_at"> & { created_at?: Timestamp }): boolean {
      try {
        statements.insertUser.run({ created_at: Date.now(), ...user });
        return true;
      } catch (err) {
        if (isUniqueViolation(err)) return false;
        throw err;
      }
    },

    getUser(username: string): UserRow | undefined {
      return statements.getUser.get(username) as UserRow | undefined;
    },

    getChallenge(nonce: string): ChallengeRow | undefined {
      return statements.getChallenge.get(nonce) as ChallengeRow | undefined;
    },

    /** Housekeeping only — expiry is enforced in the consume statement itself. */
    purgeExpiredChallenges(now: Timestamp = Date.now()): number {
      return statements.deleteExpiredChallenges.run(now).changes;
    },

    appendLog(entry: Omit<VerificationLogRow, "id" | "at" | "reason"> & {
      reason?: string | null;
      at?: Timestamp;
    }): void {
      statements.insertLog.run({
        username: entry.username,
        scheme: entry.scheme,
        result: entry.result,
        reason: entry.reason ?? null,
        at: entry.at ?? Date.now(),
      });
    },

    recentLog(limit = 20): VerificationLogRow[] {
      return statements.recentLog.all(limit) as VerificationLogRow[];
    },
  };
}

export type Store = ReturnType<typeof createStore>;

/** True for a PRIMARY KEY / UNIQUE constraint failure. */
function isUniqueViolation(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  return code === "SQLITE_CONSTRAINT_PRIMARYKEY" || code === "SQLITE_CONSTRAINT_UNIQUE";
}

let defaultStore: Store | undefined;

/** The process-wide store over `DB_PATH`, opened on first use. */
export function getStore(): Store {
  if (!defaultStore) defaultStore = createStore(openDatabase());
  return defaultStore;
}
