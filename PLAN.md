# ZeroProof — Phase-wise Execution Plan

Target: a working end-to-end system in **120 minutes**. Each phase ends with a
concrete check; do not move on until it passes. Design rationale lives in
[architecture.md](architecture.md).

**Stack:** Next.js (App Router, TypeScript) · Route Handlers on the Node runtime
as the verifier backend · SQLite via `better-sqlite3` · zero dependencies in the
cryptographic core.

---

## Phase 0 — Scaffold (15 min)

```bash
npx create-next-app@latest . --ts --app --eslint --no-tailwind --no-src-dir --import-alias "@/*"
```

```bash
npm i better-sqlite3 && npm i -D @types/better-sqlite3
```

- `architecture.md` is already written — review it before starting.

**Check:** `npm run dev` serves the default page at `localhost:3000`.

---

## Phase 1 — Cryptographic core (25 min)

Build `lib/zk/`. This layer imports nothing from Next.js and nothing from the
database — that rule is what lets the same code act as prover in the browser and
verifier on the server.

| File | Contents |
|---|---|
| `params.ts` | RFC 3526 2048-bit prime `p` as hex, `g = 2n`, `q = (p - 1n) / 2n` |
| `bigint.ts` | `modPow` by square-and-multiply; `randomBigIntBelow(q)` via `crypto.getRandomValues` with **rejection sampling** (plain modulo introduces bias); hex ⇄ BigInt |
| `hash.ts` | `sha256ToBigInt(...parts: string[])` over `crypto.subtle` |
| `schnorr.ts` | `deriveSecret(salt, secret)`, `publicKey(x)`, `prove(x, y, nonce, subject)`, `verify(proof, y, nonce, subject)` |
| `scheme.ts` | `ProofScheme` interface + `registry`; register `schnorr-dlog-v1` |

`verify` must range-check before doing any exponentiation: `1 < t < p` and
`0 ≤ s < q`.

**Check:** `node --test` covers five cases — honest proof verifies; wrong secret
rejects; tampered `s` rejects; a proof minted for nonce A rejects under nonce B;
out-of-range `t` rejects.

---

## Phase 2 — Persistence (15 min)

- `lib/db.ts` — open `zeroproof.db`, set `PRAGMA journal_mode = WAL`, create the
  three tables at module load, export prepared statements.
- `lib/nonce.ts` — `issue(username)` and `consume(nonce, username)`.

`consume` must be a **single atomic statement**:

```sql
UPDATE challenges SET consumed = 1
 WHERE nonce = ? AND consumed = 0 AND expires_at > ?
```

then assert `changes === 1`. A separate read-then-write leaves a replay window.

**Check:** a Node one-liner inserts a user row and reads it back.

---

## Phase 3 — API routes (25 min)

Every route file begins with `export const runtime = 'nodejs'` — the edge runtime
cannot load SQLite.

| Route | Behaviour |
|---|---|
| `POST /api/register` | Reject duplicate username; reject `y` outside `(1, p)`; 201 on success |
| `GET /api/challenge` | 404 on unknown user; else `{ nonce, salt, expiresAt }` — the salt lets the prover re-derive `x` |
| `POST /api/verify` | Consume nonce → load user → dispatch via `registry.get(schemeId)` → append to `verification_log` → `{ verified, reason }` |
| `GET /api/log` | Last 20 verification rows |

**Check:** a hand-rolled Node prover script walks register → challenge → verify
and gets `verified: true`.

---

## Phase 4 — Frontend (25 min)

`lib/client.ts` wraps fetch and calls `prove()` in the browser. Three tabs on
`app/page.tsx`:

- **Register** — username + secret; display the computed `y` and state plainly
  that the secret never left the browser.
- **Prove** — run the flow; render the verdict alongside the actual `{t, s}` that
  went over the wire.
- **Audit** — table fed by `/api/log`.

**Check:** register, prove with the correct secret (accepted), prove with a wrong
secret (rejected).

---

## Phase 5 — Demo hardening (10 min)

The system refusing a bad proof is more convincing than it accepting a good one.
Both of these are worth the time:

- **Tamper toggle** on the Prove tab — flip one bit of `s` before sending; the
  verifier rejects.
- **Replay button** — re-POST the previous proof verbatim; rejected as
  `nonce_consumed`.

Have DevTools → Network open during the demo to show no plaintext secret in any
payload.

---

## Phase 6 — Wrap up (5 min)

- `README.md` with run instructions and a 60-second demo script.
- Reconcile `architecture.md` against what was actually built.

---

## Final verification

1. `node --test` — all crypto cases green.
2. In the browser: correct secret → **Verified**; wrong secret → **Rejected**;
   tamper → **Rejected**; replay → **Rejected (nonce consumed)**.
3. DevTools → Network: the secret string appears in no request body.
4. `sqlite3 zeroproof.db "select * from verification_log;"` shows the trail.

---

## Known risks

- `better-sqlite3` is a native module. If no prebuilt binary matches the local
  Node version, fix the install (match a supported Node version, or rebuild from
  source) — do **not** substitute an in-memory `Map`. Challenge consumption has
  to be atomic and durable across processes and workers; process-local state
  silently reintroduces the replay window the nonce exists to close. If SQLite
  cannot load, the system should fail loudly rather than degrade.
- 2048-bit `modPow` in JavaScript takes a few milliseconds. If it ever feels slow
  in the browser, drop to the RFC 3526 1024-bit group; the protocol is unchanged.
- Do not let a route handler default to the edge runtime.
