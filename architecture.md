# ZeroProof — Architecture

A web-based Zero-Knowledge Proof system. A user proves knowledge of a secret to a
server without the secret — or anything derived from it that could reveal it —
ever crossing the network.

---

## 1. Problem statement

Conventional password authentication requires the client to transmit the secret
(or a deterministic hash of it) to the server. The server therefore learns a
value that is sufficient to impersonate the user, and any breach of the server's
store compromises every account in it.

ZeroProof removes the secret from the wire entirely. The server stores only a
**public commitment** `y`, which is computationally infeasible to invert. At
login the client produces a **zero-knowledge proof** that it knows the secret
behind `y`. The server can check the proof, but learns nothing from it that it
could not have produced by itself.

Three properties are required of the proof system:

| Property | Meaning |
|---|---|
| **Completeness** | An honest prover who knows the secret always convinces the verifier. |
| **Soundness** | A prover who does not know the secret convinces the verifier only with negligible probability. |
| **Zero-knowledge** | The verifier's view of the protocol can be simulated without the secret, so it leaks nothing. |

---

## 2. Choice of scheme

ZeroProof uses a **Schnorr proof of knowledge of a discrete logarithm**, made
non-interactive by the **Fiat–Shamir transform**.

This was chosen over a zk-SNARK toolchain (Circom + Groth16) deliberately. A
SNARK requires circuit compilation, a trusted setup ceremony, and multi-megabyte
proving keys — all of which add operational weight without changing what this
system demonstrates. The Schnorr protocol is a genuine zero-knowledge proof with
a short, auditable security argument, implementable in roughly 150 lines with no
external dependencies, and it runs identically in a browser and on a server.

### Public parameters

Fixed for the whole system, published to everyone, and requiring no ceremony:

| Symbol | Value |
|---|---|
| `p` | The 2048-bit safe prime of RFC 3526 MODP Group 14 |
| `g` | `2`, a generator of a large prime-order subgroup |
| `q` | `(p − 1) / 2`, the subgroup order |

Arithmetic uses native `BigInt`. Hashing uses Web Crypto SHA-256, which is
present both in browsers and in the Node runtime, so a single implementation
serves prover and verifier.

---

## 3. The protocol

### 3.1 Registration

The secret never leaves the browser.

```text
client                                            server
  │  salt ← random 16 bytes
  │  x    ← SHA256(salt ‖ secret) mod q          (private, discarded after use)
  │  y    ← g^x mod p                            (public commitment)
  │
  ├── POST /api/register { username, y, salt } ──▶
  │                                               store (username, y, salt)
  ◀────────────────────── 201 Created ────────────┤
```

The server receives `y`. Recovering `x` from `y` is the discrete logarithm
problem in a 2048-bit group — computationally infeasible.

### 3.2 Proof of knowledge

```text
client                                            server
  ├── GET /api/challenge?username=alice ─────────▶
  │                                               nonce ← random 128 bits
  │                                               store (nonce, exp = now + 60s)
  ◀──────────── { nonce, salt, expiresAt } ───────┤
  │
  │  x ← SHA256(salt ‖ secret) mod q             re-derived from typed secret
  │  k ← random in [1, q)                        single-use blinding factor
  │  t ← g^k mod p                               commitment
  │  c ← SHA256(p ‖ g ‖ y ‖ t ‖ nonce ‖ user) mod q     Fiat–Shamir challenge
  │  s ← (k + c·x) mod q                         response
  │
  ├── POST /api/verify { username, nonce, t, s } ▶
  │                                               consume nonce (single use)
  │                                               recompute c independently
  │                                               accept iff g^s ≡ t · y^c
  ◀──────────── { verified, reason } ─────────────┤
```

### 3.3 Why it works

**Completeness.** For an honest prover,

```text
g^s = g^(k + c·x) = g^k · (g^x)^c = t · y^c   (mod p)
```

so the verification equation holds by construction.

**Soundness.** If a prover could answer two distinct challenges `c₁ ≠ c₂` on the
same commitment `t`, then from `s₁ = k + c₁x` and `s₂ = k + c₂x` one extracts
`x = (s₁ − s₂)/(c₁ − c₂) mod q`. So anyone who can reliably produce valid proofs
can be used to compute the discrete log — which is assumed hard. Because `c` is
the output of a hash the prover cannot control, forging without `x` requires
inverting SHA-256.

**Zero-knowledge.** Given any challenge `c`, a simulator with no knowledge of `x`
can pick `s` at random and set `t = g^s · y^(−c)`. The resulting transcript
`(t, c, s)` is distributed identically to a real one. The verifier's entire view
is therefore simulatable without the secret, so it carries no information about
it. Concretely: `k` is fresh and uniform per proof, so `s = k + c·x` is a uniform
value that perfectly masks `x`.

---

## 4. Component architecture

```text
┌─────────────────────── Browser ────────────────────────┐
│  UI (Next.js App Router)                               │
│    Register · Prove · Audit                            │
│                     │                                  │
│  lib/zk  ── prover ─┤   secret and x live only here    │
└─────────────────────┼──────────────────────────────────┘
                      │  HTTPS: { username, nonce, t, s }
┌─────────────────────┼──────────────────────────────────┐
│  Route Handlers     ▼           (Node runtime)         │
│    /api/register  /api/challenge  /api/verify  /api/log│
│                     │                                  │
│  lib/zk  ── verifier┤   scheme registry dispatch       │
│                     │                                  │
│  lib/nonce ─────────┤   single-use challenge lifecycle │
│  lib/db  ───────────┘   SQLite: users, challenges, log │
└────────────────────────────────────────────────────────┘
```

`lib/zk/*` is a **pure module**. It imports nothing from Next.js and nothing from
the database layer, which is what allows the identical code to run as the prover
in the browser and as the verifier on the server — and what would allow the
verifier to be lifted into a standalone Express service without modification.

### Data model

```sql
users            (username PK, y, salt, scheme, created_at)
challenges       (nonce PK, username, expires_at, consumed)
verification_log (id PK, username, scheme, result, reason, at)
```

---

## 5. Extensibility

Schnorr's discrete-log proof is one instance of a general shape. The system
therefore dispatches on a scheme identifier rather than hard-coding it:

```ts
export interface ProofScheme<Pub, Proof> {
  id: string;                                    // "schnorr-dlog-v1"
  verify(proof: Proof, pub: Pub, ctx: { nonce: string; subject: string }):
    Promise<{ ok: boolean; reason?: string }>;
}
export const registry = new Map<string, ProofScheme<any, any>>();
```

`/api/verify` reads `schemeId` from the request and looks the verifier up in the
registry. Adding a new privacy-preserving use case — an age-over-18 range proof,
a Merkle-tree set-membership proof, a credential-attribute disclosure proof —
means adding one file and one `registry.set(...)` call. Transport, storage, and
UI are untouched.

---

## 6. Threat model

**Defended against**

| Threat | Defence |
|---|---|
| Server database breach | The store holds only `y` and `salt`, never the secret or `x`. Inverting `y` directly is a discrete-log problem. **This does not stop offline guessing — see the note below.** |
| Passive network eavesdropper | Transcripts are simulatable, so they reveal nothing about the secret. |
| Replay of a captured proof | Each proof is bound to a server-issued nonce that is single-use and expires in 60 s. Consumption is an atomic conditional `UPDATE`, so a replay loses the race rather than being caught by a check-then-act. |
| Tampering with a proof in transit | Any modification to `t` or `s` breaks the verification equation. |
| Forging a proof without the secret | Requires solving discrete log or inverting SHA-256. |

**Offline dictionary attack after a database breach**

The registration salt is stored alongside `y`, and both the parameters and the
derivation are public. An attacker who steals the database can therefore test
candidate secrets entirely offline, with no further interaction with the server:

```text
for each guess:  x' ← SHA256(salt ‖ guess) mod q
                 if g^x' mod p == y  then guess is the secret
```

The per-user salt prevents one precomputed table from covering every account,
but it does nothing to slow a targeted search: each attempt costs a single
SHA-256 and one modular exponentiation, and the derivation is deliberately not
memory- or CPU-hard.

So the honest statement of the property is narrower than "a breach reveals
nothing". Discrete-log hardness protects the commitment from **direct
inversion** — it does not protect a **low-entropy secret from being guessed**.
A human-chosen password in a wordlist falls to this attack quickly.

**ZeroProof therefore requires high-entropy secrets** — a long random
passphrase or generated key, not a memorable password. With a genuinely
high-entropy secret the search space is infeasible and the breach yields
nothing; with a weak one, `y` behaves much like an unsalted-but-fast password
hash. Closing this gap properly means an augmented PAKE such as OPAQUE, which is
outside the teaching scope of this system; a production design would at minimum
replace SHA-256 with a memory-hard KDF (scrypt, Argon2) to raise the per-guess
cost.

**Explicitly out of scope**

- **Nonce reuse by the prover.** Reusing `k` across two proofs leaks `x` outright.
  Mitigated by sampling `k` freshly per proof with rejection sampling over
  `crypto.getRandomValues`.
- **Transport security.** The nonce binding stops replay, but session
  confidentiality and integrity are assumed to come from TLS.
- **Client-side compromise.** A prover whose machine is compromised has already
  lost the secret; no proof system fixes that.
- **Session management after verification.** Issuing and protecting a session
  token once a proof is accepted is a separate, conventional concern.
- **Rate limiting and account enumeration.** `/api/challenge` currently
  distinguishes known from unknown users.

---

## 7. Non-goals

This is a teaching and demonstration system. It is not hardened for production
deployment: there is no rate limiting, no session layer, no key rotation, and the
public parameters are compiled in rather than negotiated. The cryptographic core
is sound, but the surrounding operational envelope is deliberately minimal.
