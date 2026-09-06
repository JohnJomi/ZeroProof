export const runtime = 'nodejs';

/**
 * POST /api/verify — check a proof against the stored commitment.
 *
 * Order matters: the nonce is consumed *before* the proof is checked, so a
 * captured proof cannot be replayed even if it is valid. A failed proof burns
 * the nonce too — that is the point.
 *
 * The scheme is looked up in the registry rather than calling Schnorr
 * directly, so a future scheme needs no change here.
 */

import { getStore } from "../../../lib/db.ts";
import { consume } from "../../../lib/nonce.ts";
import { registry } from "../../../lib/zk/scheme.ts";
import {
  fail,
  json,
  readJsonObject,
  isValidUsername,
  isValidHex,
  type Reason,
} from "../_shared.ts";

/** A completed verification is always 200 — verified or not. */
function verdict(verified: boolean, reason: Reason): Response {
  return json({ verified, reason });
}

export async function POST(request: Request): Promise<Response> {
  const body = await readJsonObject(request);
  if (!body) return fail("malformed_request", 400);

  const { username, nonce, t, s } = body;
  if (!isValidUsername(username)) return fail("invalid_username", 400);
  if (!isValidHex(nonce, 64)) return fail("malformed_request", 400);
  if (typeof t !== "string" || typeof s !== "string") return fail("malformed_request", 400);

  const store = getStore();

  try {
    // 1. Burn the nonce first. Everything after this is unreplayable.
    const consumed = consume(nonce, username, store);

    // The user is loaded regardless, so a rejected attempt still lands in the
    // audit log under the right scheme.
    const user = store.getUser(username);
    const scheme = user?.scheme ?? "unknown";

    if (!consumed.ok) {
      store.appendLog({ username, scheme, result: 0, reason: "nonce_invalid" });
      return verdict(false, "nonce_invalid");
    }

    if (!user) {
      store.appendLog({ username, scheme, result: 0, reason: "unknown_user" });
      return verdict(false, "unknown_user");
    }

    const impl = registry.get(user.scheme);
    if (!impl) {
      store.appendLog({ username, scheme, result: 0, reason: "unsupported_scheme" });
      return verdict(false, "unsupported_scheme");
    }

    // 2. Dispatch through the registry. `subject` binds the proof to the user.
    const result = await impl.verify({ t, s }, { y: user.y }, { nonce, subject: username });
    const reason = (result.ok ? "ok" : (result.reason ?? "verification_failed")) as Reason;

    store.appendLog({ username, scheme, result: result.ok ? 1 : 0, reason });
    return verdict(result.ok, reason);
  } catch {
    return fail("internal_error", 500);
  }
}
