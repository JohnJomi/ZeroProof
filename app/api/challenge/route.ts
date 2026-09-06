export const runtime = 'nodejs';

/**
 * GET /api/challenge?username=alice — issue a single-use nonce.
 *
 * Returns the stored salt so the prover can re-derive `x` in the browser.
 * `y` is never returned: the client already knows it, and echoing it would
 * hand an attacker the commitment for free.
 */

import { getStore } from "../../../lib/db.ts";
import { issue } from "../../../lib/nonce.ts";
import { fail, json, isValidUsername } from "../_shared.ts";

export async function GET(request: Request): Promise<Response> {
  const username = new URL(request.url).searchParams.get("username");
  if (!isValidUsername(username)) return fail("invalid_username", 400);

  const store = getStore();
  const user = store.getUser(username);
  if (!user) return fail("unknown_user", 404);

  try {
    const { nonce, expiresAt } = issue(username, store);
    return json({ nonce, salt: user.salt, expiresAt });
  } catch {
    return fail("internal_error", 500);
  }
}
