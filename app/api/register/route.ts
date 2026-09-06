export const runtime = 'nodejs';

/**
 * POST /api/register — store a public commitment.
 *
 * The body carries `y` and `salt`, never the secret. Nothing secret-derived is
 * accepted: any other field in the body is ignored and never persisted.
 */

import { getStore } from "../../../lib/db.ts";
import { registry } from "../../../lib/zk/scheme.ts";
import {
  fail,
  json,
  readJsonObject,
  isValidUsername,
  isValidHex,
  isValidPublicKey,
  MAX_SALT_LENGTH,
} from "../_shared.ts";

export async function POST(request: Request): Promise<Response> {
  const body = await readJsonObject(request);
  if (!body) return fail("malformed_request", 400);

  const { username, y, salt, scheme } = body;

  if (!isValidUsername(username)) return fail("invalid_username", 400);
  if (!isValidHex(salt, MAX_SALT_LENGTH)) return fail("missing_field", 400);
  if (typeof scheme !== "string" || !registry.has(scheme)) {
    return fail("unsupported_scheme", 400);
  }
  if (!isValidHex(y)) return fail("invalid_public_key", 400);
  if (!isValidPublicKey(y)) return fail("invalid_public_key", 400);

  try {
    // Only these four fields are ever written; the secret has no path here.
    const created = getStore().createUser({ username, y, salt, scheme });
    if (!created) return fail("username_taken", 409);
  } catch {
    return fail("internal_error", 500);
  }

  return json({ username, scheme, reason: "ok" }, 201);
}
