export const runtime = 'nodejs';

/**
 * GET /api/log — the last 20 verification attempts, newest first.
 *
 * Rows are reshaped rather than returned raw: the stored 0/1 becomes a boolean
 * and nothing beyond the audit fields is exposed.
 */

import { getStore } from "../../../lib/db.ts";
import { fail, json } from "../_shared.ts";

export const LOG_LIMIT = 20;

export async function GET(): Promise<Response> {
  try {
    const entries = getStore()
      .recentLog(LOG_LIMIT)
      .map((row) => ({
        id: row.id,
        username: row.username,
        scheme: row.scheme,
        verified: row.result === 1,
        reason: row.reason,
        at: row.at,
      }));
    return json({ entries });
  } catch {
    return fail("internal_error", 500);
  }
}
