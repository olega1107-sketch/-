import { randomUUID } from 'node:crypto';

import type { IdGenerator } from './memory-ports.js';
import type { Clock, SqlDatabase } from './ports.js';
import { systemClock } from './ports.js';

export interface OidcAccessRevocationInput {
  requestId: string;
  userId: string;
  login: string;
}

export interface OidcAccessRevocationResult {
  outcome: 'revoked' | 'unchanged';
  userId: string;
  revokedSessionCount: number;
}

export class OidcAccessRevocationError extends Error {
  constructor(readonly code: 'database_failure' | 'invalid_input' | 'user_not_found') {
    super(`OIDC access revocation failed: ${code}.`);
    this.name = 'OidcAccessRevocationError';
  }
}

interface UserRow {
  login: string;
  status: string;
}

const randomIds: IdGenerator = { next: () => randomUUID() };
const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

export class OidcAccessRevoker {
  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;

  constructor(
    private readonly database: SqlDatabase,
    options: { clock?: Clock; idGenerator?: IdGenerator } = {},
  ) {
    this.clock = options.clock ?? systemClock;
    this.idGenerator = options.idGenerator ?? randomIds;
  }

  async revoke(input: OidcAccessRevocationInput): Promise<OidcAccessRevocationResult> {
    const validated = validateInput(input);
    try {
      return await this.database.transaction(async (transaction) => {
        const userResult = await transaction.query<UserRow>(
          `
            SELECT login, status
            FROM dirizhor.app_users
            WHERE id = $1::uuid
            FOR UPDATE
          `,
          [validated.userId],
        );
        const user = userResult.rows[0];
        if (
          user === undefined ||
          user.login.toLowerCase() !== validated.login.toLowerCase()
        ) {
          throw new OidcAccessRevocationError('user_not_found');
        }

        const revokedAt = this.clock.now().toISOString();
        const sessions = await transaction.query<{ id: string }>(
          `
            UPDATE dirizhor.user_sessions
            SET revoked_at = $2::timestamptz
            WHERE user_id = $1::uuid
              AND revoked_at IS NULL
            RETURNING id::text AS id
          `,
          [validated.userId, revokedAt],
        );
        if (user.status === 'disabled' && sessions.rows.length === 0) {
          return {
            outcome: 'unchanged',
            userId: validated.userId,
            revokedSessionCount: 0,
          };
        }
        await transaction.query(
          `
            UPDATE dirizhor.app_users
            SET status = 'disabled', updated_at = $2::timestamptz
            WHERE id = $1::uuid
          `,
          [validated.userId, revokedAt],
        );
        await transaction.query(
          `
            INSERT INTO dirizhor.audit_events (
              id, actor_type, action, target_type, target_id, metadata,
              created_at, request_id
            )
            VALUES (
              $1::uuid, 'system', 'user.access_revoked', 'app_user', $2::uuid,
              $3::jsonb, $4::timestamptz, $5::uuid
            )
          `,
          [
            this.idGenerator.next(),
            validated.userId,
            JSON.stringify({
              previous_status: user.status,
              revoked_session_count: sessions.rows.length,
            }),
            revokedAt,
            validated.requestId,
          ],
        );
        return {
          outcome: 'revoked',
          userId: validated.userId,
          revokedSessionCount: sessions.rows.length,
        };
      });
    } catch (error) {
      if (error instanceof OidcAccessRevocationError) {
        throw error;
      }
      throw new OidcAccessRevocationError('database_failure');
    }
  }
}

export function parseOidcAccessRevocationInput(
  value: unknown,
): OidcAccessRevocationInput {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new OidcAccessRevocationError('invalid_input');
  }
  const input = value as Record<string, unknown>;
  if (
    Object.keys(input).some(
      (key) => !['request_id', 'user_id', 'login'].includes(key),
    ) ||
    typeof input.request_id !== 'string' ||
    typeof input.user_id !== 'string' ||
    typeof input.login !== 'string'
  ) {
    throw new OidcAccessRevocationError('invalid_input');
  }
  return validateInput({
    requestId: input.request_id,
    userId: input.user_id,
    login: input.login.trim(),
  });
}

function validateInput(input: OidcAccessRevocationInput): OidcAccessRevocationInput {
  if (
    !uuidPattern.test(input.requestId) ||
    !uuidPattern.test(input.userId) ||
    input.login.length === 0 ||
    input.login.length > 320 ||
    input.login.trim().length === 0 ||
    input.login.includes('\0')
  ) {
    throw new OidcAccessRevocationError('invalid_input');
  }
  return input;
}
