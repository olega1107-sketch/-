import { afterEach, describe, expect, it } from 'vitest';

import { sha256Text } from '../src/canonical.js';
import { PostgresUserSessionAuthenticator } from '../src/postgres-user-session-authenticator.js';
import {
  createDirectorFixture,
  ids,
  times,
  type DirectorFixture,
} from './helpers.js';

const sessionIds = {
  valid: '60000000-0000-4000-8000-000000000001',
  expired: '60000000-0000-4000-8000-000000000002',
  revoked: '60000000-0000-4000-8000-000000000003',
  raw: '60000000-0000-4000-8000-000000000004',
} as const;
const tokens = {
  valid: 'session_valid_7FrxYc3vVb0zJrRTxT9bTQ',
  expired: 'session_expired_CxBwJ4DBDhaTGJs7rQvdMw',
  revoked: 'session_revoked_SFv4RLtC2uE1Tf4xj0M-8Q',
} as const;

describe('PostgreSQL user session authentication', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('resolves an active opaque session and updates last_seen_at without storing the token', async () => {
    fixture = await createDirectorFixture();
    await insertSession(fixture, sessionIds.valid, tokens.valid, '2031-01-01T00:00:00Z');
    const authenticator = new PostgresUserSessionAuthenticator({
      database: fixture.database,
      clock: fixture.clock,
    });

    const principal = await authenticator.authenticate({
      authorization: `bearer ${tokens.valid}`,
      socket: {},
    });

    expect(principal).toEqual({
      userId: ids.user,
      sessionId: sessionIds.valid,
      authenticationMethod: 'password',
    });
    const persisted = await fixture.database.query<{
      tokenHash: string;
      lastSeenAt: Date | string;
    }>(
      `
        SELECT
          session_token_hash AS "tokenHash",
          last_seen_at AS "lastSeenAt"
        FROM dirizhor.user_sessions
        WHERE id = $1::uuid
      `,
      [sessionIds.valid],
    );
    expect(persisted.rows[0]?.tokenHash).toBe(sha256Text(tokens.valid));
    expect(persisted.rows[0]?.tokenHash).not.toContain(tokens.valid);
    expect(new Date(requiredTimestamp(persisted.rows[0]?.lastSeenAt)).toISOString()).toBe(
      times.now,
    );
    await expect(
      fixture.database.query(
        `
          INSERT INTO dirizhor.user_sessions (
            id, user_id, session_token_hash, authentication_method, expires_at
          )
          VALUES ($1::uuid, $2::uuid, $3, 'password', '2031-01-01T00:00:00Z')
        `,
        [sessionIds.raw, ids.user, tokens.valid],
      ),
    ).rejects.toThrow(/user_sessions_token_hash_valid/);
  });

  it('honors session revocation on the next request', async () => {
    fixture = await createDirectorFixture();
    await insertSession(fixture, sessionIds.valid, tokens.valid, '2031-01-01T00:00:00Z');
    const authenticator = new PostgresUserSessionAuthenticator({
      database: fixture.database,
      clock: fixture.clock,
    });
    await authenticator.authenticate({
      authorization: `Bearer ${tokens.valid}`,
      socket: {},
    });
    await fixture.database.query(
      `UPDATE dirizhor.user_sessions SET revoked_at = $2::timestamptz WHERE id = $1::uuid`,
      [sessionIds.valid, times.now],
    );

    await expect(
      authenticator.authenticate({
        authorization: `Bearer ${tokens.valid}`,
        socket: {},
      }),
    ).rejects.toMatchObject({ statusCode: 401, code: 'unauthorized' });
  });

  it('uses the same unauthorized response for expired, revoked, inactive, and unknown sessions', async () => {
    fixture = await createDirectorFixture();
    await insertSession(fixture, sessionIds.valid, tokens.valid, '2031-01-01T00:00:00Z');
    await insertSession(fixture, sessionIds.expired, tokens.expired, '2029-12-31T23:59:59Z');
    await insertSession(
      fixture,
      sessionIds.revoked,
      tokens.revoked,
      '2031-01-01T00:00:00Z',
      '2030-01-01T09:00:00Z',
    );
    const authenticator = new PostgresUserSessionAuthenticator({
      database: fixture.database,
      clock: fixture.clock,
    });

    for (const token of [tokens.expired, tokens.revoked, 'unknown_session_token']) {
      await expect(
        authenticator.authenticate({ authorization: `Bearer ${token}`, socket: {} }),
      ).rejects.toMatchObject({
        statusCode: 401,
        code: 'unauthorized',
        message: 'User bearer is invalid.',
      });
    }

    await fixture.database.query(
      `UPDATE dirizhor.app_users SET status = 'disabled' WHERE id = $1::uuid`,
      [ids.user],
    );
    await expect(
      authenticator.authenticate({
        authorization: `Bearer ${tokens.valid}`,
        socket: {},
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: 'unauthorized',
      message: 'User bearer is invalid.',
    });
  });

  it('rejects missing and malformed authorization headers before querying a session', async () => {
    fixture = await createDirectorFixture();
    const authenticator = new PostgresUserSessionAuthenticator({
      database: fixture.database,
      clock: fixture.clock,
    });

    await expect(authenticator.authenticate({ socket: {} })).rejects.toMatchObject({
      statusCode: 401,
      code: 'unauthorized',
      message: 'User bearer is required.',
    });
    await expect(
      authenticator.authenticate({ authorization: 'Basic credentials', socket: {} }),
    ).rejects.toMatchObject({ statusCode: 401, code: 'unauthorized' });
  });
});

async function insertSession(
  fixture: DirectorFixture,
  sessionId: string,
  token: string,
  expiresAt: string,
  revokedAt: string | null = null,
): Promise<void> {
  await fixture.database.query(
    `
      INSERT INTO dirizhor.user_sessions (
        id, user_id, session_token_hash, authentication_method,
        created_at, expires_at, revoked_at
      )
      VALUES (
        $1::uuid, $2::uuid, $3, 'password',
        '2029-01-01T00:00:00Z', $4::timestamptz, $5::timestamptz
      )
    `,
    [sessionId, ids.user, sha256Text(token), expiresAt, revokedAt],
  );
}

function requiredTimestamp(value: Date | string | undefined): Date | string {
  if (value === undefined) {
    throw new Error('Session timestamp is missing.');
  }
  return value;
}
