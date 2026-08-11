import { afterEach, describe, expect, it } from 'vitest';

import { buildDirectorApp } from '../src/app.js';
import { sha256Text } from '../src/canonical.js';
import { hashLocalPassword } from '../src/local-password.js';
import { MemoryIngestService } from '../src/memory-ingest-service.js';
import type { IdGenerator } from '../src/memory-ports.js';
import { PostgresMemoryIngestRepository } from '../src/postgres-memory-ingest-repository.js';
import { PostgresSessionRepository } from '../src/postgres-session-repository.js';
import { PostgresUserSessionAuthenticator } from '../src/postgres-user-session-authenticator.js';
import { StaticBearerAuthenticator } from '../src/service-auth.js';
import type { SessionTokenGenerator } from '../src/session-ports.js';
import { SessionService } from '../src/session-service.js';
import {
  createDirectorFixture,
  gatewayBearerToken,
  ids,
  type DirectorFixture,
} from './helpers.js';

const identityId = '50000000-0000-4000-8000-000000000001';
const sessionId = '50000000-0000-4000-8000-000000000002';
const authenticationAuditId = '50000000-0000-4000-8000-000000000003';
const revocationAuditId = '50000000-0000-4000-8000-000000000004';
const loginRequestId = '50000000-0000-4000-8000-000000000005';
const revokeRequestId = '50000000-0000-4000-8000-000000000006';
const retryRequestId = '50000000-0000-4000-8000-000000000007';
const invalidRequestId = '50000000-0000-4000-8000-000000000008';
const unknownRequestId = '50000000-0000-4000-8000-000000000009';
const inactiveRequestId = '50000000-0000-4000-8000-000000000010';
const password = 'correct horse battery staple';
const sessionToken = 's'.repeat(43);

describe('User session HTTP contract', () => {
  let fixture: DirectorFixture | undefined;
  let app: ReturnType<typeof buildDirectorApp> | undefined;

  afterEach(async () => {
    await app?.close();
    await fixture?.close();
    app = undefined;
    fixture = undefined;
  });

  it('issues a hash-only session, authenticates it, and revokes it immediately', async () => {
    ({ fixture, app } = await createSessionApp({
      idGenerator: new SequenceIds([sessionId, authenticationAuditId, revocationAuditId]),
      tokenGenerator: { next: () => sessionToken },
    }));

    const issued = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/sessions',
      headers: {
        'x-request-id': loginRequestId,
        'user-agent': 'Director Session Test/1.0',
      },
      payload: { login: ' OWNER@example.test ', password },
    });

    expect(issued.statusCode, issued.body).toBe(201);
    expect(issued.headers['cache-control']).toBe('no-store');
    expect(issued.headers.pragma).toBe('no-cache');
    expect(issued.json()).toEqual({
      access_token: sessionToken,
      token_type: 'Bearer',
      session: {
        id: sessionId,
        user_id: ids.user,
        authentication_method: 'local_password',
        created_at: '2030-01-01T10:00:00.000Z',
        expires_at: '2030-01-01T11:00:00.000Z',
      },
    });

    const stored = await fixture.database.query<{
      tokenHash: string;
      userAgent: string;
      revokedAt: string | null;
    }>(
      `
        SELECT
          session_token_hash AS "tokenHash",
          user_agent AS "userAgent",
          revoked_at AS "revokedAt"
        FROM dirizhor.user_sessions
        WHERE id = $1::uuid
      `,
      [sessionId],
    );
    expect(stored.rows[0]).toEqual({
      tokenHash: sha256Text(sessionToken),
      userAgent: 'Director Session Test/1.0',
      revokedAt: null,
    });
    expect(JSON.stringify(stored.rows[0])).not.toContain(sessionToken);

    const revoked = await app.inject({
      method: 'DELETE',
      url: '/api/v1/auth/sessions/current',
      headers: {
        authorization: `Bearer ${sessionToken}`,
        'x-request-id': revokeRequestId,
      },
    });
    expect(revoked.statusCode, revoked.body).toBe(204);
    expect(revoked.body).toBe('');

    const denied = await app.inject({
      method: 'DELETE',
      url: '/api/v1/auth/sessions/current',
      headers: {
        authorization: `Bearer ${sessionToken}`,
        'x-request-id': retryRequestId,
      },
    });
    expect(denied.statusCode, denied.body).toBe(401);
    expect(denied.json()).toMatchObject({ error: { code: 'unauthorized' } });

    const audit = await fixture.database.query<{ action: string }>(
      `
        SELECT action
        FROM dirizhor.audit_events
        WHERE target_type = 'user_session'
          AND target_id = $1::uuid
        ORDER BY created_at, action
      `,
      [sessionId],
    );
    expect(audit.rows.map((row) => row.action).sort()).toEqual([
      'authentication.succeeded',
      'session.revoked',
    ]);
  });

  it('conceals wrong, unknown, and inactive credentials behind the same 401', async () => {
    ({ fixture, app } = await createSessionApp());

    const wrong = await login(app, invalidRequestId, 'owner@example.test', 'wrong password');
    const unknown = await login(app, unknownRequestId, 'unknown@example.test', password);
    await fixture.database.query(
      `UPDATE dirizhor.app_users SET status = 'suspended' WHERE id = $1::uuid`,
      [ids.user],
    );
    const inactive = await login(app, inactiveRequestId, 'owner@example.test', password);

    for (const response of [wrong, unknown, inactive]) {
      expect(response.statusCode, response.body).toBe(401);
      expect(response.json()).toMatchObject({
        error: { code: 'unauthorized', message: 'Credentials are invalid.' },
      });
    }
    const sessions = await fixture.database.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM dirizhor.user_sessions`,
    );
    expect(sessions.rows[0]?.count).toBe('0');
    const failures = await fixture.database.query<{ metadata: string }>(
      `
        SELECT metadata::text AS metadata
        FROM dirizhor.audit_events
        WHERE action = 'authentication.failed'
      `,
    );
    expect(failures.rows).toHaveLength(3);
    expect(failures.rows.map((row) => row.metadata).join(' ')).not.toContain(password);
    expect(failures.rows.map((row) => row.metadata).join(' ')).not.toContain('owner@example.test');
  });

  it('accepts forwarded client IP only from an explicitly trusted proxy', async () => {
    ({ fixture, app } = await createSessionApp({ trustedProxies: ['127.0.0.1'] }));

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/sessions',
      remoteAddress: '127.0.0.1',
      headers: {
        'x-request-id': invalidRequestId,
        'x-forwarded-for': '203.0.113.42',
      },
      payload: { login: 'owner@example.test', password: 'wrong password' },
    });
    expect(response.statusCode, response.body).toBe(401);

    const failure = await fixture.database.query<{ ipAddress: string | null }>(
      `
        SELECT ip_address::text AS "ipAddress"
        FROM dirizhor.audit_events
        WHERE action = 'authentication.failed'
      `,
    );
    expect(failure.rows[0]?.ipAddress).toBe('203.0.113.42/32');
  });
});

interface SessionAppOptions {
  idGenerator?: IdGenerator;
  tokenGenerator?: SessionTokenGenerator;
  trustedProxies?: string[];
}

async function createSessionApp(options: SessionAppOptions = {}): Promise<{
  fixture: DirectorFixture;
  app: ReturnType<typeof buildDirectorApp>;
}> {
  const fixture = await createDirectorFixture();
  const secretHash = await hashLocalPassword(password, Buffer.alloc(16, 0x31));
  await fixture.database.query(
    `
      INSERT INTO dirizhor.user_identities (
        id, user_id, provider_code, provider_subject, secret_hash
      )
      VALUES ($1::uuid, $2::uuid, 'local', 'owner@example.test', $3)
    `,
    [identityId, ids.user, secretHash],
  );
  const sessionRepository = new PostgresSessionRepository(fixture.database);
  const sessionService = new SessionService({
    repository: sessionRepository,
    clock: fixture.clock,
    sessionTtlMs: 60 * 60 * 1_000,
    ...(options.idGenerator === undefined ? {} : { idGenerator: options.idGenerator }),
    ...(options.tokenGenerator === undefined ? {} : { tokenGenerator: options.tokenGenerator }),
  });
  const app = buildDirectorApp({
    service: fixture.service,
    ...(options.trustedProxies === undefined
      ? {}
      : { trustedProxies: options.trustedProxies }),
    authenticator: new StaticBearerAuthenticator({
      token: gatewayBearerToken,
      requireMutualTls: false,
    }),
    publicApi: {
      memoryIngest: new MemoryIngestService({
        repository: new PostgresMemoryIngestRepository(fixture.database),
        documentStore: fixture.documentStore,
      }),
      authenticator: new PostgresUserSessionAuthenticator({
        database: fixture.database,
        clock: fixture.clock,
      }),
      sessions: {
        service: sessionService,
        allowLocalPasswordIssuance: true,
      },
    },
  });
  return { fixture, app };
}

async function login(
  app: ReturnType<typeof buildDirectorApp>,
  requestId: string,
  loginValue: string,
  passwordValue: string,
) {
  return app.inject({
    method: 'POST',
    url: '/api/v1/auth/sessions',
    headers: { 'x-request-id': requestId },
    payload: { login: loginValue, password: passwordValue },
  });
}

class SequenceIds implements IdGenerator {
  constructor(private readonly values: string[]) {}

  next(): string {
    const next = this.values.shift();
    if (next === undefined) {
      throw new Error('No test ID remains.');
    }
    return next;
  }
}
