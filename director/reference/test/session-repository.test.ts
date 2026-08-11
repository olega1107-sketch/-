import { afterEach, describe, expect, it } from 'vitest';

import { sha256Text } from '../src/canonical.js';
import { dummyLocalPasswordHash } from '../src/local-password.js';
import { PostgresSessionRepository } from '../src/postgres-session-repository.js';
import { createDirectorFixture, ids, type DirectorFixture } from './helpers.js';

const identityId = '60000000-0000-4000-8000-000000000001';
const failedSessionId = '60000000-0000-4000-8000-000000000002';
const issuedSessionId = '60000000-0000-4000-8000-000000000003';
const issueConflictAuditId = '60000000-0000-4000-8000-000000000004';
const issueAuditId = '60000000-0000-4000-8000-000000000005';
const revokeConflictAuditId = '60000000-0000-4000-8000-000000000006';
const requestId = '60000000-0000-4000-8000-000000000007';

describe('PostgreSQL session repository transactions', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('rolls back session issuance and revocation when their audit insert fails', async () => {
    fixture = await createDirectorFixture();
    await fixture.database.query(
      `
        INSERT INTO dirizhor.user_identities (
          id, user_id, provider_code, provider_subject, secret_hash
        )
        VALUES ($1::uuid, $2::uuid, 'local', 'owner@example.test', $3)
      `,
      [identityId, ids.user, dummyLocalPasswordHash],
    );
    await reserveAuditId(fixture, issueConflictAuditId);
    const repository = new PostgresSessionRepository(fixture.database);

    await expect(
      repository.createSession(
        createCommand(failedSessionId, issueConflictAuditId, 'first-session-token'),
      ),
    ).rejects.toThrow();
    const rolledBackIssue = await fixture.database.query<{
      sessionCount: string;
      lastAuthenticatedAt: string | null;
    }>(
      `
        SELECT
          (SELECT count(*)::text FROM dirizhor.user_sessions) AS "sessionCount",
          last_authenticated_at AS "lastAuthenticatedAt"
        FROM dirizhor.user_identities
        WHERE id = $1::uuid
      `,
      [identityId],
    );
    expect(rolledBackIssue.rows[0]).toEqual({
      sessionCount: '0',
      lastAuthenticatedAt: null,
    });

    await expect(
      repository.createSession(createCommand(issuedSessionId, issueAuditId, 'second-session-token')),
    ).resolves.toMatchObject({ id: issuedSessionId });
    await reserveAuditId(fixture, revokeConflictAuditId);
    await expect(
      repository.revokeSession({
        auditEventId: revokeConflictAuditId,
        sessionId: issuedSessionId,
        userId: ids.user,
        requestId,
        revokedAt: '2030-01-01T10:30:00.000Z',
        ipAddress: null,
      }),
    ).rejects.toThrow();
    const rolledBackRevoke = await fixture.database.query<{ revokedAt: string | null }>(
      `
        SELECT revoked_at AS "revokedAt"
        FROM dirizhor.user_sessions
        WHERE id = $1::uuid
      `,
      [issuedSessionId],
    );
    expect(rolledBackRevoke.rows[0]?.revokedAt).toBeNull();
  });
});

function createCommand(sessionId: string, auditEventId: string, token: string) {
  return {
    sessionId,
    auditEventId,
    identityId,
    expectedSecretHash: dummyLocalPasswordHash,
    tokenHash: sha256Text(token),
    authenticationMethod: 'local_password' as const,
    createdAt: '2030-01-01T10:00:00.000Z',
    expiresAt: '2030-01-01T11:00:00.000Z',
    requestId,
    ipAddress: null,
    userAgent: null,
  };
}

async function reserveAuditId(fixture: DirectorFixture, auditEventId: string): Promise<void> {
  await fixture.database.query(
    `
      INSERT INTO dirizhor.audit_events (
        id, actor_type, action, request_id
      )
      VALUES ($1::uuid, 'system', 'fixture.reserved', $2::uuid)
    `,
    [auditEventId, requestId],
  );
}
