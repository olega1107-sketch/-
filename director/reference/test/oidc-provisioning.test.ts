import { afterEach, describe, expect, it } from 'vitest';

import {
  OidcAccessRevoker,
  parseOidcAccessRevocationInput,
} from '../src/oidc-access-revocation.js';
import { sha256Text } from '../src/canonical.js';
import {
  OidcProvisioner,
  OidcProvisioningError,
  parseOidcProvisioningInput,
} from '../src/oidc-provisioning.js';
import {
  createDirectorFixture,
  ids,
  type DirectorFixture,
} from './helpers.js';

const requestId = '71000000-0000-4000-8000-000000000001';
const identityId = '71000000-0000-4000-8000-000000000002';
const secondIdentityId = '71000000-0000-4000-8000-000000000003';
const auditId = '71000000-0000-4000-8000-000000000004';
const newUserId = '71000000-0000-4000-8000-000000000005';
const newIdentityId = '71000000-0000-4000-8000-000000000006';
const sessionId = '71000000-0000-4000-8000-000000000008';
const revocationAuditId = '71000000-0000-4000-8000-000000000009';
const providerSubject = 'corporate-directory-subject-42';

describe('OIDC identity provisioning', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('attaches an exact identity atomically, audits without sub, and retries unchanged', async () => {
    fixture = await createDirectorFixture();
    const provisioner = createProvisioner(fixture);
    const input = {
      operation: 'attach_identity' as const,
      requestId,
      userId: ids.user,
      identityId,
      login: 'owner@example.test',
      providerSubject,
    };

    await expect(provisioner.provision(input)).resolves.toEqual({
      outcome: 'created',
      userId: ids.user,
      identityId,
    });
    await expect(provisioner.provision(input)).resolves.toEqual({
      outcome: 'unchanged',
      userId: ids.user,
      identityId,
    });

    const identity = await fixture.database.query<{
      providerCode: string;
      providerIssuer: string;
      providerSubject: string;
    }>(
      `
        SELECT
          provider_code AS "providerCode",
          provider_issuer AS "providerIssuer",
          provider_subject AS "providerSubject"
        FROM dirizhor.user_identities
        WHERE id = $1::uuid
      `,
      [identityId],
    );
    expect(identity.rows[0]).toEqual({
      providerCode: 'corporate',
      providerIssuer: 'https://idp.example/',
      providerSubject,
    });
    const audit = await fixture.database.query<{ metadata: string; count: string }>(
      `
        SELECT metadata::text AS metadata, count(*) OVER ()::text AS count
        FROM dirizhor.audit_events
        WHERE action = 'identity.provisioned'
      `,
    );
    expect(audit.rows[0]?.count).toBe('1');
    expect(audit.rows[0]?.metadata).toContain('corporate');
    expect(audit.rows[0]?.metadata).not.toContain(providerSubject);
  });

  it('creates a new active user and identity with operator-supplied stable IDs', async () => {
    fixture = await createDirectorFixture();
    const result = await createProvisioner(fixture).provision({
      operation: 'create_user',
      requestId,
      userId: newUserId,
      identityId: newIdentityId,
      login: 'new.user@example.test',
      displayName: 'New User',
      providerSubject: 'new-user-subject',
    });

    expect(result.outcome).toBe('created');
    const user = await fixture.database.query<{ status: string; identityCount: string }>(
      `
        SELECT app_user.status, count(identity.id)::text AS "identityCount"
        FROM dirizhor.app_users AS app_user
        LEFT JOIN dirizhor.user_identities AS identity
          ON identity.user_id = app_user.id
        WHERE app_user.id = $1::uuid
        GROUP BY app_user.status
      `,
      [newUserId],
    );
    expect(user.rows[0]).toEqual({ status: 'active', identityCount: '1' });
  });

  it('refuses an ambiguous login or a second identity for the same provider', async () => {
    fixture = await createDirectorFixture();
    const provisioner = createProvisioner(fixture);
    await expect(
      provisioner.provision({
        operation: 'attach_identity',
        requestId,
        userId: ids.user,
        identityId,
        login: 'wrong@example.test',
        providerSubject,
      }),
    ).rejects.toBeInstanceOf(OidcProvisioningError);

    await provisioner.provision({
      operation: 'attach_identity',
      requestId,
      userId: ids.user,
      identityId,
      login: 'owner@example.test',
      providerSubject,
    });
    await expect(
      provisioner.provision({
        operation: 'attach_identity',
        requestId: '71000000-0000-4000-8000-000000000007',
        userId: ids.user,
        identityId: secondIdentityId,
        login: 'owner@example.test',
        providerSubject: 'different-subject',
      }),
    ).rejects.toMatchObject({ code: 'conflict' });
  });

  it('parses only the documented stdin JSON shape', () => {
    expect(
      parseOidcProvisioningInput({
        operation: 'attach_identity',
        request_id: requestId,
        user_id: ids.user,
        identity_id: identityId,
        login: ' owner@example.test ',
        provider_subject: providerSubject,
      }),
    ).toMatchObject({ login: 'owner@example.test', providerSubject });
    expect(() =>
      parseOidcProvisioningInput({
        operation: 'attach_identity',
        request_id: requestId,
        user_id: ids.user,
        identity_id: identityId,
        login: 'owner@example.test',
        provider_subject: providerSubject,
        provider_issuer: 'https://attacker.example/',
      }),
    ).toThrow(OidcProvisioningError);
  });

  it('disables a user and revokes every active Director session atomically', async () => {
    fixture = await createDirectorFixture();
    await fixture.database.query(
      `
        INSERT INTO dirizhor.user_sessions (
          id, user_id, session_token_hash, authentication_method,
          created_at, expires_at
        )
        VALUES (
          $1::uuid, $2::uuid, $3, 'oidc:corporate',
          '2030-01-01T09:00:00.000Z'::timestamptz,
          '2030-01-01T11:00:00.000Z'::timestamptz
        )
      `,
      [sessionId, ids.user, sha256Text('operator-revocation-session')],
    );
    const revoker = new OidcAccessRevoker(fixture.database, {
      clock: fixture.clock,
      idGenerator: { next: () => revocationAuditId },
    });
    const input = {
      requestId,
      userId: ids.user,
      login: 'owner@example.test',
    };

    await expect(revoker.revoke(input)).resolves.toEqual({
      outcome: 'revoked',
      userId: ids.user,
      revokedSessionCount: 1,
    });
    await expect(revoker.revoke(input)).resolves.toEqual({
      outcome: 'unchanged',
      userId: ids.user,
      revokedSessionCount: 0,
    });
    const state = await fixture.database.query<{
      status: string;
      revokedAt: string | null;
      auditCount: string;
    }>(
      `
        SELECT
          app_user.status,
          session.revoked_at::text AS "revokedAt",
          (
            SELECT count(*)::text
            FROM dirizhor.audit_events
            WHERE action = 'user.access_revoked'
          ) AS "auditCount"
        FROM dirizhor.app_users AS app_user
        JOIN dirizhor.user_sessions AS session ON session.user_id = app_user.id
        WHERE app_user.id = $1::uuid
      `,
      [ids.user],
    );
    expect(state.rows[0]).toMatchObject({ status: 'disabled', auditCount: '1' });
    expect(state.rows[0]?.revokedAt).not.toBeNull();
  });

  it('parses revocation input without accepting implicit identity selectors', () => {
    expect(
      parseOidcAccessRevocationInput({
        request_id: requestId,
        user_id: ids.user,
        login: ' owner@example.test ',
      }),
    ).toEqual({ requestId, userId: ids.user, login: 'owner@example.test' });
    expect(() =>
      parseOidcAccessRevocationInput({
        request_id: requestId,
        user_id: ids.user,
        login: 'owner@example.test',
        email: 'owner@example.test',
      }),
    ).toThrow();
  });
});

function createProvisioner(fixture: DirectorFixture): OidcProvisioner {
  return new OidcProvisioner({
    database: fixture.database,
    providerCode: 'corporate',
    issuerUrl: 'https://idp.example/',
    clock: fixture.clock,
    idGenerator: { next: () => auditId },
  });
}
