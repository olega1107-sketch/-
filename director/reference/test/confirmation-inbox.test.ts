import { afterEach, describe, expect, it } from 'vitest';

import { sha256Text } from '../src/canonical.js';
import { ConfirmationService } from '../src/confirmation-service.js';
import { PostgresConfirmationRepository } from '../src/postgres-confirmation-repository.js';
import {
  ids,
  prepareDirectorFixture,
  type PreparedDirectorFixture,
} from './helpers.js';

const newerConfirmationId = '61000000-0000-4000-8000-000000000001';
const olderConfirmationId = '61000000-0000-4000-8000-000000000002';
const newerDecisionId = '61000000-0000-4000-8000-000000000003';
const olderDecisionId = '61000000-0000-4000-8000-000000000004';
const firstRequestId = '61000000-0000-4000-8000-000000000005';
const secondRequestId = '61000000-0000-4000-8000-000000000006';
const otherUserId = '61000000-0000-4000-8000-000000000007';
const otherProjectId = '61000000-0000-4000-8000-000000000008';

describe('Confirmation inbox', () => {
  let fixture: PreparedDirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('paginates a project queue and records metadata-only allow audits', async () => {
    fixture = await prepareDirectorFixture();
    await seedConfirmations(fixture);
    const confirmations = confirmationService(fixture);

    const first = await confirmations.listConfirmations(ids.user, firstRequestId, {
      project_id: ids.project,
      limit: 1,
    });
    expect(first.items).toHaveLength(1);
    expect(first.items[0]).toMatchObject({
      id: newerConfirmationId,
      project_id: ids.project,
      status: 'pending',
    });
    expect(first.items[0]).not.toHaveProperty('frozen_payload');
    expect(first.next_cursor).toEqual(expect.any(String));

    const second = await confirmations.listConfirmations(ids.user, secondRequestId, {
      project_id: ids.project,
      limit: 1,
      cursor: requiredCursor(first.next_cursor),
    });
    expect(second.items.map((item) => item.id)).toEqual([olderConfirmationId]);
    expect(second.next_cursor).toBeNull();

    await expect(
      confirmations.listConfirmations(ids.user, secondRequestId, {
        project_id: ids.project,
        status: 'rejected',
        limit: 1,
        cursor: requiredCursor(first.next_cursor),
      }),
    ).rejects.toMatchObject({
      statusCode: 400,
      code: 'validation_error',
    });
    await expect(
      confirmations.listConfirmations(otherUserId, secondRequestId, {
        project_id: ids.project,
        limit: 1,
        cursor: requiredCursor(first.next_cursor),
      }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'validation_error' });
    await expect(
      confirmations.listConfirmations(ids.user, secondRequestId, {
        project_id: otherProjectId,
        limit: 1,
        cursor: requiredCursor(first.next_cursor),
      }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'validation_error' });
    await expect(
      confirmations.listConfirmations(ids.user, secondRequestId, {
        project_id: otherProjectId,
      }),
    ).rejects.toMatchObject({
      statusCode: 404,
      code: 'not_found',
      details: { resource: 'project', id: otherProjectId },
    });

    const authorization = await fixture.database.query<{
      decisionId: string;
      auditDecisionId: string;
      resourceType: string;
      metadata: Record<string, unknown>;
    }>(
      `
        SELECT
          decision.id::text AS "decisionId",
          audit.authorization_decision_id::text AS "auditDecisionId",
          decision.resource_type AS "resourceType",
          audit.metadata
        FROM dirizhor.authorization_decisions AS decision
        JOIN dirizhor.audit_events AS audit
          ON audit.authorization_decision_id = decision.id
        WHERE decision.request_id IN ($1::uuid, $2::uuid)
          AND decision.action = 'confirmation.read'
        ORDER BY CASE decision.request_id WHEN $1::uuid THEN 1 ELSE 2 END
      `,
      [firstRequestId, secondRequestId],
    );
    expect(authorization.rows).toHaveLength(2);
    expect(
      authorization.rows.every(
        (row) => row.decisionId === row.auditDecisionId && row.resourceType === 'project',
      ),
    ).toBe(true);
    expect(authorization.rows.map((row) => row.metadata)).toEqual([
      expect.objectContaining({
        authorized_action: 'confirmation.read',
        view: 'confirmation_inbox',
        status: 'pending',
        returned_count: 1,
        page_limit: 1,
        continued: false,
      }),
      expect.objectContaining({
        authorized_action: 'confirmation.read',
        view: 'confirmation_inbox',
        status: 'pending',
        returned_count: 1,
        page_limit: 1,
        continued: true,
      }),
    ]);
    expect(JSON.stringify(authorization.rows)).not.toContain('secret_context');
  });
});

function confirmationService(fixture: PreparedDirectorFixture): ConfirmationService {
  return new ConfirmationService({
    repository: new PostgresConfirmationRepository(fixture.database),
    gateway: { dispatch: async () => undefined },
    capabilityTokens: { issue: () => 'unused-capability' },
    clock: fixture.clock,
  });
}

async function seedConfirmations(fixture: PreparedDirectorFixture): Promise<void> {
  const hashes = [sha256Text('newer'), sha256Text('older')];
  await fixture.database.query(
    `
      INSERT INTO dirizhor.authorization_decisions (
        id, principal_type, principal_id, action, resource_type, resource_id,
        project_id, decision, reason_codes, obligations, request_id, created_at
      ) VALUES
        ($1::uuid, 'user', $2::uuid, 'agent_context.share', 'agent_run', $3::uuid,
         $4::uuid, 'require_confirmation', ARRAY['policy_confirmation'], '[]'::jsonb,
         $5::uuid, '2030-01-01T09:58:00Z'),
        ($6::uuid, 'user', $2::uuid, 'agent_context.share', 'agent_run', $7::uuid,
         $4::uuid, 'require_confirmation', ARRAY['policy_confirmation'], '[]'::jsonb,
         $8::uuid, '2030-01-01T09:57:00Z')
    `,
    [
      newerDecisionId,
      ids.user,
      newerConfirmationId,
      ids.project,
      firstRequestId,
      olderDecisionId,
      olderConfirmationId,
      secondRequestId,
    ],
  );
  await fixture.database.query(
    `
      INSERT INTO dirizhor.confirmations (
        id, operation, target_type, target_id, project_id, requested_by_user_id,
        authorization_decision_id, request_id, status, frozen_payload, payload_hash,
        summary, created_at, expires_at
      ) VALUES
        ($1::uuid, 'agent_context_share', 'agent_run', $1::uuid, $2::uuid, $3::uuid,
         $4::uuid, $5::uuid, 'pending', '{"marker":"secret_context"}'::jsonb, $6,
         'Newer pending operation', '2030-01-01T09:59:00Z', '2030-01-01T11:00:00Z'),
        ($7::uuid, 'agent_context_share', 'agent_run', $7::uuid, $2::uuid, $3::uuid,
         $8::uuid, $9::uuid, 'pending', '{"marker":"secret_context"}'::jsonb, $10,
         'Older pending operation', '2030-01-01T09:58:00Z', '2030-01-01T11:00:00Z')
    `,
    [
      newerConfirmationId,
      ids.project,
      ids.user,
      newerDecisionId,
      firstRequestId,
      hashes[0],
      olderConfirmationId,
      olderDecisionId,
      secondRequestId,
      hashes[1],
    ],
  );
}

function requiredCursor(cursor: string | null): string {
  if (cursor === null) {
    throw new Error('Expected another confirmation page.');
  }
  return cursor;
}
