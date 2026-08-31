import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  executeAuthorized,
  type AuthorizationDenial,
} from '../src/authorization-audit.js';
import { DirectorProtocolError } from '../src/errors.js';
import type { IdGenerator } from '../src/memory-ports.js';
import { PostgresAuthorizationAuditRecorder } from '../src/postgres-authorization-audit-recorder.js';
import { createDirectorFixture, ids, type DirectorFixture } from './helpers.js';

const decisionId = '70000000-0000-4000-8000-000000000001';
const auditId = '70000000-0000-4000-8000-000000000002';
const rolledBackDecisionId = '70000000-0000-4000-8000-000000000003';
const conflictAuditId = '70000000-0000-4000-8000-000000000004';
const requestId = '70000000-0000-4000-8000-000000000005';

describe('PostgreSQL authorization denial audit', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('links deny and access.denied atomically and rolls both back on audit failure', async () => {
    fixture = await createDirectorFixture();
    const recorder = new PostgresAuthorizationAuditRecorder({
      database: fixture.database,
      clock: fixture.clock,
      idGenerator: new SequenceIds([decisionId, auditId]),
    });
    await recorder.recordDenied(denial());

    const linked = await fixture.database.query<{
      decision: string;
      reasonCodes: string[];
      obligations: string[];
      auditAction: string;
      authorizationDecisionId: string;
    }>(
      `
        SELECT
          decision.decision,
          decision.reason_codes AS "reasonCodes",
          decision.obligations AS obligations,
          audit.action AS "auditAction",
          audit.authorization_decision_id::text AS "authorizationDecisionId"
        FROM dirizhor.authorization_decisions AS decision
        JOIN dirizhor.audit_events AS audit
          ON audit.authorization_decision_id = decision.id
        WHERE decision.id = $1::uuid
      `,
      [decisionId],
    );
    expect(linked.rows[0]).toEqual({
      decision: 'deny',
      reasonCodes: ['permission_missing'],
      obligations: ['audit_access_decision'],
      auditAction: 'access.denied',
      authorizationDecisionId: decisionId,
    });

    await fixture.database.query(
      `
        INSERT INTO dirizhor.audit_events (id, actor_type, action, request_id)
        VALUES ($1::uuid, 'system', 'fixture.reserved', $2::uuid)
      `,
      [conflictAuditId, requestId],
    );
    const conflictingRecorder = new PostgresAuthorizationAuditRecorder({
      database: fixture.database,
      clock: fixture.clock,
      idGenerator: new SequenceIds([rolledBackDecisionId, conflictAuditId]),
    });
    await expect(conflictingRecorder.recordDenied(denial())).rejects.toThrow();
    const rolledBack = await fixture.database.query<{ count: string }>(
      `
        SELECT count(*)::text AS count
        FROM dirizhor.authorization_decisions
        WHERE id = $1::uuid
      `,
      [rolledBackDecisionId],
    );
    expect(rolledBack.rows[0]?.count).toBe('0');
  });

  it('enforces a non-empty reason for every decision at the SQL boundary', async () => {
    fixture = await createDirectorFixture();
    await expect(
      fixture.database.query(
        `
          INSERT INTO dirizhor.authorization_decisions (
            principal_type,
            principal_id,
            action,
            resource_type,
            resource_id,
            project_id,
            decision,
            reason_codes,
            request_id
          )
          VALUES (
            'user', $1::uuid, 'task.create', 'project', $2::uuid,
            $2::uuid, 'deny', '{}'::text[], $3::uuid
          )
        `,
        [ids.user, ids.project, requestId],
      ),
    ).rejects.toThrow();
    await expect(
      fixture.database.query(
        `
          INSERT INTO dirizhor.authorization_decisions (
            principal_type,
            principal_id,
            action,
            resource_type,
            resource_id,
            project_id,
            decision,
            reason_codes,
            request_id
          )
          VALUES (
            'user', $1::uuid, 'task.create', 'project', $2::uuid,
            $2::uuid, 'allow', '{}'::text[], $3::uuid
          )
        `,
        [ids.user, ids.project, requestId],
      ),
    ).rejects.toThrow();
  });

  it('fails closed when a denial cannot be audited', async () => {
    await expect(
      executeAuthorized(
        {
          recordDenied: async () => {
            throw new Error('authorization audit unavailable');
          },
        },
        {
          actorUserId: ids.user,
          action: 'task.create',
          resourceType: 'project',
          resourceId: ids.project,
          projectId: ids.project,
          requestId,
        },
        async () => {
          throw new DirectorProtocolError(
            403,
            'access_denied',
            'The user lacks required project permissions.',
            false,
            { missing_permissions: ['task.create'] },
          );
        },
      ),
    ).rejects.toThrow('authorization audit unavailable');
  });

  it('reports an audit write failure without changing fail-closed behavior', async () => {
    fixture = await createDirectorFixture();
    const onFailure = vi.fn();
    await fixture.database.query(
      `
        INSERT INTO dirizhor.audit_events (id, actor_type, action, request_id)
        VALUES ($1::uuid, 'system', 'fixture.reserved', $2::uuid)
      `,
      [conflictAuditId, requestId],
    );
    const recorder = new PostgresAuthorizationAuditRecorder({
      database: fixture.database,
      clock: fixture.clock,
      idGenerator: new SequenceIds([rolledBackDecisionId, conflictAuditId]),
      onFailure,
    });

    await expect(recorder.recordDenied(denial())).rejects.toThrow();
    expect(onFailure).toHaveBeenCalledTimes(1);
  });
});

function denial(): AuthorizationDenial {
  return {
    actorUserId: ids.user,
    principalUserId: ids.user,
    action: 'task.create',
    resourceType: 'project',
    resourceId: ids.project,
    projectId: ids.project,
    requestId,
    reasonCodes: ['permission_missing'],
    missingPermissions: ['task.create'],
    responseConcealed: false,
    responseStatusCode: 403,
    responseCode: 'access_denied',
  };
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
