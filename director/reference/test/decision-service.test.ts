import { afterEach, describe, expect, it } from 'vitest';

import { DecisionService } from '../src/decision-service.js';
import type { IdGenerator } from '../src/memory-ports.js';
import { PostgresDecisionRepository } from '../src/postgres-decision-repository.js';
import {
  createDirectorFixture,
  ids,
  type DirectorFixture,
} from './helpers.js';

const decisionIds = {
  decision: '60000000-0000-4000-8000-000000000001',
  memory: '60000000-0000-4000-8000-000000000002',
  replayDecision: '60000000-0000-4000-8000-000000000003',
  replayMemory: '60000000-0000-4000-8000-000000000004',
  createRequest: '60000000-0000-4000-8000-000000000005',
  readRequest: '60000000-0000-4000-8000-000000000006',
  provenanceRequest: '60000000-0000-4000-8000-000000000007',
  viewer: '60000000-0000-4000-8000-000000000008',
  viewerAssignment: '60000000-0000-4000-8000-000000000009',
  deniedRequest: '60000000-0000-4000-8000-000000000010',
} as const;

describe('Decision service', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('creates a human decision and reconstructs exact source-version provenance', async () => {
    fixture = await createDirectorFixture();
    const service = decisionService(fixture, [
      decisionIds.decision,
      decisionIds.memory,
      decisionIds.replayDecision,
      decisionIds.replayMemory,
    ]);
    const input = {
      project_id: ids.project,
      title: '  Adopt immutable context  ',
      decision_text: '  Use exact document versions for every agent run.  ',
      rationale: '  Reproducible review evidence.  ',
      status: 'proposed' as const,
      sensitivity_level: 'internal' as const,
      relationships: [
        {
          target_type: 'agent_run' as const,
          target_id: ids.run,
          relation_type: 'derived_from' as const,
          description: '  Reviewed AI run  ',
        },
        {
          target_type: 'memory_object' as const,
          target_id: ids.memoryObject,
          relation_type: 'references' as const,
        },
      ],
    };

    const created = await service.createDecision(ids.user, decisionIds.createRequest, input);
    expect(created).toMatchObject({
      id: decisionIds.decision,
      memory_object_id: decisionIds.memory,
      title: 'Adopt immutable context',
      decision_text: 'Use exact document versions for every agent run.',
      rationale: 'Reproducible review evidence.',
      status: 'proposed',
      decided_by_user_id: null,
      decided_at: null,
      sensitivity_level: 'internal',
    });

    const replay = await service.createDecision(ids.user, decisionIds.createRequest, input);
    expect(replay.id).toBe(created.id);

    const read = await service.getDecision(ids.user, decisionIds.readRequest, created.id);
    expect(read).toEqual(created);

    const provenance = await service.getDecisionProvenance(
      ids.user,
      decisionIds.provenanceRequest,
      created.id,
    );
    expect(provenance.provenance_complete).toBe(true);
    expect(provenance.relationships).toHaveLength(2);
    expect(provenance.related_memory_objects).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: ids.memoryObject,
          type: 'document',
          title: 'Architecture',
        }),
      ]),
    );
    expect(provenance.agent_runs).toEqual([
      expect.objectContaining({
        id: ids.run,
        task_id: ids.task,
        context_set_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      }),
    ]);
    expect(provenance.source_versions).toEqual([
      expect.objectContaining({
        agent_run_id: ids.run,
        memory_object_id: ids.memoryObject,
        document_version_id: ids.documentVersion,
        version_number: 1,
        content_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        frozen_sensitivity_level: 'internal',
        current_sensitivity_level: 'internal',
      }),
    ]);
    expect(provenance.audit_events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          action: 'decision.created',
          target_type: 'decision',
          target_id: decisionIds.decision,
          request_id: decisionIds.createRequest,
        }),
      ]),
    );

    const evidence = await fixture.database.query<{
      memoryType: string;
      authorUserId: string;
      relationshipCount: number | string;
      authorizationDecisionId: string;
      auditDecisionId: string;
      metadata: Record<string, unknown>;
    }>(
      `
        SELECT
          memory.type AS "memoryType",
          memory.author_user_id::text AS "authorUserId",
          (SELECT count(*) FROM dirizhor.relationships WHERE source_id = decision_row.id) AS "relationshipCount",
          authz.id::text AS "authorizationDecisionId",
          audit.authorization_decision_id::text AS "auditDecisionId",
          audit.metadata
        FROM dirizhor.decisions AS decision_row
        JOIN dirizhor.memory_objects AS memory ON memory.id = decision_row.memory_object_id
        JOIN dirizhor.audit_events AS audit
          ON audit.target_type = 'decision' AND audit.target_id = decision_row.id
        JOIN dirizhor.authorization_decisions AS authz
          ON authz.id = audit.authorization_decision_id
        WHERE decision_row.id = $1::uuid AND audit.action = 'decision.created'
      `,
      [decisionIds.decision],
    );
    expect(evidence.rows).toEqual([
      {
        memoryType: 'decision',
        authorUserId: ids.user,
        relationshipCount: 2,
        authorizationDecisionId: evidence.rows[0]?.authorizationDecisionId,
        auditDecisionId: evidence.rows[0]?.authorizationDecisionId,
        metadata: {
          memory_object_id: decisionIds.memory,
          status: 'proposed',
          sensitivity_level: 'internal',
          relationship_count: 2,
        },
      },
    ]);
    expect(JSON.stringify(evidence.rows[0]?.metadata)).not.toContain('immutable context');
  });

  it('denies decision creation without decision.create and leaves no partial rows', async () => {
    fixture = await createDirectorFixture();
    await seedViewer(fixture);
    const service = decisionService(fixture, [decisionIds.decision, decisionIds.memory]);

    await expect(
      service.createDecision(decisionIds.viewer, decisionIds.deniedRequest, {
        project_id: ids.project,
        title: 'Denied decision',
        decision_text: 'Must not persist.',
      }),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'access_denied',
      details: { missing_permissions: ['decision.create'] },
    });

    const rows = await fixture.database.query<{ count: number | string }>(
      `SELECT count(*) AS count FROM dirizhor.decisions WHERE id = $1::uuid`,
      [decisionIds.decision],
    );
    expect(Number(rows.rows[0]?.count)).toBe(0);
  });
});

function decisionService(fixture: DirectorFixture, sequence: string[]): DecisionService {
  return new DecisionService({
    repository: new PostgresDecisionRepository(fixture.database),
    idGenerator: new SequenceIds(sequence),
  });
}

async function seedViewer(fixture: DirectorFixture): Promise<void> {
  await fixture.database.query(
    `
      INSERT INTO dirizhor.app_users (id, login, display_name, status)
      VALUES ($1::uuid, 'decision-viewer@example.test', 'Decision Viewer', 'active')
    `,
    [decisionIds.viewer],
  );
  await fixture.database.query(
    `
      INSERT INTO dirizhor.role_assignments (
        id, principal_type, principal_id, role_id, scope_type, scope_id, granted_by_user_id
      )
      SELECT
        $1::uuid, 'user', $2::uuid, role.id, 'project', $3::uuid, $4::uuid
      FROM dirizhor.roles AS role
      WHERE role.code = 'project_viewer'
    `,
    [decisionIds.viewerAssignment, decisionIds.viewer, ids.project, ids.user],
  );
}

class SequenceIds implements IdGenerator {
  constructor(private readonly values: string[]) {}

  next(): string {
    const value = this.values.shift();
    if (value === undefined) {
      throw new Error('Test ID sequence is exhausted.');
    }
    return value;
  }
}
