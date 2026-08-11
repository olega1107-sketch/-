import { afterEach, describe, expect, it } from 'vitest';

import { PostgresPublicQueryRepository } from '../src/postgres-public-query-repository.js';
import { PublicQueryService } from '../src/public-query-service.js';
import type { TaskTimelineItem } from '../src/task-protocol.js';
import {
  createDirectorFixture,
  ids,
  type DirectorFixture,
} from './helpers.js';

const queryIds = {
  viewer: '50000000-0000-4000-8000-000000000001',
  viewerAssignment: '50000000-0000-4000-8000-000000000002',
  metadataReader: '50000000-0000-4000-8000-000000000003',
  metadataRole: '50000000-0000-4000-8000-000000000004',
  metadataAssignment: '50000000-0000-4000-8000-000000000005',
  publicMemory: '50000000-0000-4000-8000-000000000010',
  internalMemory: '50000000-0000-4000-8000-000000000011',
  confidentialMemory: '50000000-0000-4000-8000-000000000012',
  restrictedMemory: '50000000-0000-4000-8000-000000000013',
  relatedPublicMemory: '50000000-0000-4000-8000-000000000014',
  relatedHiddenMemory: '50000000-0000-4000-8000-000000000015',
  relationship: '50000000-0000-4000-8000-000000000016',
  getRequest: '50000000-0000-4000-8000-000000000020',
  searchRequest: '50000000-0000-4000-8000-000000000021',
  contextSearchRequest: '50000000-0000-4000-8000-000000000022',
  timelineRequest: '50000000-0000-4000-8000-000000000023',
  visibleResultMemory: '50000000-0000-4000-8000-000000000030',
  hiddenResultMemory: '50000000-0000-4000-8000-000000000031',
  hiddenRun: '50000000-0000-4000-8000-000000000032',
  visibleResultRecord: '50000000-0000-4000-8000-000000000033',
  hiddenResultRecord: '50000000-0000-4000-8000-000000000034',
  visibleDecisionMemory: '50000000-0000-4000-8000-000000000035',
  visibleDecision: '50000000-0000-4000-8000-000000000036',
  hiddenDecisionMemory: '50000000-0000-4000-8000-000000000037',
  hiddenDecision: '50000000-0000-4000-8000-000000000038',
  visibleDecisionRelation: '50000000-0000-4000-8000-000000000039',
  hiddenDecisionRelation: '50000000-0000-4000-8000-000000000040',
  hiddenRunOrigin: '50000000-0000-4000-8000-000000000041',
  taskAudit: '50000000-0000-4000-8000-000000000042',
  hiddenAudit: '50000000-0000-4000-8000-000000000043',
  hiddenRunContext: '50000000-0000-4000-8000-000000000044',
  hiddenContextMemory: '50000000-0000-4000-8000-000000000045',
  hiddenContextVersion: '50000000-0000-4000-8000-000000000046',
  secondProject: '50000000-0000-4000-8000-000000000047',
  projectListRequest: '50000000-0000-4000-8000-000000000048',
} as const;

describe('Public query service', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('lists only readable projects with scoped keyset pagination and audit linkage', async () => {
    fixture = await createDirectorFixture();
    await fixture.database.query(
      `UPDATE dirizhor.projects SET updated_at = '2030-01-01T09:00:00Z' WHERE id = $1::uuid`,
      [ids.project],
    );
    await fixture.database.query(
      `
        INSERT INTO dirizhor.projects (
          id, title, description, owner_user_id, created_at, updated_at
        ) VALUES (
          $1::uuid, 'Second workspace', 'Secondary project', $2::uuid,
          '2030-01-01T09:30:00Z', '2030-01-01T09:30:00Z'
        )
      `,
      [queryIds.secondProject, ids.user],
    );
    const service = queryService(fixture);

    const first = await service.listProjects(ids.user, queryIds.projectListRequest, { limit: 1 });
    expect(first.items.map((project) => project.id)).toEqual([queryIds.secondProject]);
    expect(first.next_cursor).toEqual(expect.any(String));
    const second = await service.listProjects(ids.user, queryIds.projectListRequest, {
      limit: 1,
      cursor: requiredCursor(first.next_cursor),
    });
    expect(second.items.map((project) => project.id)).toEqual([ids.project]);
    expect(second.next_cursor).toBeNull();

    await expect(
      service.listProjects(queryIds.viewer, queryIds.projectListRequest, {
        limit: 1,
        cursor: requiredCursor(first.next_cursor),
      }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'validation_error' });

    const authorization = await fixture.database.query<{
      decisionId: string;
      auditDecisionId: string;
      metadata: Record<string, unknown>;
    }>(
      `
        SELECT
          decision.id::text AS "decisionId",
          audit.authorization_decision_id::text AS "auditDecisionId",
          audit.metadata
        FROM dirizhor.authorization_decisions AS decision
        JOIN dirizhor.audit_events AS audit
          ON audit.authorization_decision_id = decision.id
        WHERE decision.request_id = $1::uuid
          AND decision.action = 'project.read'
          AND decision.resource_type = 'project_collection'
        ORDER BY decision.created_at, decision.id
      `,
      [queryIds.projectListRequest],
    );
    expect(authorization.rows).toHaveLength(2);
    expect(authorization.rows.every((row) => row.decisionId === row.auditDecisionId)).toBe(true);
    expect(JSON.stringify(authorization.rows.map((row) => row.metadata))).not.toContain(
      'Second workspace',
    );
  });

  it('filters sensitive registry cards before keyset pagination and binds cursors', async () => {
    fixture = await createDirectorFixture();
    await grantViewer(fixture);
    await seedRegistryCards(fixture);
    const service = queryService(fixture);

    const first = await service.searchMemoryObjects(queryIds.viewer, queryIds.searchRequest, {
      project_id: ids.project,
      q: 'registry',
      limit: 1,
    });
    expect(first.items).toHaveLength(1);
    expect(first.next_cursor).not.toBeNull();

    const second = await service.searchMemoryObjects(queryIds.viewer, queryIds.searchRequest, {
      project_id: ids.project,
      q: 'registry',
      limit: 1,
      cursor: requiredCursor(first.next_cursor),
    });
    expect(second.next_cursor).toBeNull();
    expect(new Set([...first.items, ...second.items].map((item) => item.id))).toEqual(
      new Set([queryIds.publicMemory, queryIds.internalMemory]),
    );

    await expect(
      service.searchMemoryObjects(queryIds.viewer, queryIds.searchRequest, {
        project_id: ids.project,
        q: 'different query',
        limit: 1,
        cursor: requiredCursor(first.next_cursor),
      }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'validation_error' });

    const authorization = await fixture.database.query<{
      decision: string;
      reasonCodes: string[];
      auditDecisionId: string;
      decisionId: string;
      metadata: Record<string, unknown>;
    }>(
      `
        SELECT
          decision.decision,
          decision.reason_codes AS "reasonCodes",
          decision.id::text AS "decisionId",
          audit.authorization_decision_id::text AS "auditDecisionId",
          audit.metadata
        FROM dirizhor.authorization_decisions AS decision
        JOIN dirizhor.audit_events AS audit
          ON audit.authorization_decision_id = decision.id
        WHERE decision.request_id = $1::uuid
          AND decision.principal_id = $2::uuid
          AND decision.action = 'memory_object.search'
          AND audit.action = 'access.allowed'
        ORDER BY decision.created_at, decision.id
      `,
      [queryIds.searchRequest, queryIds.viewer],
    );
    expect(authorization.rows).toHaveLength(2);
    expect(authorization.rows.every((row) => row.decisionId === row.auditDecisionId)).toBe(true);
    expect(authorization.rows.every((row) => row.decision === 'allow')).toBe(true);
    expect(authorization.rows.every((row) => row.reasonCodes[0] === 'permissions_satisfied')).toBe(
      true,
    );
    expect(JSON.stringify(authorization.rows.map((row) => row.metadata))).not.toContain('registry');
  });

  it('does not match a visible card through a relationship to a hidden card', async () => {
    fixture = await createDirectorFixture();
    await grantViewer(fixture);
    await seedRegistryCards(fixture);
    const service = queryService(fixture);

    const viewer = await service.searchMemoryObjects(
      queryIds.viewer,
      queryIds.searchRequest,
      {
        project_id: ids.project,
        q: 'quantum secret',
      },
    );
    expect(viewer.items).toEqual([]);

    const owner = await service.searchMemoryObjects(ids.user, queryIds.searchRequest, {
      project_id: ids.project,
      q: 'quantum secret',
    });
    expect(owner.items.map((item) => item.id)).toEqual(
      expect.arrayContaining([queryIds.relatedPublicMemory, queryIds.relatedHiddenMemory]),
    );
  });

  it('derives task context from the task project and applies type and visibility filters', async () => {
    fixture = await createDirectorFixture();
    await grantViewer(fixture);
    await seedRegistryCards(fixture);
    const service = queryService(fixture);

    const result = await service.searchTaskContext(
      queryIds.viewer,
      queryIds.contextSearchRequest,
      ids.task,
      {
        query: 'registry',
        types: ['note'],
        limit: 10,
      },
    );

    expect(result.task_id).toBe(ids.task);
    expect(result.candidates.map((candidate) => candidate.memory_object_id)).toEqual(
      expect.arrayContaining([queryIds.publicMemory, queryIds.internalMemory]),
    );
    expect(result.candidates).toHaveLength(2);
    expect(result.candidates.every((candidate) => candidate.reason.length > 0)).toBe(true);
    const audit = await fixture.database.query<{
      decision: string;
      auditDecisionId: string;
      decisionId: string;
      metadata: Record<string, unknown>;
    }>(
      `
        SELECT
          decision.decision,
          decision.id::text AS "decisionId",
          audit.authorization_decision_id::text AS "auditDecisionId",
          audit.metadata
        FROM dirizhor.authorization_decisions AS decision
        JOIN dirizhor.audit_events AS audit
          ON audit.authorization_decision_id = decision.id
        WHERE decision.request_id = $1::uuid
          AND decision.resource_type = 'task'
          AND decision.resource_id = $2::uuid
      `,
      [queryIds.contextSearchRequest, ids.task],
    );
    expect(audit.rows).toEqual([
      {
        decision: 'allow',
        decisionId: audit.rows[0]?.decisionId,
        auditDecisionId: audit.rows[0]?.decisionId,
        metadata: {
          authorized_action: 'memory_object.search',
          page_limit: 10,
          query_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
          returned_count: 2,
        },
      },
    ]);
    expect(JSON.stringify(audit.rows[0]?.metadata)).not.toContain('registry');
  });

  it('omits the current version without document_version.read and audits an internal read', async () => {
    fixture = await createDirectorFixture();
    await grantMetadataReader(fixture);
    const service = queryService(fixture);

    const memory = await service.getMemoryObject(
      queryIds.metadataReader,
      queryIds.getRequest,
      ids.memoryObject,
    );

    expect(memory.current_version_id).toBe(ids.documentVersion);
    expect(memory).not.toHaveProperty('current_version');
    const audits = await fixture.database.query<{
      decision: string;
      reasonCodes: string[];
      decisionId: string;
      auditDecisionId: string;
      metadata: Record<string, unknown>;
    }>(
      `
        SELECT
          decision.decision,
          decision.reason_codes AS "reasonCodes",
          decision.id::text AS "decisionId",
          audit.authorization_decision_id::text AS "auditDecisionId",
          audit.metadata
        FROM dirizhor.audit_events AS audit
        JOIN dirizhor.authorization_decisions AS decision
          ON decision.id = audit.authorization_decision_id
        WHERE audit.action = 'memory_object.read'
          AND audit.target_id = $1::uuid
          AND audit.actor_id = $2::uuid
      `,
      [ids.memoryObject, queryIds.metadataReader],
    );
    expect(audits.rows).toHaveLength(1);
    expect(audits.rows[0]).toEqual({
      decision: 'allow',
      reasonCodes: ['permissions_satisfied'],
      decisionId: audits.rows[0]?.decisionId,
      auditDecisionId: audits.rows[0]?.decisionId,
      metadata: { sensitivity_level: 'internal', included_current_version: false },
    });
  });

  it('rejects direct sensitive reads without the conditional permission', async () => {
    fixture = await createDirectorFixture();
    await grantViewer(fixture);
    await seedRegistryCards(fixture);
    const service = queryService(fixture);

    await expect(
      service.getMemoryObject(
        queryIds.viewer,
        queryIds.getRequest,
        queryIds.confidentialMemory,
      ),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'access_denied',
      details: { missing_permissions: ['memory_object.read_confidential'] },
    });
  });

  it('paginates a task timeline and hides sensitive results, decisions, and their audits', async () => {
    fixture = await createDirectorFixture();
    await grantViewer(fixture);
    await seedTimeline(fixture);
    const service = queryService(fixture);

    const viewerItems = await collectTimeline(service, queryIds.viewer);
    expect(viewerItems.map((item) => item.resource_id)).toEqual(
      expect.arrayContaining([
        ids.run,
        queryIds.hiddenRun,
        queryIds.visibleResultMemory,
        queryIds.visibleDecision,
        queryIds.taskAudit,
      ]),
    );
    expect(viewerItems.map((item) => item.resource_id)).not.toEqual(
      expect.arrayContaining([
        queryIds.hiddenResultMemory,
        queryIds.hiddenDecision,
        queryIds.hiddenAudit,
      ]),
    );

    const ownerItems = await collectTimeline(service, ids.user);
    expect(ownerItems.map((item) => item.resource_id)).toEqual(
      expect.arrayContaining([
        queryIds.hiddenResultMemory,
        queryIds.hiddenDecision,
        queryIds.hiddenAudit,
      ]),
    );
    expect([...viewerItems, ...ownerItems].map((item) => item.summary)).not.toContain(
      'Audit event: access.allowed',
    );
  });
});

function queryService(fixture: DirectorFixture): PublicQueryService {
  return new PublicQueryService({
    repository: new PostgresPublicQueryRepository(fixture.database),
  });
}

async function grantViewer(fixture: DirectorFixture): Promise<void> {
  await fixture.database.transaction(async (transaction) => {
    await transaction.query(
      `
        INSERT INTO dirizhor.app_users (id, login, display_name, status)
        VALUES ($1::uuid, 'query-viewer@example.test', 'Query Viewer', 'active')
      `,
      [queryIds.viewer],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.role_assignments (
          id, principal_type, principal_id, role_id,
          scope_type, scope_id, granted_by_user_id
        )
        SELECT
          $1::uuid, 'user', $2::uuid, role.id,
          'project', $3::uuid, $4::uuid
        FROM dirizhor.roles AS role
        WHERE role.code = 'project_viewer'
      `,
      [queryIds.viewerAssignment, queryIds.viewer, ids.project, ids.user],
    );
  });
}

async function grantMetadataReader(fixture: DirectorFixture): Promise<void> {
  await fixture.database.transaction(async (transaction) => {
    await transaction.query(
      `
        INSERT INTO dirizhor.app_users (id, login, display_name, status)
        VALUES ($1::uuid, 'metadata-reader@example.test', 'Metadata Reader', 'active')
      `,
      [queryIds.metadataReader],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.roles (id, code, name, scope_type)
        VALUES ($1::uuid, 'query_metadata_reader', 'Query metadata reader', 'project')
      `,
      [queryIds.metadataRole],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.role_permissions (role_id, permission_id)
        SELECT $1::uuid, permission.id
        FROM dirizhor.permissions AS permission
        WHERE permission.code IN (
          'project.read', 'memory_object.search', 'memory_object.read', 'task.read'
        )
      `,
      [queryIds.metadataRole],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.role_assignments (
          id, principal_type, principal_id, role_id,
          scope_type, scope_id, granted_by_user_id
        )
        VALUES (
          $1::uuid, 'user', $2::uuid, $3::uuid,
          'project', $4::uuid, $5::uuid
        )
      `,
      [
        queryIds.metadataAssignment,
        queryIds.metadataReader,
        queryIds.metadataRole,
        ids.project,
        ids.user,
      ],
    );
  });
}

async function seedRegistryCards(fixture: DirectorFixture): Promise<void> {
  await fixture.database.transaction(async (transaction) => {
    await transaction.query(
      `
        INSERT INTO dirizhor.memory_objects (
          id, type, title, project_id, author_user_id, summary,
          keywords, sensitivity_level
        )
        VALUES
          ($1::uuid, 'note', 'Registry Public', $7::uuid, $8::uuid,
           'Visible registry card', ARRAY['registry'], 'public'),
          ($2::uuid, 'note', 'Registry Internal', $7::uuid, $8::uuid,
           'Internal registry card', ARRAY['registry'], 'internal'),
          ($3::uuid, 'note', 'Registry Confidential', $7::uuid, $8::uuid,
           'Confidential registry card', ARRAY['registry'], 'confidential'),
          ($4::uuid, 'note', 'Registry Restricted', $7::uuid, $8::uuid,
           'Restricted registry card', ARRAY['registry'], 'restricted'),
          ($5::uuid, 'note', 'Public roadmap', $7::uuid, $8::uuid,
           NULL, ARRAY[]::text[], 'public'),
          ($6::uuid, 'note', 'Quantum secret', $7::uuid, $8::uuid,
           NULL, ARRAY[]::text[], 'confidential')
      `,
      [
        queryIds.publicMemory,
        queryIds.internalMemory,
        queryIds.confidentialMemory,
        queryIds.restrictedMemory,
        queryIds.relatedPublicMemory,
        queryIds.relatedHiddenMemory,
        ids.project,
        ids.user,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.relationships (
          id, project_id, source_type, source_id, target_type, target_id,
          relation_type, created_by_user_id
        )
        VALUES (
          $1::uuid, $2::uuid, 'memory_object', $3::uuid,
          'memory_object', $4::uuid, 'references', $5::uuid
        )
      `,
      [
        queryIds.relationship,
        ids.project,
        queryIds.relatedPublicMemory,
        queryIds.relatedHiddenMemory,
        ids.user,
      ],
    );
  });
}

async function seedTimeline(fixture: DirectorFixture): Promise<void> {
  await fixture.database.transaction(async (transaction) => {
    await transaction.query(
      `
        INSERT INTO dirizhor.memory_objects (
          id, type, title, project_id, author_user_id, sensitivity_level
        )
        VALUES
          ($1::uuid, 'ai_result', 'Visible result', $5::uuid, $6::uuid, 'internal'),
          ($2::uuid, 'ai_result', 'Hidden result', $5::uuid, $6::uuid, 'confidential'),
          ($3::uuid, 'decision', 'Visible decision', $5::uuid, $6::uuid, 'internal'),
          ($4::uuid, 'decision', 'Hidden decision', $5::uuid, $6::uuid, 'confidential'),
          ($7::uuid, 'document', 'Hidden context', $5::uuid, $6::uuid, 'confidential')
      `,
      [
        queryIds.visibleResultMemory,
        queryIds.hiddenResultMemory,
        queryIds.visibleDecisionMemory,
        queryIds.hiddenDecisionMemory,
        ids.project,
        ids.user,
        queryIds.hiddenContextMemory,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.document_versions (
          id, memory_object_id, version_number, storage_uri, file_name,
          file_type, content_hash, size_bytes, created_by_user_id
        )
        VALUES (
          $1::uuid, $2::uuid, 1, 'memory://hidden-context', 'hidden.md',
          'text/markdown', $3, 14, $4::uuid
        )
      `,
      [
        queryIds.hiddenContextVersion,
        queryIds.hiddenContextMemory,
        `sha256:${'d'.repeat(64)}`,
        ids.user,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.agent_runs (
          id, task_id, project_id, agent_type, provider, purpose, instructions,
          status, requested_by_user_id, deployment_class, context_set_hash,
          origin_request_id, request_fingerprint, dispatched_at, deadline_at,
          started_at, finished_at, output_summary
        )
        VALUES (
          $1::uuid, $2::uuid, $3::uuid, 'architect', 'fixture',
          'Hidden result run', 'Return result', 'queued', $4::uuid, 'internal',
          $5, $6::uuid, $5, '2030-01-01T10:00:00Z', '2030-01-01T11:00:00Z',
          NULL, NULL, NULL
        )
      `,
      [
        queryIds.hiddenRun,
        ids.task,
        ids.project,
        ids.user,
        `sha256:${'a'.repeat(64)}`,
        queryIds.hiddenRunOrigin,
      ],
    );
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'running', started_at = '2030-01-01T10:00:30Z'
        WHERE id = $1::uuid
      `,
      [ids.run],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.agent_run_contexts (
          id, agent_run_id, project_id, memory_object_id, document_version_id,
          position, access_reason, sensitivity_level
        )
        VALUES (
          $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid,
          1, 'Timeline fixture context', 'confidential'
        )
      `,
      [
        queryIds.hiddenRunContext,
        queryIds.hiddenRun,
        ids.project,
        queryIds.hiddenContextMemory,
        queryIds.hiddenContextVersion,
      ],
    );
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'running', started_at = '2030-01-01T10:01:00Z'
        WHERE id = $1::uuid
      `,
      [queryIds.hiddenRun],
    );
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'completed',
            finished_at = '2030-01-01T10:02:00Z',
            output_summary = 'Hidden output'
        WHERE id = $1::uuid
      `,
      [queryIds.hiddenRun],
    );
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'completed',
            finished_at = '2030-01-01T10:01:30Z',
            output_summary = 'Visible output'
        WHERE id = $1::uuid
      `,
      [ids.run],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.agent_run_results (
          id, agent_run_id, project_id, output_storage_uri, content_hash,
          size_bytes, output_summary, sensitivity_level,
          saved_memory_object_id, saved_at
        )
        VALUES
          ($1::uuid, $3::uuid, $5::uuid, 'memory://visible-result', $7,
           10, 'Visible output', 'internal', $6::uuid, '2030-01-01T10:03:00Z'),
          ($2::uuid, $4::uuid, $5::uuid, 'memory://hidden-result', $8,
           11, 'Hidden output', 'confidential', $9::uuid, '2030-01-01T10:04:00Z')
      `,
      [
        queryIds.visibleResultRecord,
        queryIds.hiddenResultRecord,
        ids.run,
        queryIds.hiddenRun,
        ids.project,
        queryIds.visibleResultMemory,
        `sha256:${'b'.repeat(64)}`,
        `sha256:${'c'.repeat(64)}`,
        queryIds.hiddenResultMemory,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.decisions (
          id, memory_object_id, project_id, title, decision_text
        )
        VALUES
          ($1::uuid, $2::uuid, $5::uuid, 'Visible decision', 'Keep the boundary'),
          ($3::uuid, $4::uuid, $5::uuid, 'Hidden decision', 'Secret decision')
      `,
      [
        queryIds.visibleDecision,
        queryIds.visibleDecisionMemory,
        queryIds.hiddenDecision,
        queryIds.hiddenDecisionMemory,
        ids.project,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.relationships (
          id, project_id, source_type, source_id, target_type, target_id,
          relation_type, created_by_user_id
        )
        VALUES
          ($1::uuid, $3::uuid, 'memory_object', $4::uuid, 'decision', $5::uuid,
           'derived_from', $6::uuid),
          ($2::uuid, $3::uuid, 'task', $7::uuid, 'decision', $8::uuid,
           'references', $6::uuid)
      `,
      [
        queryIds.visibleDecisionRelation,
        queryIds.hiddenDecisionRelation,
        ids.project,
        queryIds.visibleResultMemory,
        queryIds.visibleDecision,
        ids.user,
        ids.task,
        queryIds.hiddenDecision,
      ],
    );
    await transaction.query(
      `
        UPDATE dirizhor.tasks SET status = 'reviewing' WHERE id = $1::uuid
      `,
      [ids.task],
    );
    await transaction.query(
      `
        UPDATE dirizhor.tasks
        SET status = 'completed', result_memory_object_id = $2::uuid,
            completed_at = '2030-01-01T10:05:00Z'
        WHERE id = $1::uuid
      `,
      [ids.task, queryIds.visibleResultMemory],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          id, actor_type, actor_id, action, target_type, target_id,
          project_id, request_id
        )
        VALUES
          ($1::uuid, 'user', $3::uuid, 'task.reviewed', 'task', $4::uuid,
           $5::uuid, $1::uuid),
          ($2::uuid, 'user', $3::uuid, 'hidden_result.reviewed', 'memory_object', $6::uuid,
           $5::uuid, $2::uuid)
      `,
      [
        queryIds.taskAudit,
        queryIds.hiddenAudit,
        ids.user,
        ids.task,
        ids.project,
        queryIds.hiddenResultMemory,
      ],
    );
  });
}

async function collectTimeline(
  service: PublicQueryService,
  userId: string,
): Promise<TaskTimelineItem[]> {
  const items: TaskTimelineItem[] = [];
  let cursor: string | null = null;
  for (let pageNumber = 0; pageNumber < 20; pageNumber += 1) {
    const page = await service.getTaskTimeline(
      userId,
      queryIds.timelineRequest,
      ids.task,
      cursor === null ? { limit: 2 } : { limit: 2, cursor },
    );
    items.push(...page.items);
    cursor = page.next_cursor;
    if (cursor === null) {
      return items;
    }
  }
  throw new Error('Timeline pagination did not terminate.');
}

function requiredCursor(value: string | null): string {
  if (value === null) {
    throw new Error('Expected a pagination cursor.');
  }
  return value;
}
