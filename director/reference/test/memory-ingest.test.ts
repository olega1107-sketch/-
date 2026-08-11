import { afterEach, describe, expect, it } from 'vitest';

import type { DirectorProtocolError } from '../src/errors.js';
import { MemoryIngestService } from '../src/memory-ingest-service.js';
import type { IdGenerator } from '../src/memory-ports.js';
import { PostgresMemoryIngestRepository } from '../src/postgres-memory-ingest-repository.js';
import type { StagedDocument } from '../src/ports.js';
import {
  createDirectorFixture,
  ids,
  MemoryDocumentStore,
  type DirectorFixture,
} from './helpers.js';

const uploadIds = {
  memoryObject: '30000000-0000-4000-8000-000000000001',
  documentVersion: '30000000-0000-4000-8000-000000000002',
  request: '30000000-0000-4000-8000-000000000003',
  viewer: '30000000-0000-4000-8000-000000000004',
  editor: '30000000-0000-4000-8000-000000000005',
  editorAssignment: '30000000-0000-4000-8000-000000000006',
  missingTopic: '30000000-0000-4000-8000-000000000007',
} as const;

describe('Memory ingest', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('stages bytes and atomically creates the object, first version, and audit trail', async () => {
    fixture = await createDirectorFixture();
    const content = Buffer.from('# Uploaded architecture\nImmutable source.', 'utf8');
    const service = serviceFor(fixture, fixture.documentStore);

    const memoryObject = await service.upload({
      userId: ids.user,
      requestId: uploadIds.request,
      metadata: {
        project_id: ids.project,
        topic_id: null,
        type: 'document',
        title: 'Uploaded architecture',
        summary: 'Primary source',
        keywords: ['architecture', 'source'],
        sensitivity_level: 'confidential',
      },
      fileName: 'architecture.md',
      fileType: 'text/markdown',
      content,
    });

    const storageUri = `memory://document-versions/${ids.project}/${uploadIds.memoryObject}/${uploadIds.documentVersion}`;
    expect(memoryObject).toMatchObject({
      id: uploadIds.memoryObject,
      project_id: ids.project,
      current_version_id: uploadIds.documentVersion,
      author_user_id: ids.user,
      keywords: ['architecture', 'source'],
      sensitivity_level: 'confidential',
      current_version: {
        id: uploadIds.documentVersion,
        version_number: 1,
        file_name: 'architecture.md',
        file_type: 'text/markdown',
        size_bytes: content.byteLength,
      },
    });
    const stored = await fixture.documentStore.readImmutable(storageUri);
    expect(Buffer.from(stored.bytes).equals(content)).toBe(true);

    const persisted = await fixture.database.query<{
      storageUri: string;
      currentVersionId: string;
      auditCount: number | string;
    }>(
      `
        SELECT
          version.storage_uri AS "storageUri",
          memory.current_version_id::text AS "currentVersionId",
          (
            SELECT count(*)
            FROM dirizhor.audit_events AS audit
            WHERE audit.request_id = $3::uuid
              AND audit.actor_type = 'user'
              AND audit.actor_id = $4::uuid
              AND audit.action IN ('memory_object.created', 'document_version.created')
          ) AS "auditCount"
        FROM dirizhor.memory_objects AS memory
        JOIN dirizhor.document_versions AS version
          ON version.id = memory.current_version_id
        WHERE memory.id = $1::uuid
          AND version.id = $2::uuid
      `,
      [uploadIds.memoryObject, uploadIds.documentVersion, uploadIds.request, ids.user],
    );
    expect(persisted.rows[0]).toMatchObject({
      storageUri,
      currentVersionId: uploadIds.documentVersion,
    });
    expect(Number(persisted.rows[0]?.auditCount)).toBe(2);
    const authorization = await fixture.database.query<{
      decisionId: string;
      decision: string;
      reasonCodes: string[];
      auditAction: string;
      auditDecisionId: string;
      metadata: Record<string, unknown>;
    }>(
      `
        SELECT
          decision.id::text AS "decisionId",
          decision.decision,
          decision.reason_codes AS "reasonCodes",
          audit.action AS "auditAction",
          audit.authorization_decision_id::text AS "auditDecisionId",
          audit.metadata
        FROM dirizhor.authorization_decisions AS decision
        JOIN dirizhor.audit_events AS audit
          ON audit.authorization_decision_id = decision.id
        WHERE decision.request_id = $1::uuid
        ORDER BY audit.action
      `,
      [uploadIds.request],
    );
    expect(authorization.rows).toHaveLength(2);
    expect(authorization.rows.map((row) => row.auditAction)).toEqual([
      'document_version.created',
      'memory_object.created',
    ]);
    expect(new Set(authorization.rows.map((row) => row.decisionId))).toEqual(
      new Set([authorization.rows[0]?.auditDecisionId]),
    );
    expect(authorization.rows[0]).toMatchObject({
      decision: 'allow',
      reasonCodes: ['permissions_satisfied'],
    });
    expect(JSON.stringify(authorization.rows.map((row) => row.metadata))).not.toContain(
      'Immutable source.',
    );
  });

  it('denies a viewer before any document bytes are staged', async () => {
    fixture = await createDirectorFixture();
    await grantProjectRole(fixture, uploadIds.viewer, 'project_viewer');
    const immutableCount = fixture.documentStore.immutable.size;
    const service = serviceFor(fixture, fixture.documentStore);

    await expect(
      service.upload({
        userId: uploadIds.viewer,
        requestId: uploadIds.request,
        metadata: metadata(),
        fileName: 'denied.md',
        fileType: 'text/markdown',
        content: Buffer.from('must not be staged', 'utf8'),
      }),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'access_denied',
    } satisfies Partial<DirectorProtocolError>);
    expect(fixture.documentStore.immutable.size).toBe(immutableCount);
  });

  it('rejects a topic outside the project before document staging', async () => {
    fixture = await createDirectorFixture();
    const immutableCount = fixture.documentStore.immutable.size;
    const service = serviceFor(fixture, fixture.documentStore);

    await expect(
      service.upload({
        userId: ids.user,
        requestId: uploadIds.request,
        metadata: { ...metadata(), topic_id: uploadIds.missingTopic },
        fileName: 'missing-topic.md',
        fileType: 'text/markdown',
        content: Buffer.from('must not be staged', 'utf8'),
      }),
    ).rejects.toMatchObject({
      statusCode: 404,
      code: 'not_found',
      details: { resource: 'topic', id: uploadIds.missingTopic },
    });
    expect(fixture.documentStore.immutable.size).toBe(immutableCount);
  });

  it('rechecks RBAC after staging and rejects a role revoked before commit', async () => {
    fixture = await createDirectorFixture();
    await grantProjectRole(
      fixture,
      uploadIds.editor,
      'project_editor',
      uploadIds.editorAssignment,
    );
    const documentStore = new RevokingDocumentStore(async () => {
      await fixture!.database.query(
        `
          UPDATE dirizhor.role_assignments
          SET revoked_at = clock_timestamp()
          WHERE id = $1::uuid
        `,
        [uploadIds.editorAssignment],
      );
    });
    const service = serviceFor(fixture, documentStore);

    await expect(
      service.upload({
        userId: uploadIds.editor,
        requestId: uploadIds.request,
        metadata: metadata(),
        fileName: 'revoked.md',
        fileType: 'text/markdown',
        content: Buffer.from('staged before revocation', 'utf8'),
      }),
    ).rejects.toMatchObject({ statusCode: 403, code: 'access_denied' });
    expect(documentStore.immutable.size).toBe(1);
    const persisted = await fixture.database.query<{ count: number | string }>(
      `
        SELECT count(*) AS count
        FROM dirizhor.memory_objects
        WHERE id = $1::uuid
      `,
      [uploadIds.memoryObject],
    );
    expect(Number(persisted.rows[0]?.count)).toBe(0);
  });

  it('rolls back the object and audit writes when the document version conflicts', async () => {
    fixture = await createDirectorFixture();
    const service = new MemoryIngestService({
      repository: new PostgresMemoryIngestRepository(fixture.database),
      documentStore: fixture.documentStore,
      idGenerator: new SequenceIds([uploadIds.memoryObject, ids.documentVersion]),
    });

    await expect(
      service.upload({
        userId: ids.user,
        requestId: uploadIds.request,
        metadata: metadata(),
        fileName: 'collision.md',
        fileType: 'text/markdown',
        content: Buffer.from('staged orphan after SQL rollback', 'utf8'),
      }),
    ).rejects.toMatchObject({ statusCode: 409, code: 'conflict' });

    const persisted = await fixture.database.query<{
      memoryCount: number | string;
      auditCount: number | string;
      decisionCount: number | string;
    }>(
      `
        SELECT
          (SELECT count(*) FROM dirizhor.memory_objects WHERE id = $1::uuid) AS "memoryCount",
          (SELECT count(*) FROM dirizhor.audit_events WHERE request_id = $2::uuid) AS "auditCount",
          (
            SELECT count(*) FROM dirizhor.authorization_decisions
            WHERE request_id = $2::uuid
          ) AS "decisionCount"
      `,
      [uploadIds.memoryObject, uploadIds.request],
    );
    expect(Number(persisted.rows[0]?.memoryCount)).toBe(0);
    expect(Number(persisted.rows[0]?.auditCount)).toBe(0);
    expect(Number(persisted.rows[0]?.decisionCount)).toBe(0);
  });
});

function serviceFor(
  fixture: DirectorFixture,
  documentStore: MemoryDocumentStore,
): MemoryIngestService {
  return new MemoryIngestService({
    repository: new PostgresMemoryIngestRepository(fixture.database),
    documentStore,
    idGenerator: new SequenceIds([uploadIds.memoryObject, uploadIds.documentVersion]),
  });
}

function metadata() {
  return {
    project_id: ids.project,
    topic_id: null,
    type: 'document' as const,
    title: 'Architecture',
    summary: null,
    keywords: [],
    sensitivity_level: 'internal' as const,
  };
}

async function grantProjectRole(
  fixture: DirectorFixture,
  userId: string,
  roleCode: 'project_viewer' | 'project_editor',
  assignmentId?: string,
): Promise<void> {
  await fixture.database.transaction(async (transaction) => {
    await transaction.query(
      `
        INSERT INTO dirizhor.app_users (id, login, display_name, status)
        VALUES ($1::uuid, $2, 'Upload test user', 'active')
      `,
      [userId, `${userId}@example.test`],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.role_assignments (
          id,
          principal_type,
          principal_id,
          role_id,
          scope_type,
          scope_id,
          granted_by_user_id
        )
        SELECT
          COALESCE($1::uuid, gen_random_uuid()),
          'user',
          $2::uuid,
          role.id,
          'project',
          $3::uuid,
          $4::uuid
        FROM dirizhor.roles AS role
        WHERE role.code = $5
      `,
      [assignmentId ?? null, userId, ids.project, ids.user, roleCode],
    );
  });
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

class RevokingDocumentStore extends MemoryDocumentStore {
  constructor(private readonly afterStage: () => Promise<void>) {
    super();
  }

  override async stageImmutableDocument(
    deterministicKey: string,
    content: Uint8Array,
    contentType: string,
    expectedHash: string,
  ): Promise<StagedDocument> {
    const staged = await super.stageImmutableDocument(
      deterministicKey,
      content,
      contentType,
      expectedHash,
    );
    await this.afterStage();
    return staged;
  }
}
