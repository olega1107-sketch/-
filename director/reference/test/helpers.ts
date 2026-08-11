import { readFile } from 'node:fs/promises';

import { PGlite, type PGliteInterface, type Transaction } from '@electric-sql/pglite';

import {
  StaticAgentRouteResolver,
  type AgentRoute,
} from '../src/agent-routing.js';
import {
  computeContextSetHash,
  hashCanonical,
  sha256Bytes,
  sha256Text,
} from '../src/canonical.js';
import { DirectorService } from '../src/director-service.js';
import type {
  Clock,
  DocumentStore,
  SqlDatabase,
  SqlQueryable,
  SqlResult,
} from '../src/ports.js';
import { PostgresDirectorRepository } from '../src/postgres-director-repository.js';
import type {
  AgentRunCompletedEvent,
  AgentRunStartedEvent,
  ContextBundle,
  ContextBundleRedeemRequest,
  GatewayEvent,
} from '../src/protocol.js';

export const ids = {
  run: '10000000-0000-4000-8000-000000000001',
  project: '10000000-0000-4000-8000-000000000002',
  task: '10000000-0000-4000-8000-000000000003',
  originRequest: '10000000-0000-4000-8000-000000000004',
  memoryObject: '10000000-0000-4000-8000-000000000005',
  documentVersion: '10000000-0000-4000-8000-000000000006',
  callerRequest: '10000000-0000-4000-8000-000000000007',
  capability: '10000000-0000-4000-8000-000000000008',
  user: '10000000-0000-4000-8000-000000000009',
  uploadRequest: '10000000-0000-4000-8000-000000000010',
  startedEvent: '20000000-0000-4000-8000-000000000001',
  completedEvent: '20000000-0000-4000-8000-000000000002',
} as const;

export const times = {
  dispatched: '2030-01-01T09:59:00.000Z',
  now: '2030-01-01T10:00:00.000Z',
  started: '2030-01-01T10:00:01.000Z',
  completed: '2030-01-01T10:00:02.000Z',
  capabilityIssued: '2029-12-31T10:00:00.000Z',
  capabilityExpires: '2030-01-01T11:30:00.000Z',
  deadline: '2030-01-01T12:00:00.000Z',
} as const;

export const capabilitySecret = 'test-capability-secret';
export const gatewayBearerToken = 'test-gateway-bearer-token';

export function fixtureRouteResolver(
  overrides: Partial<AgentRoute> = {},
): StaticAgentRouteResolver {
  return new StaticAgentRouteResolver({
    routes: [],
    fallback: {
      provider: overrides.provider ?? 'fixture',
      model: overrides.model ?? null,
      deploymentClass: overrides.deploymentClass ?? 'internal',
      providerDataProfileVersion: overrides.providerDataProfileVersion ?? null,
    },
  });
}

export class TestClock implements Clock {
  constructor(private current = new Date(times.now)) {}

  now(): Date {
    return new Date(this.current);
  }

  set(value: string): void {
    this.current = new Date(value);
  }
}

export class PGliteDatabase implements SqlDatabase {
  constructor(readonly client: PGliteInterface = new PGlite()) {}

  async query<Row>(text: string, parameters: readonly unknown[] = []): Promise<SqlResult<Row>> {
    return query(this.client, text, parameters);
  }

  async transaction<T>(operation: (transaction: SqlQueryable) => Promise<T>): Promise<T> {
    return this.client.transaction((transaction) => operation(new PGliteTransaction(transaction)));
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}

class PGliteTransaction implements SqlQueryable {
  constructor(private readonly transaction: Transaction) {}

  async query<Row>(text: string, parameters: readonly unknown[] = []): Promise<SqlResult<Row>> {
    return query(this.transaction, text, parameters);
  }
}

interface PGliteQueryable {
  query<Row>(text: string, parameters?: unknown[]): Promise<{
    rows: Row[];
    affectedRows?: number;
  }>;
}

async function query<Row>(
  client: PGliteQueryable,
  text: string,
  parameters: readonly unknown[],
): Promise<SqlResult<Row>> {
  const result = await client.query<Row>(text, [...parameters]);
  return {
    rows: result.rows,
    rowCount: result.affectedRows ?? result.rows.length,
  };
}

export class MemoryDocumentStore implements DocumentStore {
  readonly immutable = new Map<string, Uint8Array>();
  readonly staged = new Map<string, { bytes: Uint8Array; contentType: string; hash: string }>();

  async readImmutable(storageUri: string): Promise<{ bytes: Uint8Array }> {
    const stagedKey = storageUri.startsWith('memory://')
      ? storageUri.slice('memory://'.length)
      : undefined;
    const bytes =
      this.immutable.get(storageUri) ??
      (stagedKey === undefined ? undefined : this.staged.get(stagedKey)?.bytes);
    if (bytes === undefined) {
      throw new Error(`Missing immutable document: ${storageUri}`);
    }
    return { bytes: Uint8Array.from(bytes) };
  }

  async stageAgentResult(
    deterministicKey: string,
    content: Uint8Array,
    contentType: string,
    expectedHash: string,
  ): Promise<{ storageUri: string }> {
    if (sha256Bytes(content) !== expectedHash) {
      throw new Error('Result hash mismatch.');
    }
    const existing = this.staged.get(deterministicKey);
    if (
      existing !== undefined &&
      (existing.hash !== expectedHash ||
        existing.contentType !== contentType ||
        !Buffer.from(existing.bytes).equals(Buffer.from(content)))
    ) {
      throw new Error('Deterministic result key collision.');
    }
    this.staged.set(deterministicKey, {
      bytes: Uint8Array.from(content),
      contentType,
      hash: expectedHash,
    });
    return { storageUri: `memory://${deterministicKey}` };
  }

  async stageImmutableDocument(
    deterministicKey: string,
    content: Uint8Array,
    contentType: string,
    expectedHash: string,
  ): Promise<{ storageUri: string }> {
    if (contentType.length === 0 || sha256Bytes(content) !== expectedHash) {
      throw new Error('Immutable document staging metadata is invalid.');
    }
    const storageUri = `memory://${deterministicKey}`;
    const existing = this.immutable.get(storageUri);
    if (existing !== undefined && !Buffer.from(existing).equals(Buffer.from(content))) {
      throw new Error('Deterministic document key collision.');
    }
    this.immutable.set(storageUri, Uint8Array.from(content));
    return { storageUri };
  }
}

export interface GatewayExecutionRequestFixture {
  protocol_version: '1.0';
  project_id: string;
  task_id: string;
  origin_request_id: string;
  request_fingerprint: string;
  agent_type: string;
  provider: string;
  model: string | null;
  purpose: string;
  instructions: string;
  deployment_class: 'internal';
  provider_data_profile_version: null;
  context_set_hash: string;
  context_item_count: number;
  max_context_sensitivity: 'internal';
  dispatched_at: string;
  deadline_at: string;
}

export interface DirectorFixture {
  database: PGliteDatabase;
  documentStore: MemoryDocumentStore;
  clock: TestClock;
  service: DirectorService;
  executionRequest: GatewayExecutionRequestFixture;
  redeemRequest: ContextBundleRedeemRequest;
  contextContent: string;
  close(): Promise<void>;
}

export interface PreparedDirectorFixture {
  database: PGliteDatabase;
  documentStore: MemoryDocumentStore;
  clock: TestClock;
  service: DirectorService;
  contextContent: string;
  close(): Promise<void>;
}

export async function prepareDirectorFixture(): Promise<PreparedDirectorFixture> {
  const database = new PGliteDatabase();
  await loadSchema(database.client);
  await seedProjectFixture(database);
  const clock = new TestClock();
  const documentStore = new MemoryDocumentStore();
  return {
    database,
    documentStore,
    clock,
    service: new DirectorService({
      repository: new PostgresDirectorRepository(database),
      documentStore,
      clock,
    }),
    contextContent: '# Architecture\nUse immutable context.',
    close: () => database.close(),
  };
}

export async function completeDirectorFixture(
  prepared: PreparedDirectorFixture,
): Promise<DirectorFixture> {
  const document = await prepared.database.query<{
    storageUri: string;
    fileName: string;
    fileType: string;
    contentHash: string;
    sizeBytes: number | string;
    sensitivityLevel: 'internal';
  }>(
    `
      SELECT
        version.storage_uri AS "storageUri",
        version.file_name AS "fileName",
        version.file_type AS "fileType",
        version.content_hash AS "contentHash",
        version.size_bytes AS "sizeBytes",
        memory.sensitivity_level AS "sensitivityLevel"
      FROM dirizhor.document_versions AS version
      JOIN dirizhor.memory_objects AS memory
        ON memory.id = version.memory_object_id
      WHERE memory.id = $1::uuid
        AND version.id = $2::uuid
        AND memory.current_version_id = version.id
    `,
    [ids.memoryObject, ids.documentVersion],
  );
  const row = document.rows[0];
  if (row === undefined) {
    throw new Error('Uploaded fixture document is missing or is not current.');
  }
  const contextBytes = Buffer.from(prepared.contextContent, 'utf8');
  const sizeBytes = typeof row.sizeBytes === 'string' ? Number(row.sizeBytes) : row.sizeBytes;
  if (
    !Number.isSafeInteger(sizeBytes) ||
    sizeBytes !== contextBytes.byteLength ||
    row.contentHash !== sha256Bytes(contextBytes)
  ) {
    throw new Error('Uploaded fixture document metadata does not match its context bytes.');
  }

  const contextBundleSeed: ContextBundle = {
    protocol_version: '1.0',
    agent_run_id: ids.run,
    project_id: ids.project,
    request_fingerprint: zeroHash(),
    context_set_hash: zeroHash(),
    item_count: 1,
    max_sensitivity_level: row.sensitivityLevel,
    items: [
      {
        position: 1,
        memory_object_id: ids.memoryObject,
        document_version_id: ids.documentVersion,
        file_name: row.fileName,
        media_type: row.fileType,
        size_bytes: sizeBytes,
        content_encoding: 'utf-8',
        content: prepared.contextContent,
        content_hash: row.contentHash,
        sensitivity_level: row.sensitivityLevel,
        access_reason: 'Primary architecture context',
      },
    ],
    assembled_at: times.now,
    expires_at: times.capabilityExpires,
  };
  const contextSetHash = computeContextSetHash(contextBundleSeed);
  const executionRequest = createExecutionRequest(contextSetHash);
  executionRequest.request_fingerprint = requestFingerprint(executionRequest);
  await seedLegacyTask(prepared.database);
  await seedDirector(
    prepared.database,
    {
      storageUri: row.storageUri,
      contentHash: row.contentHash,
      sizeBytes,
      contextSetHash,
      requestFingerprint: executionRequest.request_fingerprint,
    },
    false,
  );
  return {
    ...prepared,
    executionRequest,
    redeemRequest: {
      protocol_version: '1.0',
      request_fingerprint: executionRequest.request_fingerprint,
      expected_context_set_hash: contextSetHash,
    },
  };
}

export async function createDirectorFixture(): Promise<DirectorFixture> {
  const database = new PGliteDatabase();
  await loadSchema(database.client);

  const clock = new TestClock();
  const documentStore = new MemoryDocumentStore();
  const contextContent = '# Architecture\nUse immutable context.';
  const contextBytes = Buffer.from(contextContent, 'utf8');
  const storageUri = 'documents/architecture-v1.md';
  const contentHash = sha256Bytes(contextBytes);
  documentStore.immutable.set(storageUri, contextBytes);

  const contextBundleSeed: ContextBundle = {
    protocol_version: '1.0',
    agent_run_id: ids.run,
    project_id: ids.project,
    request_fingerprint: zeroHash(),
    context_set_hash: zeroHash(),
    item_count: 1,
    max_sensitivity_level: 'internal',
    items: [
      {
        position: 1,
        memory_object_id: ids.memoryObject,
        document_version_id: ids.documentVersion,
        file_name: 'architecture.md',
        media_type: 'text/markdown',
        size_bytes: contextBytes.byteLength,
        content_encoding: 'utf-8',
        content: contextContent,
        content_hash: contentHash,
        sensitivity_level: 'internal',
        access_reason: 'Primary architecture context',
      },
    ],
    assembled_at: times.now,
    expires_at: times.capabilityExpires,
  };
  const contextSetHash = computeContextSetHash(contextBundleSeed);
  const executionRequest = createExecutionRequest(contextSetHash);
  executionRequest.request_fingerprint = requestFingerprint(executionRequest);

  await seedProjectFixture(database);
  await seedLegacyTask(database);
  await seedDirector(database, {
    storageUri,
    contentHash,
    sizeBytes: contextBytes.byteLength,
    contextSetHash,
    requestFingerprint: executionRequest.request_fingerprint,
  });

  const repository = new PostgresDirectorRepository(database);
  const service = new DirectorService({ repository, documentStore, clock });
  return {
    database,
    documentStore,
    clock,
    service,
    executionRequest,
    redeemRequest: {
      protocol_version: '1.0',
      request_fingerprint: executionRequest.request_fingerprint,
      expected_context_set_hash: contextSetHash,
    },
    contextContent,
    close: () => database.close(),
  };
}

export function startedEvent(fixture: DirectorFixture): AgentRunStartedEvent {
  return sealEvent({
    protocol_version: '1.0',
    event_id: ids.startedEvent,
    event_type: 'agent_run.started',
    agent_run_id: ids.run,
    project_id: ids.project,
    origin_request_id: ids.originRequest,
    request_fingerprint: fixture.executionRequest.request_fingerprint,
    occurred_at: times.started,
    provider: fixture.executionRequest.provider,
    model: fixture.executionRequest.model,
    adapter_version: 'fixture/1.0',
    context_set_hash: fixture.executionRequest.context_set_hash,
  });
}

export function completedEvent(fixture: DirectorFixture): AgentRunCompletedEvent {
  const content = '# Recommendation\nKeep the immutable boundary.';
  const bytes = Buffer.from(content, 'utf8');
  return sealEvent({
    protocol_version: '1.0',
    event_id: ids.completedEvent,
    event_type: 'agent_run.completed',
    agent_run_id: ids.run,
    project_id: ids.project,
    origin_request_id: ids.originRequest,
    request_fingerprint: fixture.executionRequest.request_fingerprint,
    occurred_at: times.completed,
    provider: fixture.executionRequest.provider,
    model: fixture.executionRequest.model,
    adapter_version: 'fixture/1.0',
    provider_request_id: 'fixture-request-1',
    result: {
      content,
      content_type: 'text/markdown',
      content_hash: sha256Bytes(bytes),
      size_bytes: bytes.byteLength,
      output_summary: 'Keep the immutable boundary.',
      sensitivity_level: 'internal',
      finish_reason: 'stop',
      usage: { input_tokens: 12, output_tokens: 8 },
    },
  });
}

export function resealEvent<T extends GatewayEvent>(event: T): T {
  const body: Partial<GatewayEvent> = { ...event };
  delete body.event_hash;
  return { ...body, event_hash: hashCanonical(body) } as T;
}

function sealEvent<T extends GatewayEvent>(event: Omit<T, 'event_hash'>): T {
  return { ...event, event_hash: hashCanonical(event) } as T;
}

function createExecutionRequest(contextSetHash: string): GatewayExecutionRequestFixture {
  return {
    protocol_version: '1.0',
    project_id: ids.project,
    task_id: ids.task,
    origin_request_id: ids.originRequest,
    request_fingerprint: zeroHash(),
    agent_type: 'architect',
    provider: 'fixture',
    model: null,
    purpose: 'Review the architecture',
    instructions: 'Return only the final recommendation.',
    deployment_class: 'internal',
    provider_data_profile_version: null,
    context_set_hash: contextSetHash,
    context_item_count: 1,
    max_context_sensitivity: 'internal',
    dispatched_at: times.dispatched,
    deadline_at: times.deadline,
  };
}

function requestFingerprint(request: GatewayExecutionRequestFixture): string {
  const envelope: Partial<GatewayExecutionRequestFixture> = { ...request };
  delete envelope.request_fingerprint;
  return hashCanonical({ agent_run_id: ids.run, ...envelope });
}

async function loadSchema(client: PGliteInterface): Promise<void> {
  const schemaPath = new URL('../../../db/schema-v1.sql', import.meta.url);
  const schema = await readFile(schemaPath, 'utf8');
  const pgliteSchema = schema.replace('CREATE EXTENSION IF NOT EXISTS pgcrypto;\n', '');
  if (pgliteSchema === schema) {
    throw new Error('Expected pgcrypto extension declaration was not found.');
  }
  await client.exec(pgliteSchema, { onNotice: () => undefined });
}

interface SeedInput {
  storageUri: string;
  contentHash: string;
  sizeBytes: number;
  contextSetHash: string;
  requestFingerprint: string;
}

async function seedProjectFixture(database: SqlDatabase): Promise<void> {
  await database.transaction(async (transaction) => {
    await transaction.query(
      `
        INSERT INTO dirizhor.app_users (id, login, display_name, status)
        VALUES ($1::uuid, 'owner@example.test', 'Test Owner', 'active')
      `,
      [ids.user],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.projects (id, title, owner_user_id)
        VALUES ($1::uuid, 'Architecture', $2::uuid)
      `,
      [ids.project, ids.user],
    );
  });
}

async function seedLegacyTask(database: SqlDatabase): Promise<void> {
  await database.query(
    `
      INSERT INTO dirizhor.tasks (
        id, project_id, created_by_user_id, title, user_request, status
      )
      VALUES ($1::uuid, $2::uuid, $3::uuid, 'Review', 'Review architecture', 'running_agent')
    `,
    [ids.task, ids.project, ids.user],
  );
}

async function seedDirector(
  database: SqlDatabase,
  input: SeedInput,
  includeDocument = true,
): Promise<void> {
  await database.transaction(async (transaction) => {
    if (includeDocument) {
      await transaction.query(
        `
          INSERT INTO dirizhor.memory_objects (
            id, type, title, project_id, author_user_id, sensitivity_level
          )
          VALUES ($1::uuid, 'document', 'Architecture', $2::uuid, $3::uuid, 'internal')
        `,
        [ids.memoryObject, ids.project, ids.user],
      );
      await transaction.query(
        `
          INSERT INTO dirizhor.document_versions (
            id,
            memory_object_id,
            version_number,
            storage_uri,
            file_name,
            file_type,
            content_hash,
            size_bytes,
            created_by_user_id
          )
          VALUES ($1::uuid, $2::uuid, 1, $3, 'architecture.md', 'text/markdown', $4, $5, $6::uuid)
        `,
        [
          ids.documentVersion,
          ids.memoryObject,
          input.storageUri,
          input.contentHash,
          input.sizeBytes,
          ids.user,
        ],
      );
    }
    await transaction.query(
      `
        INSERT INTO dirizhor.agent_runs (
          id,
          task_id,
          project_id,
          agent_type,
          provider,
          model,
          purpose,
          instructions,
          status,
          requested_by_user_id,
          provider_data_profile_version,
          deployment_class,
          context_set_hash,
          origin_request_id,
          request_fingerprint,
          dispatched_at,
          deadline_at
        )
        VALUES (
          $1::uuid,
          $2::uuid,
          $3::uuid,
          'architect',
          'fixture',
          NULL,
          'Review the architecture',
          'Return only the final recommendation.',
          'queued',
          $4::uuid,
          NULL,
          'internal',
          $5,
          $6::uuid,
          $7,
          $8::timestamptz,
          $9::timestamptz
        )
      `,
      [
        ids.run,
        ids.task,
        ids.project,
        ids.user,
        input.contextSetHash,
        ids.originRequest,
        input.requestFingerprint,
        times.dispatched,
        times.deadline,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.agent_run_contexts (
          agent_run_id,
          project_id,
          memory_object_id,
          document_version_id,
          position,
          access_reason,
          sensitivity_level
        )
        VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, $5, 'internal')
      `,
      [
        ids.run,
        ids.project,
        ids.memoryObject,
        ids.documentVersion,
        'Primary architecture context',
      ],
    );
    const servicePrincipal = await transaction.query<{ id: string }>(
      `
        SELECT id::text AS id
        FROM dirizhor.service_principals
        WHERE code = 'agent-gateway'
      `,
    );
    const servicePrincipalId = servicePrincipal.rows[0]?.id;
    if (servicePrincipalId === undefined) {
      throw new Error('Seeded Agent Gateway principal is missing.');
    }
    await transaction.query(
      `
        INSERT INTO dirizhor.agent_capabilities (
          id,
          agent_run_id,
          project_id,
          issued_to_service_principal_id,
          allowed_actions,
          context_set_hash,
          token_hash,
          issued_at,
          expires_at
        )
        VALUES (
          $1::uuid,
          $2::uuid,
          $3::uuid,
          $4::uuid,
          ARRAY['context_bundle.read']::text[],
          $5,
          $6,
          $7::timestamptz,
          $8::timestamptz
        )
      `,
      [
        ids.capability,
        ids.run,
        ids.project,
        servicePrincipalId,
        input.contextSetHash,
        sha256Text(capabilitySecret),
        times.capabilityIssued,
        times.capabilityExpires,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.agent_capability_resources (
          agent_capability_id,
          project_id,
          memory_object_id,
          document_version_id
        )
        VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)
      `,
      [ids.capability, ids.project, ids.memoryObject, ids.documentVersion],
    );
  });
}

function zeroHash(): string {
  return `sha256:${'0'.repeat(64)}`;
}
