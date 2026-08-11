import { afterEach, describe, expect, it } from 'vitest';

import { buildGatewayApp } from '../../../gateway/reference/src/app.js';
import { FixtureProviderAdapter } from '../../../gateway/reference/src/fixture-provider-adapter.js';
import { GatewayService } from '../../../gateway/reference/src/gateway-service.js';
import { HttpDirectorClient } from '../../../gateway/reference/src/http-director-client.js';
import type {
  ExecutionRecord,
  ExecutionStore,
  IdGenerator,
} from '../../../gateway/reference/src/ports.js';
import { StaticBearerAuthenticator as GatewayAuthenticator } from '../../../gateway/reference/src/service-auth.js';
import { AgentResultService } from '../src/agent-result-service.js';
import { StaticAgentRouteResolver } from '../src/agent-routing.js';
import { buildDirectorApp } from '../src/app.js';
import { HmacCapabilityTokenIssuer } from '../src/capability-token.js';
import { ConfirmationService } from '../src/confirmation-service.js';
import { HttpAgentGatewayClient } from '../src/http-agent-gateway-client.js';
import { MemoryIngestService } from '../src/memory-ingest-service.js';
import { PostgresAgentResultRepository } from '../src/postgres-agent-result-repository.js';
import { PostgresMemoryIngestRepository } from '../src/postgres-memory-ingest-repository.js';
import { PostgresConfirmationRepository } from '../src/postgres-confirmation-repository.js';
import { PostgresPublicQueryRepository } from '../src/postgres-public-query-repository.js';
import { PostgresTaskRepository } from '../src/postgres-task-repository.js';
import { PublicQueryService } from '../src/public-query-service.js';
import { StaticBearerAuthenticator as DirectorAuthenticator } from '../src/service-auth.js';
import { TaskService } from '../src/task-service.js';
import { StaticUserBearerAuthenticator } from '../src/user-auth.js';
import {
  gatewayBearerToken,
  ids,
  prepareDirectorFixture,
  type PreparedDirectorFixture,
} from './helpers.js';

const publicUserToken = 'test-public-user-token';
const directorToGatewayToken = 'test-director-to-gateway-token';
const taskRequestId = '10000000-0000-4000-8000-000000000011';
const confirmationCapabilityId = '10000000-0000-4000-8000-000000000012';
const approvalRequestId = '10000000-0000-4000-8000-000000000013';
const resultReadRequestId = '10000000-0000-4000-8000-000000000014';
const resultSaveRequestId = '10000000-0000-4000-8000-000000000015';
const resultApprovalRequestId = '10000000-0000-4000-8000-000000000016';
const confirmationInboxRequestId = '10000000-0000-4000-8000-000000000017';
const projectListRequestId = '10000000-0000-4000-8000-000000000018';
const externalProfileVersion = 'fixture-external-v1';

describe('Gateway and Director reference implementations', () => {
  let prepared: PreparedDirectorFixture | undefined;
  let directorApp: ReturnType<typeof buildDirectorApp> | undefined;
  let gatewayApp: ReturnType<typeof buildGatewayApp> | undefined;

  afterEach(async () => {
    await gatewayApp?.close();
    await directorApp?.close();
    await prepared?.close();
    gatewayApp = undefined;
    directorApp = undefined;
    prepared = undefined;
  });

  it('executes, reads, confirms, and saves an AI result end to end', async () => {
    prepared = await prepareDirectorFixture();
    const runtime = createE2eRuntime(prepared);
    directorApp = runtime.directorApp;
    gatewayApp = runtime.gatewayApp;
    const { adapter, gatewayService, store } = runtime;

    const projects = await directorApp.inject({
      method: 'GET',
      url: '/api/v1/projects?limit=10',
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': projectListRequestId,
      },
    });
    expect(projects.statusCode, projects.body).toBe(200);
    expect(projects.json()).toMatchObject({
      items: [{ id: ids.project, title: 'Architecture', status: 'active' }],
      next_cursor: null,
    });

    const task = await directorApp.inject({
      method: 'POST',
      url: '/api/v1/tasks',
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': taskRequestId,
      },
      payload: {
        project_id: ids.project,
        title: 'Review architecture',
        user_request: 'Review the uploaded architecture document.',
      },
    });
    expect(task.statusCode, task.body).toBe(201);
    expect(task.json()).toMatchObject({
      id: ids.task,
      project_id: ids.project,
      status: 'created',
    });

    const upload = await documentUpload(prepared.contextContent);
    const uploaded = await directorApp.inject({
      method: 'POST',
      url: '/api/v1/memory-objects:upload',
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': ids.uploadRequest,
        'content-type': upload.contentType,
      },
      payload: upload.payload,
    });
    expect(uploaded.statusCode, uploaded.body).toBe(201);
    expect(uploaded.json()).toMatchObject({
      id: ids.memoryObject,
      current_version_id: ids.documentVersion,
    });

    const accepted = await directorApp.inject({
      method: 'POST',
      url: `/api/v1/tasks/${ids.task}/agent-runs`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': ids.originRequest,
      },
      payload: {
        agent_type: 'architect',
        purpose: 'Review the architecture',
        instructions: 'Return only the final recommendation.',
        context: [
          {
            memory_object_id: ids.memoryObject,
            document_version_id: ids.documentVersion,
            access_reason: 'Primary architecture context',
          },
        ],
      },
    });
    expect(accepted.statusCode, accepted.body).toBe(202);
    expect(accepted.json()).toMatchObject({
      id: ids.run,
      task_id: ids.task,
      status: 'queued',
      origin_request_id: ids.originRequest,
    });

    await gatewayService.drain(ids.run);

    expect(adapter.calls).toHaveLength(1);
    expect(await store.load(ids.run)).toMatchObject({
      phase: 'completed',
      terminalEventType: 'agent_run.completed',
    });

    const taskAfterRun = await directorApp.inject({
      method: 'GET',
      url: `/api/v1/tasks/${ids.task}`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultReadRequestId,
      },
    });
    expect(taskAfterRun.statusCode, taskAfterRun.body).toBe(200);
    expect(taskAfterRun.json()).toMatchObject({ id: ids.task, status: 'reviewing' });

    const runAfterExecution = await directorApp.inject({
      method: 'GET',
      url: `/api/v1/agent-runs/${ids.run}`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultReadRequestId,
      },
    });
    expect(runAfterExecution.statusCode, runAfterExecution.body).toBe(200);
    expect(runAfterExecution.json()).toMatchObject({ id: ids.run, status: 'completed' });

    const temporaryResult = await directorApp.inject({
      method: 'GET',
      url: `/api/v1/agent-runs/${ids.run}/result`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultReadRequestId,
      },
    });
    expect(temporaryResult.statusCode, temporaryResult.body).toBe(200);
    expect(temporaryResult.json()).toMatchObject({
      agent_run_id: ids.run,
      content: expect.stringContaining('Fixture result for:'),
      saved_memory_object_id: null,
    });

    const savePayload = {
      title: 'Architecture review result',
      relationships: [
        {
          target_type: 'memory_object',
          target_id: ids.memoryObject,
          relation_type: 'derived_from',
        },
      ],
    };
    const saveRequested = await directorApp.inject({
      method: 'POST',
      url: `/api/v1/agent-runs/${ids.run}/result:save`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultSaveRequestId,
      },
      payload: savePayload,
    });
    expect(saveRequested.statusCode, saveRequested.body).toBe(428);
    const resultConfirmationId = confirmationIdFrom(saveRequested.json());

    const saveApproved = await directorApp.inject({
      method: 'POST',
      url: `/api/v1/confirmations/${resultConfirmationId}:approve`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultApprovalRequestId,
      },
    });
    expect(saveApproved.statusCode, saveApproved.body).toBe(200);
    expect(saveApproved.json()).toMatchObject({
      id: resultConfirmationId,
      operation: 'ai_result_save',
      status: 'consumed',
    });

    const savedResult = await directorApp.inject({
      method: 'POST',
      url: `/api/v1/agent-runs/${ids.run}/result:save`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultSaveRequestId,
      },
      payload: savePayload,
    });
    expect(savedResult.statusCode, savedResult.body).toBe(201);
    expect(savedResult.json()).toMatchObject({
      type: 'ai_result',
      title: 'Architecture review result',
      sensitivity_level: 'internal',
    });
    const savedMemoryObjectId = memoryObjectIdFrom(savedResult.json());

    const registry = await directorApp.inject({
      method: 'GET',
      url: `/api/v1/memory-objects/search?project_id=${ids.project}&q=architecture`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultReadRequestId,
      },
    });
    expect(registry.statusCode, registry.body).toBe(200);
    expect(registry.json()).toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({ id: ids.memoryObject }),
        expect.objectContaining({ id: savedMemoryObjectId, type: 'ai_result' }),
      ]),
    });

    const savedMemory = await directorApp.inject({
      method: 'GET',
      url: `/api/v1/memory-objects/${savedMemoryObjectId}`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultReadRequestId,
      },
    });
    expect(savedMemory.statusCode, savedMemory.body).toBe(200);
    expect(savedMemory.json()).toMatchObject({
      id: savedMemoryObjectId,
      current_version: { content_hash: expect.stringMatching(/^sha256:/) },
    });

    const timeline = await directorApp.inject({
      method: 'GET',
      url: `/api/v1/tasks/${ids.task}/timeline`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': resultReadRequestId,
      },
    });
    expect(timeline.statusCode, timeline.body).toBe(200);
    expect(timeline.json()).toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({ kind: 'agent_run', resource_id: ids.run }),
        expect.objectContaining({ kind: 'ai_result', resource_id: savedMemoryObjectId }),
      ]),
    });

    const persisted = await prepared.database.query<{
      status: string;
      taskStatus: string;
      taskResultId: string | null;
      resultCount: number | string;
      auditCount: number | string;
      uploadAuditCount: number | string;
      dispatchAuditCount: number | string;
      taskAuditCount: number | string;
      capabilityUsed: boolean;
    }>(
      `
        SELECT
          run.status,
          task.status AS "taskStatus",
          task.result_memory_object_id::text AS "taskResultId",
          (
            SELECT count(*)
            FROM dirizhor.agent_run_results AS result
            WHERE result.agent_run_id = run.id
          ) AS "resultCount",
          (
            SELECT count(*)
            FROM dirizhor.audit_events AS audit
            WHERE audit.target_id = run.id
              AND audit.action IN (
                'agent_context.redeemed',
                'agent_run.started',
                'agent_run.completed'
              )
          ) AS "auditCount",
          (
            SELECT count(*)
            FROM dirizhor.audit_events AS audit
            WHERE audit.request_id = $2::uuid
              AND audit.action IN ('memory_object.created', 'document_version.created')
          ) AS "uploadAuditCount",
          (
            SELECT count(*)
            FROM dirizhor.audit_events AS audit
            WHERE audit.request_id = $3::uuid
              AND audit.action IN (
                'agent_run.dispatched',
                'memory_object.read',
                'agent_context.attached'
              )
          ) AS "dispatchAuditCount",
          (
            SELECT count(*)
            FROM dirizhor.audit_events AS audit
            WHERE audit.request_id = $4::uuid
              AND audit.action = 'task.created'
          ) AS "taskAuditCount",
          capability.used_at IS NOT NULL AS "capabilityUsed"
        FROM dirizhor.agent_runs AS run
        JOIN dirizhor.tasks AS task ON task.id = run.task_id
        JOIN dirizhor.agent_capabilities AS capability
          ON capability.agent_run_id = run.id
        WHERE run.id = $1::uuid
      `,
      [ids.run, ids.uploadRequest, ids.originRequest, taskRequestId],
    );
    const row = persisted.rows[0];
    expect(row?.status).toBe('completed');
    expect(row?.taskStatus).toBe('completed');
    expect(row?.taskResultId).toBe(savedMemoryObjectId);
    expect(Number(row?.resultCount)).toBe(1);
    expect(Number(row?.auditCount)).toBe(3);
    expect(Number(row?.uploadAuditCount)).toBe(2);
    expect(Number(row?.dispatchAuditCount)).toBe(3);
    expect(Number(row?.taskAuditCount)).toBe(1);
    expect(row?.capabilityUsed).toBe(true);
  });

  it('continues an external frozen run after public confirmation approval', async () => {
    prepared = await prepareDirectorFixture();
    await prepared.database.query(
      `
        UPDATE dirizhor.project_ai_policies
        SET external_ai_enabled = true,
            allowed_provider_ids = ARRAY['fixture']::text[],
            provider_data_profile_versions = $2::jsonb,
            max_external_sensitivity_level = 'internal',
            confirm_internal_external_share = true
        WHERE project_id = $1::uuid
      `,
      [ids.project, JSON.stringify({ fixture: externalProfileVersion })],
    );
    const runtime = createE2eRuntime(prepared, {
      deploymentClass: 'external',
      providerDataProfileVersion: externalProfileVersion,
    });
    directorApp = runtime.directorApp;
    gatewayApp = runtime.gatewayApp;

    const task = await directorApp.inject({
      method: 'POST',
      url: '/api/v1/tasks',
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': taskRequestId,
      },
      payload: {
        project_id: ids.project,
        title: 'External architecture review',
        user_request: 'Review the uploaded document with the approved provider.',
      },
    });
    expect(task.statusCode, task.body).toBe(201);

    const upload = await documentUpload(prepared.contextContent);
    const uploaded = await directorApp.inject({
      method: 'POST',
      url: '/api/v1/memory-objects:upload',
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': ids.uploadRequest,
        'content-type': upload.contentType,
      },
      payload: upload.payload,
    });
    expect(uploaded.statusCode, uploaded.body).toBe(201);

    const requested = await directorApp.inject({
      method: 'POST',
      url: `/api/v1/tasks/${ids.task}/agent-runs`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': ids.originRequest,
      },
      payload: {
        agent_type: 'architect',
        purpose: 'Review the architecture',
        instructions: 'Return only the final recommendation.',
        context: [
          {
            memory_object_id: ids.memoryObject,
            document_version_id: ids.documentVersion,
            access_reason: 'Primary architecture context',
          },
        ],
      },
    });
    expect(requested.statusCode, requested.body).toBe(428);
    expect(requested.json()).toMatchObject({
      error: {
        code: 'requires_confirmation',
        details: {
          target_type: 'agent_run',
          target_id: ids.run,
          payload_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        },
        request_id: ids.originRequest,
      },
    });
    const confirmationId = confirmationIdFrom(requested.json());

    const inbox = await directorApp.inject({
      method: 'GET',
      url: `/api/v1/confirmations?project_id=${ids.project}&limit=10`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': confirmationInboxRequestId,
      },
    });
    expect(inbox.statusCode, inbox.body).toBe(200);
    expect(inbox.json()).toMatchObject({
      items: [{ id: confirmationId, status: 'pending' }],
      next_cursor: null,
    });
    expect(inbox.json().items[0]).not.toHaveProperty('frozen_payload');

    const pending = await directorApp.inject({
      method: 'GET',
      url: `/api/v1/confirmations/${confirmationId}`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': ids.callerRequest,
      },
    });
    expect(pending.statusCode, pending.body).toBe(200);
    expect(pending.json()).toMatchObject({
      id: confirmationId,
      operation: 'agent_context_share',
      status: 'pending',
    });

    const approved = await directorApp.inject({
      method: 'POST',
      url: `/api/v1/confirmations/${confirmationId}:approve`,
      headers: {
        authorization: `Bearer ${publicUserToken}`,
        'x-request-id': approvalRequestId,
      },
    });
    expect(approved.statusCode, approved.body).toBe(200);
    expect(approved.json()).toMatchObject({
      id: confirmationId,
      status: 'consumed',
      decided_by_user_id: ids.user,
    });

    await runtime.gatewayService.drain(ids.run);
    expect(runtime.adapter.calls).toHaveLength(1);
    expect(await runtime.store.load(ids.run)).toMatchObject({ phase: 'completed' });
    const persisted = await prepared.database.query<{
      status: string;
      deploymentClass: string;
      profileVersion: string | null;
      capabilityUsed: boolean;
      confirmationStatus: string;
    }>(
      `
        SELECT
          run.status,
          run.deployment_class AS "deploymentClass",
          run.provider_data_profile_version AS "profileVersion",
          capability.used_at IS NOT NULL AS "capabilityUsed",
          confirmation.status AS "confirmationStatus"
        FROM dirizhor.agent_runs AS run
        JOIN dirizhor.agent_capabilities AS capability ON capability.agent_run_id = run.id
        JOIN dirizhor.confirmations AS confirmation
          ON confirmation.target_type = 'agent_run' AND confirmation.target_id = run.id
        WHERE run.id = $1::uuid
      `,
      [ids.run],
    );
    expect(persisted.rows[0]).toEqual({
      status: 'completed',
      deploymentClass: 'external',
      profileVersion: externalProfileVersion,
      capabilityUsed: true,
      confirmationStatus: 'consumed',
    });
  });
});

function createE2eRuntime(
  prepared: PreparedDirectorFixture,
  options: {
    deploymentClass?: 'internal' | 'external';
    providerDataProfileVersion?: string | null;
  } = {},
) {
  const appReference: { director?: ReturnType<typeof buildDirectorApp> } = {};
  const directorClient = new HttpDirectorClient({
    baseUrl: 'http://director.internal/',
    tokenProvider: () => gatewayBearerToken,
    fetch: async (input, init) => {
      if (appReference.director === undefined) {
        throw new Error('Director app is not ready.');
      }
      return fastifyFetch(appReference.director)(input, init);
    },
    allowHttpForDevelopment: true,
  });
  const store = new MemoryExecutionStore();
  const adapter = new FixtureProviderAdapter();
  const gatewayService = new GatewayService({
    store,
    director: directorClient,
    adapters: [adapter],
    clock: prepared.clock,
    idGenerator: new SequentialIds(),
    autoProcess: false,
  });
  const gatewayApp = buildGatewayApp({
    service: gatewayService,
    authenticator: new GatewayAuthenticator({
      token: directorToGatewayToken,
      requireMutualTls: false,
    }),
  });
  const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x45));
  const agentGateway = new HttpAgentGatewayClient({
    baseUrl: 'http://gateway.internal/',
    tokenProvider: () => directorToGatewayToken,
    fetch: fastifyFetch(gatewayApp),
    allowHttpForDevelopment: true,
  });
  const directorApp = buildDirectorApp({
    service: prepared.service,
    authenticator: new DirectorAuthenticator({
      token: gatewayBearerToken,
      requireMutualTls: false,
    }),
    publicApi: {
      memoryIngest: new MemoryIngestService({
        repository: new PostgresMemoryIngestRepository(prepared.database),
        documentStore: prepared.documentStore,
        idGenerator: new FixedIds([ids.memoryObject, ids.documentVersion]),
      }),
      authenticator: new StaticUserBearerAuthenticator({
        token: publicUserToken,
        userId: ids.user,
      }),
      agentResults: new AgentResultService({
        repository: new PostgresAgentResultRepository(prepared.database),
        documentStore: prepared.documentStore,
        clock: prepared.clock,
      }),
      tasks: new TaskService({
        repository: new PostgresTaskRepository(prepared.database),
        gateway: agentGateway,
        capabilityTokens,
        routeResolver: new StaticAgentRouteResolver({
          routes: [
            {
              agentType: 'architect',
              provider: 'fixture',
              model: null,
              deploymentClass: options.deploymentClass ?? 'internal',
              providerDataProfileVersion: options.providerDataProfileVersion ?? null,
            },
          ],
        }),
        clock: prepared.clock,
        idGenerator: new FixedIds([ids.task, ids.run, ids.capability]),
      }),
      confirmations: new ConfirmationService({
        repository: new PostgresConfirmationRepository(prepared.database),
        gateway: agentGateway,
        capabilityTokens,
        clock: prepared.clock,
        idGenerator: new FixedIds([confirmationCapabilityId]),
      }),
      queries: new PublicQueryService({
        repository: new PostgresPublicQueryRepository(prepared.database),
      }),
    },
  });
  appReference.director = directorApp;
  return { directorApp, gatewayApp, gatewayService, adapter, store };
}

function confirmationIdFrom(payload: unknown): string {
  if (
    typeof payload === 'object' &&
    payload !== null &&
    'error' in payload &&
    typeof payload.error === 'object' &&
    payload.error !== null &&
    'details' in payload.error &&
    typeof payload.error.details === 'object' &&
    payload.error.details !== null &&
    'confirmation_id' in payload.error.details &&
    typeof payload.error.details.confirmation_id === 'string'
  ) {
    return payload.error.details.confirmation_id;
  }
  throw new Error('Confirmation response is missing confirmation_id.');
}

function memoryObjectIdFrom(payload: unknown): string {
  if (
    typeof payload === 'object' &&
    payload !== null &&
    'id' in payload &&
    typeof payload.id === 'string'
  ) {
    return payload.id;
  }
  throw new Error('Memory object response is missing id.');
}

class MemoryExecutionStore implements ExecutionStore {
  private readonly records = new Map<string, ExecutionRecord>();

  async load(agentRunId: string): Promise<ExecutionRecord | undefined> {
    const record = this.records.get(agentRunId);
    return record === undefined ? undefined : structuredClone(record);
  }

  async save(record: ExecutionRecord): Promise<void> {
    this.records.set(record.agentRunId, structuredClone(record));
  }

  async listPending(): Promise<ExecutionRecord[]> {
    return [...this.records.values()]
      .filter((record) => !['completed', 'failed', 'cancelled'].includes(record.phase))
      .map((record) => structuredClone(record));
  }
}

class SequentialIds implements IdGenerator {
  private value = 100;

  next(): string {
    const suffix = String(this.value++).padStart(12, '0');
    return `20000000-0000-4000-8000-${suffix}`;
  }
}

class FixedIds {
  constructor(private readonly values: string[]) {}

  next(): string {
    const value = this.values.shift();
    if (value === undefined) {
      throw new Error('Test ID sequence is exhausted.');
    }
    return value;
  }
}

async function documentUpload(content: string): Promise<{
  payload: Buffer;
  contentType: string;
}> {
  const form = new FormData();
  form.append('project_id', ids.project);
  form.append('type', 'document');
  form.append('title', 'Architecture');
  form.append('sensitivity_level', 'internal');
  form.append(
    'file',
    new Blob([Uint8Array.from(Buffer.from(content, 'utf8')).buffer], {
      type: 'text/markdown',
    }),
    'architecture.md',
  );
  const request = new Request('http://director.test/api/v1/memory-objects:upload', {
    method: 'POST',
    body: form,
  });
  const contentType = request.headers.get('content-type');
  if (contentType === null) {
    throw new Error('Multipart E2E request is missing its content type.');
  }
  return {
    payload: Buffer.from(await request.arrayBuffer()),
    contentType,
  };
}

function fastifyFetch(app: ReturnType<typeof buildDirectorApp>): typeof fetch {
  return async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    const payload = request.body === null ? undefined : await request.text();
    const injected = await app.inject({
      method: request.method as 'POST',
      url: `${url.pathname}${url.search}`,
      headers: Object.fromEntries(request.headers.entries()),
      ...(payload === undefined ? {} : { payload }),
    });
    const headers = new Headers();
    for (const [name, value] of Object.entries(injected.headers)) {
      if (value === undefined) {
        continue;
      }
      headers.set(name, Array.isArray(value) ? value.join(', ') : String(value));
    }
    return new Response(injected.body.length === 0 ? null : injected.body, {
      status: injected.statusCode,
      headers,
    });
  };
}
