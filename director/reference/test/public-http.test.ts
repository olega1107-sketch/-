import { afterEach, describe, expect, it } from 'vitest';

import { AgentResultService } from '../src/agent-result-service.js';
import { StaticAgentRouteResolver, type AgentRouteResolver } from '../src/agent-routing.js';
import { buildDirectorApp } from '../src/app.js';
import { sha256Text } from '../src/canonical.js';
import { HmacCapabilityTokenIssuer } from '../src/capability-token.js';
import { ConfirmationService } from '../src/confirmation-service.js';
import { DecisionService } from '../src/decision-service.js';
import { DirectorProtocolError } from '../src/errors.js';
import { MemoryIngestService } from '../src/memory-ingest-service.js';
import type { IdGenerator } from '../src/memory-ports.js';
import { PostgresMemoryIngestRepository } from '../src/postgres-memory-ingest-repository.js';
import { PostgresAgentResultRepository } from '../src/postgres-agent-result-repository.js';
import { PostgresAuthorizationAuditRecorder } from '../src/postgres-authorization-audit-recorder.js';
import { PostgresConfirmationRepository } from '../src/postgres-confirmation-repository.js';
import { PostgresDecisionRepository } from '../src/postgres-decision-repository.js';
import { PostgresPublicQueryRepository } from '../src/postgres-public-query-repository.js';
import { PostgresTaskRepository } from '../src/postgres-task-repository.js';
import { PostgresUserSessionAuthenticator } from '../src/postgres-user-session-authenticator.js';
import { PublicQueryService } from '../src/public-query-service.js';
import { StaticBearerAuthenticator } from '../src/service-auth.js';
import type { AgentGatewayClient, AgentGatewayDispatch } from '../src/task-ports.js';
import { TaskService } from '../src/task-service.js';
import { StaticUserBearerAuthenticator } from '../src/user-auth.js';
import {
  createDirectorFixture,
  completedEvent,
  fixtureRouteResolver,
  gatewayBearerToken,
  ids,
  startedEvent,
  type DirectorFixture,
} from './helpers.js';

const publicToken = 'test-public-user-token';
const objectId = '40000000-0000-4000-8000-000000000001';
const versionId = '40000000-0000-4000-8000-000000000002';
const requestId = '40000000-0000-4000-8000-000000000003';
const taskId = '40000000-0000-4000-8000-000000000004';
const runId = '40000000-0000-4000-8000-000000000005';
const capabilityId = '40000000-0000-4000-8000-000000000006';
const taskRequestId = '40000000-0000-4000-8000-000000000007';
const runRequestId = '40000000-0000-4000-8000-000000000008';
const readRequestId = '40000000-0000-4000-8000-000000000009';
const saveRequestId = '40000000-0000-4000-8000-000000000010';
const approvalRequestId = '40000000-0000-4000-8000-000000000011';
const userSessionId = '40000000-0000-4000-8000-000000000012';
const userSessionToken = 'session_http_y6NYqZpB7rJ2mR4xF8dV5A';
const deniedRequestId = '40000000-0000-4000-8000-000000000013';
const concealedRequestId = '40000000-0000-4000-8000-000000000014';
const policyDeniedRequestId = '40000000-0000-4000-8000-000000000015';
const viewerUserId = '40000000-0000-4000-8000-000000000016';
const outsiderUserId = '40000000-0000-4000-8000-000000000017';
const realNotFoundRequestId = '40000000-0000-4000-8000-000000000018';
const missingMemoryObjectId = '40000000-0000-4000-8000-000000000019';

describe('Public Director HTTP contract', () => {
  let fixture: DirectorFixture | undefined;
  let app: ReturnType<typeof buildDirectorApp> | undefined;

  afterEach(async () => {
    await app?.close();
    await fixture?.close();
    app = undefined;
    fixture = undefined;
  });

  it('accepts multipart fields after the file and returns the OpenAPI memory object', async () => {
    ({ fixture, app } = await createApp());
    const content = Buffer.from('# Public upload\nExact bytes.', 'utf8');
    const multipart = await uploadPayload(content, [
      ['project_id', ids.project],
      ['type', 'protocol'],
      ['title', '  Operating protocol  '],
      ['summary', '  Approved source  '],
      ['keywords', 'operations'],
      ['keywords', 'approved'],
      ['sensitivity_level', 'confidential'],
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/memory-objects:upload',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': requestId,
        'content-type': multipart.contentType,
      },
      payload: multipart.payload,
    });

    expect(response.statusCode, response.body).toBe(201);
    expect(response.headers['x-request-id']).toBe(requestId);
    expect(response.json()).toMatchObject({
      id: objectId,
      type: 'protocol',
      title: 'Operating protocol',
      project_id: ids.project,
      topic_id: null,
      current_version_id: versionId,
      author_user_id: ids.user,
      summary: 'Approved source',
      keywords: ['operations', 'approved'],
      status: 'active',
      sensitivity_level: 'confidential',
      archived_at: null,
      current_version: {
        id: versionId,
        memory_object_id: objectId,
        version_number: 1,
        file_name: 'architecture.md',
        file_type: 'text/markdown',
        size_bytes: content.byteLength,
        change_summary: null,
      },
    });
  });

  it('authenticates before buffering multipart bytes', async () => {
    ({ fixture, app } = await createApp());
    const immutableCount = fixture.documentStore.immutable.size;
    const multipart = await uploadPayload(Buffer.from('not authorized'), [
      ['project_id', ids.project],
      ['type', 'document'],
      ['title', 'Denied'],
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/memory-objects:upload',
      headers: {
        authorization: 'Bearer wrong-token',
        'x-request-id': requestId,
        'content-type': multipart.contentType,
      },
      payload: multipart.payload,
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: {
        code: 'unauthorized',
        message: 'User bearer is invalid.',
        details: {},
        request_id: requestId,
      },
    });
    expect(fixture.documentStore.immutable.size).toBe(immutableCount);
  });

  it('uses the database session verifier and applies revocation on the next HTTP request', async () => {
    ({ fixture, app } = await createSessionApp());

    const allowed = await app.inject({
      method: 'GET',
      url: `/api/v1/memory-objects/${ids.memoryObject}`,
      headers: {
        authorization: `Bearer ${userSessionToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(allowed.statusCode, allowed.body).toBe(200);

    await fixture.database.query(
      `UPDATE dirizhor.user_sessions SET revoked_at = $2::timestamptz WHERE id = $1::uuid`,
      [userSessionId, '2030-01-01T10:00:00Z'],
    );
    const denied = await app.inject({
      method: 'GET',
      url: `/api/v1/memory-objects/${ids.memoryObject}`,
      headers: {
        authorization: `Bearer ${userSessionToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(denied.statusCode, denied.body).toBe(401);
    expect(denied.json()).toMatchObject({
      error: { code: 'unauthorized', message: 'User bearer is invalid.' },
    });
  });

  it('requires X-Request-Id and uses the public error envelope', async () => {
    ({ app } = await createApp());
    const multipart = await uploadPayload(Buffer.from('missing request id'), [
      ['project_id', ids.project],
      ['type', 'document'],
      ['title', 'Missing request ID'],
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/memory-objects:upload',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'content-type': multipart.contentType,
      },
      payload: multipart.payload,
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation_error',
        details: { fields: expect.any(Array) },
        request_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      },
    });
    expect(response.json()).not.toHaveProperty('request_id');
  });

  it('maps the multipart file limit to payload_too_large', async () => {
    ({ fixture, app } = await createApp(4));
    const immutableCount = fixture.documentStore.immutable.size;
    const multipart = await uploadPayload(Buffer.from('five!'), [
      ['project_id', ids.project],
      ['type', 'document'],
      ['title', 'Too large'],
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/memory-objects:upload',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': requestId,
        'content-type': multipart.contentType,
      },
      payload: multipart.payload,
    });

    expect(response.statusCode, response.body).toBe(413);
    expect(response.json()).toEqual({
      error: {
        code: 'payload_too_large',
        message: 'The multipart upload exceeds an operational limit.',
        details: {},
        request_id: requestId,
      },
    });
    expect(fixture.documentStore.immutable.size).toBe(immutableCount);
  });

  it('creates a task and accepts an internal frozen agent run', async () => {
    const gateway = new RecordingGateway();
    ({ fixture, app } = await createApp(undefined, gateway));

    const taskResponse = await app.inject({
      method: 'POST',
      url: '/api/v1/tasks',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': taskRequestId,
      },
      payload: {
        project_id: ids.project,
        title: '  Review architecture  ',
        user_request: '  Review the immutable context.  ',
      },
    });
    expect(taskResponse.statusCode, taskResponse.body).toBe(201);
    expect(taskResponse.headers['x-request-id']).toBe(taskRequestId);
    expect(taskResponse.json()).toMatchObject({
      id: taskId,
      project_id: ids.project,
      created_by_user_id: ids.user,
      title: 'Review architecture',
      user_request: 'Review the immutable context.',
      status: 'created',
    });

    const runResponse = await app.inject({
      method: 'POST',
      url: `/api/v1/tasks/${taskId}/agent-runs`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': runRequestId,
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
    expect(runResponse.statusCode, runResponse.body).toBe(202);
    expect(runResponse.headers['x-request-id']).toBe(runRequestId);
    expect(runResponse.json()).toMatchObject({
      id: runId,
      task_id: taskId,
      status: 'queued',
      provider: 'fixture',
      deployment_class: 'internal',
      origin_request_id: runRequestId,
    });
    expect(gateway.calls).toHaveLength(1);
    expect(gateway.calls[0]).toMatchObject({ agentRunId: runId, requestId: runRequestId });
  });

  it('returns the OpenAPI error when an agent type has no configured route', async () => {
    const routeResolver = new StaticAgentRouteResolver({
      routes: [
        {
          agentType: 'architect',
          provider: 'fixture',
          model: null,
          deploymentClass: 'internal',
          providerDataProfileVersion: null,
        },
      ],
    });
    ({ app } = await createApp(undefined, new RecordingGateway(), routeResolver));
    await app.inject({
      method: 'POST',
      url: '/api/v1/tasks',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': taskRequestId,
      },
      payload: {
        project_id: ids.project,
        title: 'Review architecture',
        user_request: 'Review the immutable context.',
      },
    });

    const response = await app.inject({
      method: 'POST',
      url: `/api/v1/tasks/${taskId}/agent-runs`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': runRequestId,
      },
      payload: {
        agent_type: 'unmapped_agent',
        purpose: 'Review the architecture',
        instructions: 'Return only the final recommendation.',
        context: [
          {
            memory_object_id: ids.memoryObject,
            document_version_id: ids.documentVersion,
            access_reason: 'Primary architecture source',
          },
        ],
      },
    });

    expect(response.statusCode, response.body).toBe(409);
    expect(response.json()).toEqual({
      error: {
        code: 'agent_route_unavailable',
        message: 'No enabled provider route is configured for the requested agent type.',
        details: {},
        request_id: runRequestId,
      },
    });
  });

  it('serves task, run, and result reads and completes result-save confirmation', async () => {
    ({ fixture, app } = await createApp());
    await fixture.service.recordGatewayEvent(ids.run, startedEvent(fixture));
    await fixture.service.recordGatewayEvent(ids.run, completedEvent(fixture));
    fixture.clock.set('2030-01-01T10:01:00.000Z');

    const task = await app.inject({
      method: 'GET',
      url: `/api/v1/tasks/${ids.task}`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(task.statusCode, task.body).toBe(200);
    expect(task.headers['x-request-id']).toBe(readRequestId);
    expect(task.json()).toMatchObject({ id: ids.task, status: 'reviewing' });

    const run = await app.inject({
      method: 'GET',
      url: `/api/v1/agent-runs/${ids.run}`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(run.statusCode, run.body).toBe(200);
    expect(run.json()).toMatchObject({ id: ids.run, status: 'completed' });

    const result = await app.inject({
      method: 'GET',
      url: `/api/v1/agent-runs/${ids.run}/result`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(result.statusCode, result.body).toBe(200);
    expect(result.json()).toMatchObject({
      agent_run_id: ids.run,
      content: '# Recommendation\nKeep the immutable boundary.',
      saved_memory_object_id: null,
    });

    const save = await app.inject({
      method: 'POST',
      url: `/api/v1/agent-runs/${ids.run}/result:save`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': saveRequestId,
      },
      payload: { title: 'Approved architecture recommendation' },
    });
    expect(save.statusCode, save.body).toBe(428);
    expect(save.json()).toMatchObject({
      error: {
        code: 'requires_confirmation',
        details: { target_type: 'agent_run_result' },
        request_id: saveRequestId,
      },
    });
    const confirmationId = requiredConfirmationId(save.json());

    const approval = await app.inject({
      method: 'POST',
      url: `/api/v1/confirmations/${confirmationId}:approve`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': approvalRequestId,
      },
    });
    expect(approval.statusCode, approval.body).toBe(200);
    expect(approval.json()).toMatchObject({ id: confirmationId, status: 'consumed' });

    const saved = await app.inject({
      method: 'POST',
      url: `/api/v1/agent-runs/${ids.run}/result:save`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': saveRequestId,
      },
      payload: { title: 'Approved architecture recommendation' },
    });
    expect(saved.statusCode, saved.body).toBe(201);
    expect(saved.json()).toMatchObject({
      type: 'ai_result',
      title: 'Approved architecture recommendation',
      sensitivity_level: 'internal',
    });
  });

  it('serves memory search, memory read, task context, and task timeline contracts', async () => {
    ({ app } = await createApp());

    const search = await app.inject({
      method: 'GET',
      url: `/api/v1/memory-objects/search?project_id=${ids.project}&q=architecture`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(search.statusCode, search.body).toBe(200);
    expect(search.json()).toMatchObject({
      items: [{ id: ids.memoryObject, title: 'Architecture' }],
      next_cursor: null,
    });

    const memory = await app.inject({
      method: 'GET',
      url: `/api/v1/memory-objects/${ids.memoryObject}`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(memory.statusCode, memory.body).toBe(200);
    expect(memory.json()).toMatchObject({
      id: ids.memoryObject,
      current_version: { id: ids.documentVersion },
    });

    const context = await app.inject({
      method: 'POST',
      url: `/api/v1/tasks/${ids.task}/context:search`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': readRequestId,
      },
      payload: { query: 'architecture' },
    });
    expect(context.statusCode, context.body).toBe(200);
    expect(context.json()).toMatchObject({
      task_id: ids.task,
      candidates: [{ memory_object_id: ids.memoryObject, reason: 'Matched title' }],
    });

    const timeline = await app.inject({
      method: 'GET',
      url: `/api/v1/tasks/${ids.task}/timeline`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(timeline.statusCode, timeline.body).toBe(200);
    expect(timeline.json()).toMatchObject({
      items: [{ kind: 'agent_run', resource_id: ids.run }],
      next_cursor: null,
    });
  });

  it('creates and reads pilot decisions with complete provenance', async () => {
    ({ fixture, app } = await createApp());
    const decisionRequestId = '40000000-0000-4000-8000-000000000022';
    const provenanceRequestId = '40000000-0000-4000-8000-000000000023';
    const decisionId = '40000000-0000-4000-8000-000000000020';

    const created = await app.inject({
      method: 'POST',
      url: '/api/v1/decisions',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': decisionRequestId,
      },
      payload: {
        project_id: ids.project,
        title: 'Adopt immutable context',
        decision_text: 'Use exact document versions for every run.',
        status: 'proposed',
        relationships: [
          {
            target_type: 'agent_run',
            target_id: ids.run,
            relation_type: 'derived_from',
          },
        ],
      },
    });
    expect(created.statusCode, created.body).toBe(201);
    expect(created.json()).toMatchObject({
      id: decisionId,
      memory_object_id: '40000000-0000-4000-8000-000000000021',
      status: 'proposed',
    });

    const read = await app.inject({
      method: 'GET',
      url: `/api/v1/decisions/${decisionId}`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': readRequestId,
      },
    });
    expect(read.statusCode, read.body).toBe(200);
    expect(read.json()).toMatchObject({ id: decisionId, title: 'Adopt immutable context' });

    const provenance = await app.inject({
      method: 'GET',
      url: `/api/v1/decisions/${decisionId}/provenance`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': provenanceRequestId,
      },
    });
    expect(provenance.statusCode, provenance.body).toBe(200);
    expect(provenance.json()).toMatchObject({
      provenance_complete: true,
      decision: { id: decisionId },
      agent_runs: [{ id: ids.run }],
      source_versions: [{ document_version_id: ids.documentVersion }],
    });
  });

  it('rejects approved decision creation at the pilot transport boundary', async () => {
    ({ app } = await createApp());
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/decisions',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': requestId,
      },
      payload: {
        project_id: ids.project,
        title: 'Premature approval',
        decision_text: 'This must require a confirmation workflow.',
        status: 'approved',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'validation_error' } });
  });

  it('approves and supersedes decisions through public confirmation endpoints', async () => {
    ({ app } = await createApp());
    const decisionId = '40000000-0000-4000-8000-000000000020';
    const approvalRequestId = '40000000-0000-4000-8000-000000000030';
    const approvalConsumeRequestId = '40000000-0000-4000-8000-000000000031';
    const supersedeRequestId = '40000000-0000-4000-8000-000000000032';
    const supersedeConsumeRequestId = '40000000-0000-4000-8000-000000000033';
    const successorId = '40000000-0000-4000-8000-000000000024';
    await app.inject({
      method: 'POST',
      url: '/api/v1/decisions',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': '40000000-0000-4000-8000-000000000034',
      },
      payload: {
        project_id: ids.project,
        title: 'Pilot decision',
        decision_text: 'Use the pilot API.',
        status: 'proposed',
      },
    });

    const approvalRequired = await app.inject({
      method: 'POST',
      url: `/api/v1/decisions/${decisionId}:approve`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': approvalRequestId,
      },
    });
    expect(approvalRequired.statusCode, approvalRequired.body).toBe(428);
    const approvalId = requiredConfirmationId(approvalRequired.json());
    const approved = await app.inject({
      method: 'POST',
      url: `/api/v1/confirmations/${approvalId}:approve`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': approvalConsumeRequestId,
      },
    });
    expect(approved.statusCode, approved.body).toBe(200);
    expect(approved.json()).toMatchObject({
      operation: 'decision_approve',
      status: 'consumed',
    });

    const supersedeRequired = await app.inject({
      method: 'POST',
      url: `/api/v1/decisions/${decisionId}:supersede`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': supersedeRequestId,
      },
      payload: {
        title: 'Verified pilot decision',
        decision_text: 'Use only the verified pilot API.',
      },
    });
    expect(supersedeRequired.statusCode, supersedeRequired.body).toBe(428);
    const supersedeId = requiredConfirmationId(supersedeRequired.json());
    const superseded = await app.inject({
      method: 'POST',
      url: `/api/v1/confirmations/${supersedeId}:approve`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': supersedeConsumeRequestId,
      },
    });
    expect(superseded.statusCode, superseded.body).toBe(200);
    expect(superseded.json()).toMatchObject({
      operation: 'decision_supersede',
      status: 'consumed',
    });

    const replay = await app.inject({
      method: 'POST',
      url: `/api/v1/decisions/${decisionId}:supersede`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': supersedeRequestId,
      },
      payload: {
        title: 'Verified pilot decision',
        decision_text: 'Use only the verified pilot API.',
      },
    });
    expect(replay.statusCode, replay.body).toBe(201);
    expect(replay.json()).toMatchObject({
      superseded_decision: { id: decisionId, status: 'superseded' },
      new_decision: {
        id: successorId,
        status: 'approved',
        supersedes_decision_id: decisionId,
      },
    });
  });

  it('returns Gateway backpressure in the public error envelope', async () => {
    ({ app } = await createApp(undefined, new RecordingGateway(1)));
    await app.inject({
      method: 'POST',
      url: '/api/v1/tasks',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': taskRequestId,
      },
      payload: {
        project_id: ids.project,
        title: 'Review architecture',
        user_request: 'Review the immutable context.',
      },
    });

    const response = await app.inject({
      method: 'POST',
      url: `/api/v1/tasks/${taskId}/agent-runs`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': runRequestId,
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

    expect(response.statusCode, response.body).toBe(429);
    expect(response.json()).toEqual({
      error: {
        code: 'rate_limited',
        message: 'Fixture Gateway is full.',
        details: { retry_after_seconds: 3 },
        request_id: runRequestId,
      },
    });
  });

  it('records permission deny and access.denied atomically for a public operation', async () => {
    ({ fixture, app } = await createApp(
      undefined,
      new RecordingGateway(),
      fixtureRouteResolver(),
      viewerUserId,
    ));
    await createProjectUser(fixture, viewerUserId, 'viewer@example.test', 'project_viewer');

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/tasks',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': deniedRequestId,
      },
      payload: {
        project_id: ids.project,
        title: 'Forbidden task',
        user_request: 'This user cannot create tasks.',
      },
    });

    expect(response.statusCode, response.body).toBe(403);
    expect(response.json()).toMatchObject({
      error: {
        code: 'access_denied',
        details: { missing_permissions: ['task.create'] },
      },
    });
    const recorded = await authorizationRecord(fixture, deniedRequestId);
    expect(recorded).toMatchObject({
      action: 'task.create',
      resourceType: 'project',
      resourceId: ids.project,
      projectId: ids.project,
      decision: 'deny',
      reasonCodes: ['permission_missing'],
      auditAction: 'access.denied',
    });
    expect(recorded.auditDecisionId).toBe(recorded.decisionId);
    expect(recorded.metadata).toMatchObject({
      missing_permissions: ['task.create'],
      response_concealed: false,
      response_status: 403,
    });
  });

  it('records a concealed permission denial without changing the public 404', async () => {
    ({ fixture, app } = await createApp(
      undefined,
      new RecordingGateway(),
      fixtureRouteResolver(),
      outsiderUserId,
    ));
    await createProjectUser(fixture, outsiderUserId, 'outsider@example.test');

    const response = await app.inject({
      method: 'GET',
      url: `/api/v1/memory-objects/${ids.memoryObject}`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': concealedRequestId,
      },
    });

    expect(response.statusCode, response.body).toBe(404);
    expect(response.json()).toMatchObject({
      error: {
        code: 'not_found',
        details: { resource: 'memory_object', id: ids.memoryObject },
      },
    });
    const recorded = await authorizationRecord(fixture, concealedRequestId);
    expect(recorded).toMatchObject({
      action: 'memory_object.read',
      resourceType: 'memory_object',
      resourceId: ids.memoryObject,
      projectId: ids.project,
      reasonCodes: ['permission_missing'],
    });
    expect(recorded.metadata).toMatchObject({
      missing_permissions: ['project.read', 'memory_object.read'],
      response_concealed: true,
      response_status: 404,
      response_code: 'not_found',
    });
  });

  it('does not classify a genuinely missing resource as authorization deny', async () => {
    ({ fixture, app } = await createApp());

    const response = await app.inject({
      method: 'GET',
      url: `/api/v1/memory-objects/${missingMemoryObjectId}`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': realNotFoundRequestId,
      },
    });

    expect(response.statusCode, response.body).toBe(404);
    const decisions = await fixture.database.query<{ count: string }>(
      `
        SELECT count(*)::text AS count
        FROM dirizhor.authorization_decisions
        WHERE request_id = $1::uuid
      `,
      [realNotFoundRequestId],
    );
    expect(decisions.rows[0]?.count).toBe('0');
  });

  it('records the exact project-policy reason for a denied external run', async () => {
    const gateway = new RecordingGateway();
    ({ fixture, app } = await createApp(
      undefined,
      gateway,
      fixtureRouteResolver({
        deploymentClass: 'external',
        providerDataProfileVersion: 'fixture-profile-v1',
      }),
    ));
    await app.inject({
      method: 'POST',
      url: '/api/v1/tasks',
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': taskRequestId,
      },
      payload: {
        project_id: ids.project,
        title: 'External review',
        user_request: 'Review using an external provider.',
      },
    });

    const response = await app.inject({
      method: 'POST',
      url: `/api/v1/tasks/${taskId}/agent-runs`,
      headers: {
        authorization: `Bearer ${publicToken}`,
        'x-request-id': policyDeniedRequestId,
      },
      payload: {
        agent_type: 'architect',
        purpose: 'External architecture review',
        instructions: 'Return the recommendation.',
        context: [
          {
            memory_object_id: ids.memoryObject,
            document_version_id: ids.documentVersion,
            access_reason: 'Primary architecture source',
          },
        ],
      },
    });

    expect(response.statusCode, response.body).toBe(403);
    expect(response.json()).toMatchObject({
      error: {
        code: 'access_denied',
        details: { reason_codes: ['external_ai_disabled'] },
      },
    });
    expect(gateway.calls).toHaveLength(0);
    const recorded = await authorizationRecord(fixture, policyDeniedRequestId);
    expect(recorded).toMatchObject({
      action: 'agent_run.create',
      resourceType: 'task',
      resourceId: taskId,
      projectId: ids.project,
      reasonCodes: ['external_ai_disabled'],
    });
    expect(recorded.metadata).toMatchObject({
      reason_codes: ['external_ai_disabled'],
      missing_permissions: [],
      response_concealed: false,
    });
  });
});

async function createApp(
  maxUploadBytes?: number,
  gateway: AgentGatewayClient = new RecordingGateway(),
  routeResolver: AgentRouteResolver = fixtureRouteResolver(),
  publicUserId: string = ids.user,
): Promise<{
  fixture: DirectorFixture;
  app: ReturnType<typeof buildDirectorApp>;
}> {
  const fixture = await createDirectorFixture();
  const memoryIngest = new MemoryIngestService({
    repository: new PostgresMemoryIngestRepository(fixture.database),
    documentStore: fixture.documentStore,
    idGenerator: new SequenceIds([objectId, versionId]),
  });
  const app = buildDirectorApp({
    service: fixture.service,
    authenticator: new StaticBearerAuthenticator({
      token: gatewayBearerToken,
      requireMutualTls: false,
    }),
    publicApi: {
      memoryIngest,
      authenticator: new StaticUserBearerAuthenticator({ token: publicToken, userId: publicUserId }),
      authorizationAudit: new PostgresAuthorizationAuditRecorder({
        database: fixture.database,
        clock: fixture.clock,
      }),
      ...(maxUploadBytes === undefined ? {} : { maxUploadBytes }),
      agentResults: new AgentResultService({
        repository: new PostgresAgentResultRepository(fixture.database),
        documentStore: fixture.documentStore,
        clock: fixture.clock,
      }),
      tasks: new TaskService({
        repository: new PostgresTaskRepository(fixture.database),
        gateway,
        capabilityTokens: new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x44)),
        routeResolver,
        clock: fixture.clock,
        idGenerator: new SequenceIds([taskId, runId, capabilityId]),
      }),
      confirmations: new ConfirmationService({
        repository: new PostgresConfirmationRepository(fixture.database),
        gateway,
        capabilityTokens: new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x44)),
        clock: fixture.clock,
      }),
      decisions: new DecisionService({
        repository: new PostgresDecisionRepository(fixture.database),
        idGenerator: new SequenceIds([
          '40000000-0000-4000-8000-000000000020',
          '40000000-0000-4000-8000-000000000021',
          '40000000-0000-4000-8000-000000000024',
          '40000000-0000-4000-8000-000000000025',
          '40000000-0000-4000-8000-000000000026',
          '40000000-0000-4000-8000-000000000027',
        ]),
        clock: fixture.clock,
      }),
      queries: new PublicQueryService({
        repository: new PostgresPublicQueryRepository(fixture.database),
      }),
    },
  });
  return { fixture, app };
}

interface AuthorizationRecord {
  decisionId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  projectId: string | null;
  decision: string;
  reasonCodes: string[];
  auditAction: string;
  auditDecisionId: string;
  metadata: Record<string, unknown>;
}

async function authorizationRecord(
  fixture: DirectorFixture,
  requestId: string,
): Promise<AuthorizationRecord> {
  const result = await fixture.database.query<AuthorizationRecord>(
    `
      SELECT
        decision.id::text AS "decisionId",
        decision.action,
        decision.resource_type AS "resourceType",
        decision.resource_id::text AS "resourceId",
        decision.project_id::text AS "projectId",
        decision.decision,
        decision.reason_codes AS "reasonCodes",
        audit.action AS "auditAction",
        audit.authorization_decision_id::text AS "auditDecisionId",
        audit.metadata
      FROM dirizhor.authorization_decisions AS decision
      JOIN dirizhor.audit_events AS audit
        ON audit.authorization_decision_id = decision.id
      WHERE decision.request_id = $1::uuid
    `,
    [requestId],
  );
  const record = result.rows[0];
  if (record === undefined) {
    throw new Error('Authorization denial record is missing.');
  }
  return record;
}

async function createProjectUser(
  fixture: DirectorFixture,
  userId: string,
  login: string,
  roleCode?: string,
): Promise<void> {
  await fixture.database.query(
    `
      INSERT INTO dirizhor.app_users (id, login, display_name, status)
      VALUES ($1::uuid, $2, 'Authorization Test User', 'active')
    `,
    [userId, login],
  );
  if (roleCode === undefined) {
    return;
  }
  await fixture.database.query(
    `
      INSERT INTO dirizhor.role_assignments (
        principal_type,
        principal_id,
        role_id,
        scope_type,
        scope_id,
        granted_by_user_id
      )
      SELECT 'user', $1::uuid, role.id, 'project', $2::uuid, $1::uuid
      FROM dirizhor.roles AS role
      WHERE role.code = $3
    `,
    [userId, ids.project, roleCode],
  );
}

async function createSessionApp(): Promise<{
  fixture: DirectorFixture;
  app: ReturnType<typeof buildDirectorApp>;
}> {
  const fixture = await createDirectorFixture();
  await fixture.database.query(
    `
      INSERT INTO dirizhor.user_sessions (
        id, user_id, session_token_hash, authentication_method,
        created_at, expires_at
      )
      VALUES (
        $1::uuid, $2::uuid, $3, 'password',
        '2029-01-01T00:00:00Z', '2031-01-01T00:00:00Z'
      )
    `,
    [userSessionId, ids.user, sha256Text(userSessionToken)],
  );
  const app = buildDirectorApp({
    service: fixture.service,
    authenticator: new StaticBearerAuthenticator({
      token: gatewayBearerToken,
      requireMutualTls: false,
    }),
    publicApi: {
      memoryIngest: new MemoryIngestService({
        repository: new PostgresMemoryIngestRepository(fixture.database),
        documentStore: fixture.documentStore,
        idGenerator: new SequenceIds([objectId, versionId]),
      }),
      authenticator: new PostgresUserSessionAuthenticator({
        database: fixture.database,
        clock: fixture.clock,
      }),
      queries: new PublicQueryService({
        repository: new PostgresPublicQueryRepository(fixture.database),
      }),
    },
  });
  return { fixture, app };
}

function requiredConfirmationId(value: unknown): string {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('error' in value) ||
    typeof value.error !== 'object' ||
    value.error === null ||
    !('details' in value.error) ||
    typeof value.error.details !== 'object' ||
    value.error.details === null ||
    !('confirmation_id' in value.error.details) ||
    typeof value.error.details.confirmation_id !== 'string'
  ) {
    throw new Error('Response does not contain a confirmation ID.');
  }
  return value.error.details.confirmation_id;
}

async function uploadPayload(
  content: Uint8Array,
  fieldsAfterFile: ReadonlyArray<readonly [string, string]>,
): Promise<{ payload: Buffer; contentType: string }> {
  const form = new FormData();
  form.append(
    'file',
    new Blob([Uint8Array.from(content).buffer], { type: 'text/markdown' }),
    'architecture.md',
  );
  for (const [name, value] of fieldsAfterFile) {
    form.append(name, value);
  }
  const request = new Request('http://director.test/api/v1/memory-objects:upload', {
    method: 'POST',
    body: form,
  });
  const contentType = request.headers.get('content-type');
  if (contentType === null) {
    throw new Error('Multipart test request is missing its content type.');
  }
  return {
    payload: Buffer.from(await request.arrayBuffer()),
    contentType,
  };
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

class RecordingGateway implements AgentGatewayClient {
  readonly calls: AgentGatewayDispatch[] = [];

  constructor(private failuresRemaining = 0) {}

  async dispatch(input: AgentGatewayDispatch): Promise<void> {
    this.calls.push(structuredClone(input));
    if (this.failuresRemaining > 0) {
      this.failuresRemaining -= 1;
      throw new DirectorProtocolError(
        429,
        'rate_limited',
        'Fixture Gateway is full.',
        true,
        { retry_after_seconds: 3 },
      );
    }
  }
}
