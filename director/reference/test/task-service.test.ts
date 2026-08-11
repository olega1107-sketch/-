import { afterEach, describe, expect, it } from 'vitest';

import {
  StaticAgentRouteResolver,
  type AgentRoute,
  type AgentRouteResolver,
} from '../src/agent-routing.js';
import { computeRequestFingerprint, sha256Text } from '../src/canonical.js';
import { HmacCapabilityTokenIssuer } from '../src/capability-token.js';
import { DirectorProtocolError } from '../src/errors.js';
import type { IdGenerator } from '../src/memory-ports.js';
import { PostgresTaskRepository } from '../src/postgres-task-repository.js';
import type { AgentGatewayClient, AgentGatewayDispatch } from '../src/task-ports.js';
import { TaskService } from '../src/task-service.js';
import {
  createDirectorFixture,
  fixtureRouteResolver,
  ids,
  type DirectorFixture,
  type PGliteDatabase,
} from './helpers.js';

const taskId = '30000000-0000-4000-8000-000000000001';
const taskRetryId = '30000000-0000-4000-8000-000000000002';
const taskConflictId = '30000000-0000-4000-8000-000000000003';
const taskRequestId = '30000000-0000-4000-8000-000000000004';
const runId = '30000000-0000-4000-8000-000000000005';
const capabilityId = '30000000-0000-4000-8000-000000000006';
const runRetryId = '30000000-0000-4000-8000-000000000007';
const capabilityRetryId = '30000000-0000-4000-8000-000000000008';
const runRequestId = '30000000-0000-4000-8000-000000000009';
const editorId = '30000000-0000-4000-8000-000000000010';
const editorAssignmentId = '30000000-0000-4000-8000-000000000011';
const editorTaskId = '30000000-0000-4000-8000-000000000012';
const editorRunId = '30000000-0000-4000-8000-000000000013';
const editorCapabilityId = '30000000-0000-4000-8000-000000000014';
const editorTaskRequestId = '30000000-0000-4000-8000-000000000015';
const editorRunRequestId = '30000000-0000-4000-8000-000000000016';

describe('Task service PostgreSQL lifecycle', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('creates a task atomically and replays the same request idempotently', async () => {
    fixture = await createDirectorFixture();
    const { service } = taskRuntime(
      fixture,
      new SequenceIds([taskId, taskRetryId, taskConflictId]),
    );

    const created = await service.createTask(ids.user, taskRequestId, taskInput());
    const replayed = await service.createTask(ids.user, taskRequestId, taskInput());

    expect(created).toMatchObject({ id: taskId, status: 'created' });
    expect(replayed).toEqual(created);
    await expect(
      service.createTask(ids.user, taskRequestId, {
        ...taskInput(),
        title: 'Different request',
      }),
    ).rejects.toMatchObject({ statusCode: 409, code: 'conflict' });

    const persisted = await fixture.database.query<{
      taskCount: number | string;
      auditCount: number | string;
      allowDecisionCount: number | string;
      linkedAuditCount: number | string;
    }>(
      `
        SELECT
          (SELECT count(*) FROM dirizhor.tasks WHERE id = $1::uuid) AS "taskCount",
          (
            SELECT count(*)
            FROM dirizhor.audit_events
            WHERE request_id = $2::uuid AND action = 'task.created'
          ) AS "auditCount",
          (
            SELECT count(*)
            FROM dirizhor.authorization_decisions
            WHERE request_id = $2::uuid
              AND action = 'task.create'
              AND decision = 'allow'
          ) AS "allowDecisionCount",
          (
            SELECT count(*)
            FROM dirizhor.audit_events AS audit
            JOIN dirizhor.authorization_decisions AS decision
              ON decision.id = audit.authorization_decision_id
            WHERE audit.request_id = $2::uuid
              AND audit.action = 'task.created'
              AND decision.decision = 'allow'
          ) AS "linkedAuditCount"
      `,
      [taskId, taskRequestId],
    );
    expect(Number(persisted.rows[0]?.taskCount)).toBe(1);
    expect(Number(persisted.rows[0]?.auditCount)).toBe(1);
    expect(Number(persisted.rows[0]?.allowDecisionCount)).toBe(1);
    expect(Number(persisted.rows[0]?.linkedAuditCount)).toBe(1);
  });

  it('freezes context, capability, task transition, and dispatch in one transaction', async () => {
    fixture = await createDirectorFixture();
    const gateway = new RecordingGateway();
    const { service, capabilityTokens } = taskRuntime(
      fixture,
      new SequenceIds([taskId, runId, capabilityId]),
      gateway,
    );
    await service.createTask(ids.user, taskRequestId, taskInput());

    const run = await service.createAgentRun(ids.user, taskId, runRequestId, runInput());

    expect(run).toMatchObject({
      id: runId,
      task_id: taskId,
      project_id: ids.project,
      status: 'queued',
      provider: 'fixture',
      deployment_class: 'internal',
      origin_request_id: runRequestId,
    });
    expect(gateway.calls).toHaveLength(1);
    const dispatch = gateway.calls[0];
    if (dispatch === undefined) {
      throw new Error('Gateway dispatch was not recorded.');
    }
    expect(dispatch).toMatchObject({ agentRunId: runId, requestId: runRequestId });
    expect(dispatch.capability).toBe(capabilityTokens.issue(capabilityId));
    expect(dispatch.request.context_set_hash).toBe(run.context_set_hash);
    expect(dispatch.request.request_fingerprint).toBe(
      computeRequestFingerprint(runId, dispatch.request),
    );

    const persisted = await fixture.database.query<{
      taskStatus: string;
      runStatus: string;
      contextCount: number | string;
      resourceCount: number | string;
      auditCount: number | string;
      allowDecisionCount: number | string;
      linkedAuditCount: number | string;
      linkedDecisionCount: number | string;
      tokenHash: string;
    }>(
      `
        SELECT
          task.status AS "taskStatus",
          run.status AS "runStatus",
          capability.token_hash AS "tokenHash",
          (
            SELECT count(*) FROM dirizhor.agent_run_contexts
            WHERE agent_run_id = run.id
          ) AS "contextCount",
          (
            SELECT count(*) FROM dirizhor.agent_capability_resources
            WHERE agent_capability_id = capability.id
          ) AS "resourceCount",
          (
            SELECT count(*) FROM dirizhor.audit_events
            WHERE request_id = $3::uuid
              AND action IN (
                'agent_run.dispatched', 'memory_object.read', 'agent_context.attached'
              )
          ) AS "auditCount",
          (
            SELECT count(*) FROM dirizhor.authorization_decisions
            WHERE request_id = $3::uuid
              AND action = 'agent_run.create'
              AND decision = 'allow'
          ) AS "allowDecisionCount",
          (
            SELECT count(*) FROM dirizhor.audit_events AS audit
            JOIN dirizhor.authorization_decisions AS decision
              ON decision.id = audit.authorization_decision_id
            WHERE audit.request_id = $3::uuid
              AND audit.action IN (
                'agent_run.dispatched', 'memory_object.read', 'agent_context.attached'
              )
              AND decision.decision = 'allow'
          ) AS "linkedAuditCount",
          (
            SELECT count(DISTINCT audit.authorization_decision_id)
            FROM dirizhor.audit_events AS audit
            WHERE audit.request_id = $3::uuid
              AND audit.action IN (
                'agent_run.dispatched', 'memory_object.read', 'agent_context.attached'
              )
          ) AS "linkedDecisionCount"
        FROM dirizhor.tasks AS task
        JOIN dirizhor.agent_runs AS run ON run.task_id = task.id
        JOIN dirizhor.agent_capabilities AS capability ON capability.agent_run_id = run.id
        WHERE task.id = $1::uuid AND run.id = $2::uuid
      `,
      [taskId, runId, runRequestId],
    );
    const row = persisted.rows[0];
    expect(row?.taskStatus).toBe('running_agent');
    expect(row?.runStatus).toBe('queued');
    expect(Number(row?.contextCount)).toBe(1);
    expect(Number(row?.resourceCount)).toBe(1);
    expect(Number(row?.auditCount)).toBe(3);
    expect(Number(row?.allowDecisionCount)).toBe(1);
    expect(Number(row?.linkedAuditCount)).toBe(3);
    expect(Number(row?.linkedDecisionCount)).toBe(1);
    expect(row?.tokenHash).toBe(sha256Text(capabilityTokens.issue(capabilityId)));
  });

  it('selects provider, model, and deployment from the requested agent type', async () => {
    fixture = await createDirectorFixture();
    const gateway = new RecordingGateway();
    const routeResolver = new StaticAgentRouteResolver({
      routes: [
        {
          agentType: 'architect',
          provider: 'architecture-provider',
          model: 'architecture-v2',
          deploymentClass: 'internal',
          providerDataProfileVersion: null,
        },
      ],
    });
    const { service } = taskRuntime(
      fixture,
      new SequenceIds([taskId, runId, capabilityId]),
      gateway,
      routeResolver,
    );
    await service.createTask(ids.user, taskRequestId, taskInput());

    const run = await service.createAgentRun(ids.user, taskId, runRequestId, runInput());

    expect(run).toMatchObject({
      provider: 'architecture-provider',
      model: 'architecture-v2',
      deployment_class: 'internal',
    });
    expect(gateway.calls[0]?.request).toMatchObject({
      provider: 'architecture-provider',
      model: 'architecture-v2',
    });
  });

  it('rejects an unmapped agent type without creating a run', async () => {
    fixture = await createDirectorFixture();
    const routeResolver = new StaticAgentRouteResolver({
      routes: [
        {
          agentType: 'researcher',
          provider: 'research-provider',
          model: null,
          deploymentClass: 'internal',
          providerDataProfileVersion: null,
        },
      ],
    });
    const { service } = taskRuntime(
      fixture,
      new SequenceIds([taskId, runId, capabilityId]),
      new RecordingGateway(),
      routeResolver,
    );
    await service.createTask(ids.user, taskRequestId, taskInput());

    await expect(
      service.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    ).rejects.toMatchObject({ statusCode: 409, code: 'agent_route_unavailable' });
    const runs = await fixture.database.query<{ count: number | string }>(
      `SELECT count(*) AS count FROM dirizhor.agent_runs WHERE origin_request_id = $1::uuid`,
      [runRequestId],
    );
    expect(Number(runs.rows[0]?.count)).toBe(0);
  });

  it('keeps a queued run after dispatch failure and retries the frozen envelope', async () => {
    fixture = await createDirectorFixture();
    const gateway = new RecordingGateway(1);
    const routeResolver = new MutableAgentRouteResolver({
      provider: 'fixture',
      model: null,
      deploymentClass: 'internal',
      providerDataProfileVersion: null,
    });
    const { service } = taskRuntime(
      fixture,
      new SequenceIds([
        taskId,
        runId,
        capabilityId,
        runRetryId,
        capabilityRetryId,
      ]),
      gateway,
      routeResolver,
    );
    await service.createTask(ids.user, taskRequestId, taskInput());

    await expect(
      service.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    ).rejects.toMatchObject({ statusCode: 500, code: 'internal_error', retryable: true });
    routeResolver.set({
      provider: 'replacement-provider',
      model: 'replacement-model',
      deploymentClass: 'internal',
      providerDataProfileVersion: null,
    });
    const replayed = await service.createAgentRun(ids.user, taskId, runRequestId, runInput());

    expect(replayed.id).toBe(runId);
    expect(gateway.calls).toHaveLength(2);
    expect(gateway.calls[1]).toEqual(gateway.calls[0]);
    const persisted = await fixture.database.query<{
      count: number | string;
      status: string;
      allowDecisionCount: number | string;
    }>(
      `
        SELECT
          count(*) AS count,
          min(status) AS status,
          (
            SELECT count(*) FROM dirizhor.authorization_decisions
            WHERE request_id = $1::uuid
              AND action = 'agent_run.create'
              AND decision = 'allow'
          ) AS "allowDecisionCount"
        FROM dirizhor.agent_runs
        WHERE origin_request_id = $1::uuid
      `,
      [runRequestId],
    );
    expect(Number(persisted.rows[0]?.count)).toBe(1);
    expect(persisted.rows[0]?.status).toBe('queued');
    expect(Number(persisted.rows[0]?.allowDecisionCount)).toBe(1);
  });

  it('rejects confidential dispatch when the current role cannot share it', async () => {
    fixture = await createDirectorFixture();
    await assignProjectEditor(fixture.database);
    await fixture.database.query(
      `UPDATE dirizhor.memory_objects SET sensitivity_level = 'confidential' WHERE id = $1::uuid`,
      [ids.memoryObject],
    );
    const gateway = new RecordingGateway();
    const { service } = taskRuntime(
      fixture,
      new SequenceIds([editorTaskId, editorRunId, editorCapabilityId]),
      gateway,
    );
    await service.createTask(editorId, editorTaskRequestId, taskInput());

    await expect(
      service.createAgentRun(editorId, editorTaskId, editorRunRequestId, runInput()),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'access_denied',
      details: { missing_permissions: ['agent_context.share_confidential'] },
    });
    expect(gateway.calls).toHaveLength(0);
    const persisted = await fixture.database.query<{ count: number | string }>(
      `SELECT count(*) AS count FROM dirizhor.agent_runs WHERE id = $1::uuid`,
      [editorRunId],
    );
    expect(Number(persisted.rows[0]?.count)).toBe(0);
  });

  it('rejects blank semantic fields as public validation errors', async () => {
    fixture = await createDirectorFixture();
    const { service } = taskRuntime(fixture, new SequenceIds([taskId]));

    await expect(
      service.createTask(ids.user, taskRequestId, { ...taskInput(), title: '   ' }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'validation_error' });
  });
});

function taskInput() {
  return {
    project_id: ids.project,
    title: 'Review architecture',
    user_request: 'Review the frozen architecture context.',
  };
}

function runInput() {
  return {
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
  };
}

function taskRuntime(
  fixture: DirectorFixture,
  idGenerator: IdGenerator,
  gateway: AgentGatewayClient = new RecordingGateway(),
  routeResolver: AgentRouteResolver = fixtureRouteResolver(),
): {
  service: TaskService;
  capabilityTokens: HmacCapabilityTokenIssuer;
} {
  const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x5a));
  return {
    capabilityTokens,
    service: new TaskService({
      repository: new PostgresTaskRepository(fixture.database),
      gateway,
      capabilityTokens,
      routeResolver,
      clock: fixture.clock,
      idGenerator,
    }),
  };
}

class MutableAgentRouteResolver implements AgentRouteResolver {
  constructor(private route: AgentRoute | null) {}

  resolve(): AgentRoute | null {
    return this.route;
  }

  set(route: AgentRoute | null): void {
    this.route = route;
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
        500,
        'internal_error',
        'Fixture gateway did not accept the run.',
        true,
      );
    }
  }
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

async function assignProjectEditor(database: PGliteDatabase): Promise<void> {
  await database.transaction(async (transaction) => {
    await transaction.query(
      `
        INSERT INTO dirizhor.app_users (id, login, display_name, status)
        VALUES ($1::uuid, 'editor@example.test', 'Test Editor', 'active')
      `,
      [editorId],
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
        WHERE role.code = 'project_editor'
      `,
      [editorAssignmentId, editorId, ids.project, ids.user],
    );
  });
}
