import { afterEach, describe, expect, it } from 'vitest';

import { sha256Bytes } from '../src/canonical.js';
import { HmacCapabilityTokenIssuer } from '../src/capability-token.js';
import { ConfirmationService } from '../src/confirmation-service.js';
import { DirectorProtocolError } from '../src/errors.js';
import type { IdGenerator } from '../src/memory-ports.js';
import { PostgresConfirmationRepository } from '../src/postgres-confirmation-repository.js';
import { PostgresTaskRepository } from '../src/postgres-task-repository.js';
import type { AgentGatewayClient, AgentGatewayDispatch } from '../src/task-ports.js';
import { TaskService } from '../src/task-service.js';
import {
  createDirectorFixture,
  fixtureRouteResolver,
  ids,
  type DirectorFixture,
} from './helpers.js';

const taskId = '50000000-0000-4000-8000-000000000001';
const runId = '50000000-0000-4000-8000-000000000002';
const unusedCapabilityId = '50000000-0000-4000-8000-000000000003';
const approvalCapabilityId = '50000000-0000-4000-8000-000000000004';
const retryUnusedCapabilityId = '50000000-0000-4000-8000-000000000005';
const taskRequestId = '50000000-0000-4000-8000-000000000006';
const runRequestId = '50000000-0000-4000-8000-000000000007';
const approvalRequestId = '50000000-0000-4000-8000-000000000008';
const retryRequestId = '50000000-0000-4000-8000-000000000009';
const rejectionRequestId = '50000000-0000-4000-8000-000000000010';
const profileVersion = 'fixture-external-v1';
const secondMemoryObjectId = '50000000-0000-4000-8000-000000000011';
const secondDocumentVersionId = '50000000-0000-4000-8000-000000000012';
const retryRunId = '50000000-0000-4000-8000-000000000013';
const retryCapabilityId = '50000000-0000-4000-8000-000000000014';
const approverId = '50000000-0000-4000-8000-000000000015';
const approverAssignmentId = '50000000-0000-4000-8000-000000000016';
const confirmationReadRequestId = '50000000-0000-4000-8000-000000000017';

describe('Confirmation workflow', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('approves and idempotently dispatches the same external frozen run', async () => {
    fixture = await createDirectorFixture();
    await allowExternalFixture(fixture);
    const gateway = new RecordingGateway();
    const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x51));
    const tasks = externalTaskService(fixture, gateway, capabilityTokens);
    const confirmations = new ConfirmationService({
      repository: new PostgresConfirmationRepository(fixture.database),
      gateway,
      capabilityTokens,
      clock: fixture.clock,
      idGenerator: new SequenceIds([approvalCapabilityId, retryUnusedCapabilityId]),
    });
    await tasks.createTask(ids.user, taskRequestId, taskInput());

    const confirmationError = await requiresConfirmation(
      tasks.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    );
    const confirmationId = requiredString(
      confirmationError.details.confirmation_id,
      'confirmation_id',
    );
    expect(confirmationError).toMatchObject({
      statusCode: 428,
      code: 'requires_confirmation',
      details: {
        target_type: 'agent_run',
        target_id: runId,
        payload_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      },
    });
    expect(gateway.calls).toHaveLength(0);
    const replayedError = await requiresConfirmation(
      tasks.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    );
    expect(replayedError.details).toEqual(confirmationError.details);
    expect(
      await confirmations.getConfirmation(
        ids.user,
        confirmationReadRequestId,
        confirmationId,
      ),
    ).toMatchObject({
      id: confirmationId,
      operation: 'agent_context_share',
      target_id: runId,
      status: 'pending',
    });

    const approved = await confirmations.approveConfirmation(
      ids.user,
      confirmationId,
      approvalRequestId,
    );
    expect(approved).toMatchObject({
      id: confirmationId,
      status: 'consumed',
      decided_by_user_id: ids.user,
      consumed_at: expect.any(String),
    });
    expect(gateway.calls).toHaveLength(1);
    expect(gateway.calls[0]).toMatchObject({
      agentRunId: runId,
      requestId: approvalRequestId,
      capability: capabilityTokens.issue(approvalCapabilityId),
      request: {
        deployment_class: 'external',
        provider_data_profile_version: profileVersion,
      },
    });

    const replayed = await confirmations.approveConfirmation(
      ids.user,
      confirmationId,
      retryRequestId,
    );
    expect(replayed).toEqual(approved);
    expect(gateway.calls).toHaveLength(2);
    expect(gateway.calls[1]).toMatchObject({
      agentRunId: runId,
      requestId: retryRequestId,
      capability: capabilityTokens.issue(approvalCapabilityId),
      request: gateway.calls[0]?.request,
    });

    const persisted = await fixture.database.query<{
      runStatus: string;
      taskStatus: string;
      capabilityCount: number | string;
      approvalAuditCount: number | string;
      freezeAuditCount: number | string;
    }>(
      `
        SELECT
          run.status AS "runStatus",
          task.status AS "taskStatus",
          (
            SELECT count(*) FROM dirizhor.agent_capabilities
            WHERE agent_run_id = run.id
          ) AS "capabilityCount",
          (
            SELECT count(*) FROM dirizhor.audit_events
            WHERE request_id = $2::uuid
              AND action IN (
                'confirmation.approved', 'confirmation.consumed', 'agent_run.dispatched'
              )
          ) AS "approvalAuditCount",
          (
            SELECT count(*) FROM dirizhor.audit_events
            WHERE request_id = $3::uuid
              AND action IN (
                'confirmation.created', 'memory_object.read', 'agent_context.attached'
              )
          ) AS "freezeAuditCount"
        FROM dirizhor.agent_runs AS run
        JOIN dirizhor.tasks AS task ON task.id = run.task_id
        WHERE run.id = $1::uuid
      `,
      [runId, approvalRequestId, runRequestId],
    );
    const row = persisted.rows[0];
    expect(row?.runStatus).toBe('queued');
    expect(row?.taskStatus).toBe('running_agent');
    expect(Number(row?.capabilityCount)).toBe(1);
    expect(Number(row?.approvalAuditCount)).toBe(3);
    expect(Number(row?.freezeAuditCount)).toBe(3);

    const currentAuthorization = await fixture.database.query<{
      action: string;
      decision: string;
      decisionId: string;
      auditAction: string;
      auditDecisionId: string;
    }>(
      `
        SELECT
          decision.action,
          decision.decision,
          decision.id::text AS "decisionId",
          audit.action AS "auditAction",
          audit.authorization_decision_id::text AS "auditDecisionId"
        FROM dirizhor.authorization_decisions AS decision
        JOIN dirizhor.audit_events AS audit
          ON audit.authorization_decision_id = decision.id
        WHERE decision.resource_type = 'confirmation'
          AND decision.resource_id = $1::uuid
        ORDER BY decision.created_at, decision.id
      `,
      [confirmationId],
    );
    expect(currentAuthorization.rows).toHaveLength(3);
    expect(currentAuthorization.rows.map((authorization) => authorization.action)).toEqual([
      'confirmation.read',
      'confirmation.approve',
      'confirmation.approve',
    ]);
    expect(
      currentAuthorization.rows.every(
        (authorization) =>
          authorization.decision === 'allow' &&
          authorization.auditAction === 'access.allowed' &&
          authorization.decisionId === authorization.auditDecisionId,
      ),
    ).toBe(true);
    const lifecycleAuthorization = await fixture.database.query<{ decision: string }>(
      `
        SELECT decision.decision
        FROM dirizhor.audit_events AS audit
        JOIN dirizhor.authorization_decisions AS decision
          ON decision.id = audit.authorization_decision_id
        WHERE audit.action = 'confirmation.approved'
          AND audit.target_id = $1::uuid
      `,
      [confirmationId],
    );
    expect(lifecycleAuthorization.rows).toEqual([{ decision: 'require_confirmation' }]);
  });

  it('rejects a pending run without issuing a capability', async () => {
    fixture = await createDirectorFixture();
    await allowExternalFixture(fixture);
    const gateway = new RecordingGateway();
    const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x52));
    const tasks = externalTaskService(fixture, gateway, capabilityTokens);
    const confirmations = new ConfirmationService({
      repository: new PostgresConfirmationRepository(fixture.database),
      gateway,
      capabilityTokens,
      clock: fixture.clock,
    });
    await tasks.createTask(ids.user, taskRequestId, taskInput());
    const error = await requiresConfirmation(
      tasks.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    );
    const confirmationId = requiredString(error.details.confirmation_id, 'confirmation_id');

    const rejected = await confirmations.rejectConfirmation(
      ids.user,
      confirmationId,
      rejectionRequestId,
    );
    const replayed = await confirmations.rejectConfirmation(
      ids.user,
      confirmationId,
      retryRequestId,
    );

    expect(rejected).toMatchObject({ status: 'rejected', decided_by_user_id: ids.user });
    expect(replayed).toEqual(rejected);
    expect(gateway.calls).toHaveLength(0);
    const persisted = await fixture.database.query<{
      runStatus: string;
      taskStatus: string;
      capabilityCount: number | string;
    }>(
      `
        SELECT
          run.status AS "runStatus",
          task.status AS "taskStatus",
          (
            SELECT count(*) FROM dirizhor.agent_capabilities
            WHERE agent_run_id = run.id
          ) AS "capabilityCount"
        FROM dirizhor.agent_runs AS run
        JOIN dirizhor.tasks AS task ON task.id = run.task_id
        WHERE run.id = $1::uuid
      `,
      [runId],
    );
    expect(persisted.rows[0]?.runStatus).toBe('cancelled');
    expect(persisted.rows[0]?.taskStatus).toBe('cancelled');
    expect(Number(persisted.rows[0]?.capabilityCount)).toBe(0);
  });

  it('denies external execution before creating a run when project policy is disabled', async () => {
    fixture = await createDirectorFixture();
    const gateway = new RecordingGateway();
    const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x53));
    const tasks = externalTaskService(fixture, gateway, capabilityTokens);
    await tasks.createTask(ids.user, taskRequestId, taskInput());

    await expect(
      tasks.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'access_denied',
      details: { reason_codes: ['external_ai_disabled'] },
    });
    const persisted = await fixture.database.query<{ count: number | string }>(
      `SELECT count(*) AS count FROM dirizhor.agent_runs WHERE id = $1::uuid`,
      [runId],
    );
    expect(Number(persisted.rows[0]?.count)).toBe(0);
    expect(gateway.calls).toHaveLength(0);
  });

  it('dispatches allowed external internal-level context without confirmation when policy permits', async () => {
    fixture = await createDirectorFixture();
    await allowExternalFixture(fixture);
    await fixture.database.query(
      `
        UPDATE dirizhor.project_ai_policies
        SET confirm_internal_external_share = false
        WHERE project_id = $1::uuid
      `,
      [ids.project],
    );
    const gateway = new RecordingGateway();
    const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x57));
    const tasks = externalTaskService(fixture, gateway, capabilityTokens);
    await tasks.createTask(ids.user, taskRequestId, taskInput());

    const run = await tasks.createAgentRun(ids.user, taskId, runRequestId, runInput());

    expect(run).toMatchObject({
      id: runId,
      status: 'queued',
      deployment_class: 'external',
      provider_data_profile_version: profileVersion,
    });
    expect(gateway.calls).toHaveLength(1);
    const persisted = await fixture.database.query<{ count: number | string }>(
      `SELECT count(*) AS count FROM dirizhor.confirmations WHERE target_id = $1::uuid`,
      [runId],
    );
    expect(Number(persisted.rows[0]?.count)).toBe(0);
  });

  it('requires and consumes a bulk-context confirmation for an internal run', async () => {
    fixture = await createDirectorFixture();
    await seedSecondContext(fixture);
    await fixture.database.query(
      `
        UPDATE dirizhor.project_ai_policies
        SET bulk_context_object_limit = 1
        WHERE project_id = $1::uuid
      `,
      [ids.project],
    );
    const gateway = new RecordingGateway();
    const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x54));
    const tasks = new TaskService({
      repository: new PostgresTaskRepository(fixture.database),
      gateway,
      capabilityTokens,
      routeResolver: fixtureRouteResolver(),
      clock: fixture.clock,
      idGenerator: new SequenceIds([taskId, runId, unusedCapabilityId]),
    });
    const confirmations = new ConfirmationService({
      repository: new PostgresConfirmationRepository(fixture.database),
      gateway,
      capabilityTokens,
      clock: fixture.clock,
      idGenerator: new SequenceIds([approvalCapabilityId]),
    });
    await tasks.createTask(ids.user, taskRequestId, taskInput());

    const error = await requiresConfirmation(
      tasks.createAgentRun(ids.user, taskId, runRequestId, bulkRunInput()),
    );
    const confirmationId = requiredString(error.details.confirmation_id, 'confirmation_id');
    expect(
      await confirmations.getConfirmation(
        ids.user,
        confirmationReadRequestId,
        confirmationId,
      ),
    ).toMatchObject({
      operation: 'bulk_context_share',
      status: 'pending',
    });

    await confirmations.approveConfirmation(ids.user, confirmationId, approvalRequestId);
    expect(gateway.calls).toHaveLength(1);
    expect(gateway.calls[0]?.request).toMatchObject({
      deployment_class: 'internal',
      context_item_count: 2,
      max_context_sensitivity: 'internal',
    });
  });

  it('revokes confirmation when current sensitivity changes the frozen payload', async () => {
    fixture = await createDirectorFixture();
    await allowExternalFixture(fixture);
    await fixture.database.query(
      `
        UPDATE dirizhor.project_ai_policies
        SET max_external_sensitivity_level = 'confidential'
        WHERE project_id = $1::uuid
      `,
      [ids.project],
    );
    const gateway = new RecordingGateway();
    const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x55));
    const tasks = externalTaskService(fixture, gateway, capabilityTokens);
    const confirmations = new ConfirmationService({
      repository: new PostgresConfirmationRepository(fixture.database),
      gateway,
      capabilityTokens,
      clock: fixture.clock,
      idGenerator: new SequenceIds([approvalCapabilityId]),
    });
    await tasks.createTask(ids.user, taskRequestId, taskInput());
    const error = await requiresConfirmation(
      tasks.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    );
    const confirmationId = requiredString(error.details.confirmation_id, 'confirmation_id');
    await fixture.database.query(
      `
        UPDATE dirizhor.memory_objects
        SET sensitivity_level = 'confidential'
        WHERE id = $1::uuid
      `,
      [ids.memoryObject],
    );

    await expect(
      confirmations.approveConfirmation(ids.user, confirmationId, approvalRequestId),
    ).rejects.toMatchObject({ statusCode: 409, code: 'conflict' });
    expect(gateway.calls).toHaveLength(0);
    const persisted = await fixture.database.query<{
      confirmationStatus: string;
      runStatus: string;
      taskStatus: string;
    }>(
      `
        SELECT
          confirmation.status AS "confirmationStatus",
          run.status AS "runStatus",
          task.status AS "taskStatus"
        FROM dirizhor.confirmations AS confirmation
        JOIN dirizhor.agent_runs AS run ON run.id = confirmation.target_id
        JOIN dirizhor.tasks AS task ON task.id = run.task_id
        WHERE confirmation.id = $1::uuid
      `,
      [confirmationId],
    );
    expect(persisted.rows[0]).toEqual({
      confirmationStatus: 'revoked',
      runStatus: 'cancelled',
      taskStatus: 'cancelled',
    });
  });

  it('expires confirmation and cancels its waiting workflow atomically', async () => {
    fixture = await createDirectorFixture();
    await allowExternalFixture(fixture);
    const gateway = new RecordingGateway();
    const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x56));
    const tasks = externalTaskService(fixture, gateway, capabilityTokens);
    const confirmations = new ConfirmationService({
      repository: new PostgresConfirmationRepository(fixture.database),
      gateway,
      capabilityTokens,
      clock: fixture.clock,
      idGenerator: new SequenceIds([approvalCapabilityId]),
    });
    await tasks.createTask(ids.user, taskRequestId, taskInput());
    const error = await requiresConfirmation(
      tasks.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    );
    const confirmationId = requiredString(error.details.confirmation_id, 'confirmation_id');
    fixture.clock.set('2030-01-01T10:16:00.000Z');

    await expect(
      confirmations.approveConfirmation(ids.user, confirmationId, approvalRequestId),
    ).rejects.toMatchObject({ statusCode: 409, code: 'conflict' });
    expect(gateway.calls).toHaveLength(0);
    const persisted = await fixture.database.query<{
      confirmationStatus: string;
      runStatus: string;
      taskStatus: string;
    }>(
      `
        SELECT
          confirmation.status AS "confirmationStatus",
          run.status AS "runStatus",
          task.status AS "taskStatus"
        FROM dirizhor.confirmations AS confirmation
        JOIN dirizhor.agent_runs AS run ON run.id = confirmation.target_id
        JOIN dirizhor.tasks AS task ON task.id = run.task_id
        WHERE confirmation.id = $1::uuid
      `,
      [confirmationId],
    );
    expect(persisted.rows[0]).toEqual({
      confirmationStatus: 'expired',
      runStatus: 'cancelled',
      taskStatus: 'cancelled',
    });
  });

  it('allows a project approver with target share permissions to approve confidential context', async () => {
    fixture = await createDirectorFixture();
    await allowExternalFixture(fixture);
    await fixture.database.transaction(async (transaction) => {
      await transaction.query(
        `
          UPDATE dirizhor.project_ai_policies
          SET max_external_sensitivity_level = 'confidential',
              confirm_internal_external_share = false
          WHERE project_id = $1::uuid
        `,
        [ids.project],
      );
      await transaction.query(
        `
          UPDATE dirizhor.memory_objects
          SET sensitivity_level = 'confidential'
          WHERE id = $1::uuid
        `,
        [ids.memoryObject],
      );
      await transaction.query(
        `
          INSERT INTO dirizhor.app_users (id, login, display_name, status)
          VALUES ($1::uuid, 'approver@example.test', 'Test Approver', 'active')
        `,
        [approverId],
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
          WHERE role.code = 'project_approver'
        `,
        [approverAssignmentId, approverId, ids.project, ids.user],
      );
    });
    const gateway = new RecordingGateway();
    const capabilityTokens = new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x58));
    const tasks = externalTaskService(fixture, gateway, capabilityTokens);
    const confirmations = new ConfirmationService({
      repository: new PostgresConfirmationRepository(fixture.database),
      gateway,
      capabilityTokens,
      clock: fixture.clock,
      idGenerator: new SequenceIds([approvalCapabilityId]),
    });
    await tasks.createTask(ids.user, taskRequestId, taskInput());
    const error = await requiresConfirmation(
      tasks.createAgentRun(ids.user, taskId, runRequestId, runInput()),
    );
    const confirmationId = requiredString(error.details.confirmation_id, 'confirmation_id');

    const approved = await confirmations.approveConfirmation(
      approverId,
      confirmationId,
      approvalRequestId,
    );

    expect(approved).toMatchObject({
      status: 'consumed',
      requested_by_user_id: ids.user,
      decided_by_user_id: approverId,
    });
    expect(gateway.calls).toHaveLength(1);
  });
});

function externalTaskService(
  fixture: DirectorFixture,
  gateway: AgentGatewayClient,
  capabilityTokens: HmacCapabilityTokenIssuer,
): TaskService {
  return new TaskService({
    repository: new PostgresTaskRepository(fixture.database),
    gateway,
    capabilityTokens,
    routeResolver: fixtureRouteResolver({
      deploymentClass: 'external',
      providerDataProfileVersion: profileVersion,
    }),
    clock: fixture.clock,
    idGenerator: new SequenceIds([
      taskId,
      runId,
      unusedCapabilityId,
      retryRunId,
      retryCapabilityId,
    ]),
  });
}

function taskInput() {
  return {
    project_id: ids.project,
    title: 'Review external architecture',
    user_request: 'Review the context with the approved external provider.',
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

function bulkRunInput() {
  return {
    ...runInput(),
    context: [
      ...runInput().context,
      {
        memory_object_id: secondMemoryObjectId,
        document_version_id: secondDocumentVersionId,
        access_reason: 'Secondary architecture context',
      },
    ],
  };
}

async function allowExternalFixture(fixture: DirectorFixture): Promise<void> {
  await fixture.database.query(
    `
      UPDATE dirizhor.project_ai_policies
      SET external_ai_enabled = true,
          allowed_provider_ids = ARRAY['fixture']::text[],
          provider_data_profile_versions = $2::jsonb,
          max_external_sensitivity_level = 'internal',
          confirm_internal_external_share = true
      WHERE project_id = $1::uuid
    `,
    [ids.project, JSON.stringify({ fixture: profileVersion })],
  );
}

async function seedSecondContext(fixture: DirectorFixture): Promise<void> {
  const content = Buffer.from('# Secondary context\nImmutable.', 'utf8');
  const storageUri = 'documents/secondary-context-v1.md';
  fixture.documentStore.immutable.set(storageUri, content);
  await fixture.database.transaction(async (transaction) => {
    await transaction.query(
      `
        INSERT INTO dirizhor.memory_objects (
          id, type, title, project_id, author_user_id, sensitivity_level
        )
        VALUES ($1::uuid, 'document', 'Secondary', $2::uuid, $3::uuid, 'internal')
      `,
      [secondMemoryObjectId, ids.project, ids.user],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.document_versions (
          id, memory_object_id, version_number, storage_uri,
          file_name, file_type, content_hash, size_bytes, created_by_user_id
        )
        VALUES (
          $1::uuid, $2::uuid, 1, $3,
          'secondary.md', 'text/markdown', $4, $5, $6::uuid
        )
      `,
      [
        secondDocumentVersionId,
        secondMemoryObjectId,
        storageUri,
        sha256Bytes(content),
        content.byteLength,
        ids.user,
      ],
    );
  });
}

async function requiresConfirmation(promise: Promise<unknown>): Promise<DirectorProtocolError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof DirectorProtocolError) {
      return error;
    }
    throw error;
  }
  throw new Error('Expected the operation to require confirmation.');
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new Error(`Confirmation error is missing ${field}.`);
  }
  return value;
}

class RecordingGateway implements AgentGatewayClient {
  readonly calls: AgentGatewayDispatch[] = [];

  async dispatch(input: AgentGatewayDispatch): Promise<void> {
    this.calls.push(structuredClone(input));
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
