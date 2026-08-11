import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AgentResultService } from '../src/agent-result-service.js';
import { HmacCapabilityTokenIssuer } from '../src/capability-token.js';
import { ConfirmationService } from '../src/confirmation-service.js';
import { DirectorProtocolError } from '../src/errors.js';
import { PostgresAgentResultRepository } from '../src/postgres-agent-result-repository.js';
import { PostgresConfirmationRepository } from '../src/postgres-confirmation-repository.js';
import { PostgresTaskRepository } from '../src/postgres-task-repository.js';
import type { AgentGatewayClient, AgentGatewayDispatch } from '../src/task-ports.js';
import {
  completedEvent,
  createDirectorFixture,
  ids,
  startedEvent,
  type DirectorFixture,
} from './helpers.js';

const saveRequestId = '70000000-0000-4000-8000-000000000001';
const approvalRequestId = '70000000-0000-4000-8000-000000000002';
const rejectionRequestId = '70000000-0000-4000-8000-000000000003';
const afterCompletion = '2030-01-01T10:01:00.000Z';
const viewerId = '70000000-0000-4000-8000-000000000004';
const outsiderId = '70000000-0000-4000-8000-000000000005';
const resultReadRequestId = '70000000-0000-4000-8000-000000000006';
const savedResultReadRequestId = '70000000-0000-4000-8000-000000000007';
const viewerTaskReadRequestId = '70000000-0000-4000-8000-000000000008';
const viewerRunReadRequestId = '70000000-0000-4000-8000-000000000009';
const outsiderTaskReadRequestId = '70000000-0000-4000-8000-000000000010';
const viewerResultReadRequestId = '70000000-0000-4000-8000-000000000011';
const deniedResultReadRequestId = '70000000-0000-4000-8000-000000000012';

describe('Public agent result workflow', () => {
  let fixture: DirectorFixture;
  let results: AgentResultService;
  let confirmations: ConfirmationService;
  let gateway: RecordingGateway;

  beforeEach(async () => {
    fixture = await createDirectorFixture();
    await fixture.service.recordGatewayEvent(ids.run, startedEvent(fixture));
    await fixture.service.recordGatewayEvent(ids.run, completedEvent(fixture));
    fixture.clock.set(afterCompletion);
    gateway = new RecordingGateway();
    results = new AgentResultService({
      repository: new PostgresAgentResultRepository(fixture.database),
      documentStore: fixture.documentStore,
      clock: fixture.clock,
    });
    confirmations = new ConfirmationService({
      repository: new PostgresConfirmationRepository(fixture.database),
      gateway,
      capabilityTokens: new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x51)),
      clock: fixture.clock,
    });
  });

  afterEach(async () => {
    await fixture.close();
  });

  it('reads, confirms, and atomically saves an AI result to corporate memory', async () => {
    const temporary = await results.getAgentRunResult(
      ids.user,
      resultReadRequestId,
      ids.run,
    );
    expect(temporary).toMatchObject({
      agent_run_id: ids.run,
      content: '# Recommendation\nKeep the immutable boundary.',
      content_type: 'text/markdown',
      sensitivity_level: 'internal',
      saved_memory_object_id: null,
      saved_at: null,
    });
    const readAuthorization = await fixture.database.query<{
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
        FROM dirizhor.authorization_decisions AS decision
        JOIN dirizhor.audit_events AS audit
          ON audit.authorization_decision_id = decision.id
        WHERE decision.request_id = $1::uuid
          AND decision.action = 'agent_run.read'
          AND audit.action = 'access.allowed'
      `,
      [resultReadRequestId],
    );
    expect(readAuthorization.rows).toHaveLength(1);
    expect(readAuthorization.rows[0]).toMatchObject({
      decision: 'allow',
      reasonCodes: ['permissions_satisfied'],
      decisionId: readAuthorization.rows[0]?.auditDecisionId,
      metadata: {
        authorized_action: 'agent_run.read',
        view: 'result',
        agent_run_result_id: temporary.id,
        sensitivity_level: 'internal',
      },
    });
    expect(JSON.stringify(readAuthorization.rows[0]?.metadata)).not.toContain(temporary.content);

    const input = {
      title: '  Architecture recommendation  ',
      summary: '  Approved AI review  ',
      keywords: ['architecture', 'review'],
      relationships: [
        {
          target_type: 'memory_object' as const,
          target_id: ids.memoryObject,
          relation_type: 'derived_from' as const,
          description: '  Based on the frozen source  ',
        },
      ],
    };
    const required = await requiresConfirmation(
      results.saveAgentRunResult(ids.user, ids.run, saveRequestId, input),
    );
    expect(required).toMatchObject({
      statusCode: 428,
      code: 'requires_confirmation',
      details: {
        target_type: 'agent_run_result',
        payload_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      },
    });
    const confirmationId = requiredString(required.details.confirmation_id);
    const resultId = requiredString(required.details.target_id);

    const replay = await requiresConfirmation(
      results.saveAgentRunResult(ids.user, ids.run, saveRequestId, input),
    );
    expect(replay.details).toEqual(required.details);

    const approved = await confirmations.approveConfirmation(
      ids.user,
      confirmationId,
      approvalRequestId,
    );
    expect(approved).toMatchObject({
      id: confirmationId,
      operation: 'ai_result_save',
      target_type: 'agent_run_result',
      target_id: resultId,
      status: 'consumed',
      decided_by_user_id: ids.user,
    });
    expect(gateway.calls).toHaveLength(0);
    await expect(
      confirmations.approveConfirmation(ids.user, confirmationId, approvalRequestId),
    ).resolves.toMatchObject({ id: confirmationId, status: 'consumed' });
    expect(gateway.calls).toHaveLength(0);

    const saved = await results.saveAgentRunResult(ids.user, ids.run, saveRequestId, input);
    expect(saved).toMatchObject({
      type: 'ai_result',
      title: 'Architecture recommendation',
      project_id: ids.project,
      author_user_id: ids.user,
      summary: 'Approved AI review',
      keywords: ['architecture', 'review'],
      status: 'active',
      sensitivity_level: 'internal',
      current_version: {
        file_type: 'text/markdown',
        content_hash: temporary.content_hash,
        size_bytes: Buffer.byteLength(temporary.content, 'utf8'),
      },
    });
    const replayAuthorization = await fixture.database.query<{
      decision: string;
      decisionId: string;
      auditDecisionId: string;
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
          AND decision.action = 'ai_result.save'
          AND decision.decision = 'allow'
          AND audit.action = 'access.allowed'
      `,
      [saveRequestId],
    );
    expect(replayAuthorization.rows).toHaveLength(1);
    expect(replayAuthorization.rows[0]).toMatchObject({
      decision: 'allow',
      decisionId: replayAuthorization.rows[0]?.auditDecisionId,
      metadata: {
        authorized_action: 'ai_result.save',
        replay: true,
        agent_run_result_id: resultId,
        saved_memory_object_id: saved.id,
      },
    });
    expect(JSON.stringify(replayAuthorization.rows[0]?.metadata)).not.toContain(input.title.trim());

    const persisted = await fixture.database.query<{
      taskStatus: string;
      taskResultId: string | null;
      resultSavedId: string | null;
      relationshipCount: number | string;
      auditCount: number | string;
    }>(
      `
        SELECT
          task.status AS "taskStatus",
          task.result_memory_object_id::text AS "taskResultId",
          result.saved_memory_object_id::text AS "resultSavedId",
          (
            SELECT count(*) FROM dirizhor.relationships AS relationship
            WHERE relationship.source_type = 'memory_object'
              AND relationship.source_id = result.saved_memory_object_id
          ) AS "relationshipCount",
          (
            SELECT count(*) FROM dirizhor.audit_events AS audit
            WHERE audit.request_id = $2::uuid
              AND audit.action IN (
                'confirmation.approved', 'memory_object.created',
                'document_version.created', 'ai_result.saved',
                'task.completed', 'confirmation.consumed'
              )
          ) AS "auditCount"
        FROM dirizhor.agent_run_results AS result
        JOIN dirizhor.agent_runs AS run ON run.id = result.agent_run_id
        JOIN dirizhor.tasks AS task ON task.id = run.task_id
        WHERE result.id = $1::uuid
      `,
      [resultId, approvalRequestId],
    );
    expect(persisted.rows[0]).toEqual({
      taskStatus: 'completed',
      taskResultId: saved.id,
      resultSavedId: saved.id,
      relationshipCount: 1,
      auditCount: 6,
    });
    expect(
      await results.getAgentRunResult(ids.user, savedResultReadRequestId, ids.run),
    ).toMatchObject({
      saved_memory_object_id: saved.id,
      saved_at: afterCompletion,
    });
  });

  it('revokes a pending save when current context sensitivity changes', async () => {
    const required = await requiresConfirmation(
      results.saveAgentRunResult(ids.user, ids.run, saveRequestId, {
        title: 'Architecture recommendation',
      }),
    );
    const confirmationId = requiredString(required.details.confirmation_id);
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

    const state = await fixture.database.query<{
      confirmationStatus: string;
      taskStatus: string;
      savedMemoryObjectId: string | null;
      aiResultCount: number | string;
    }>(
      `
        SELECT
          confirmation.status AS "confirmationStatus",
          task.status AS "taskStatus",
          result.saved_memory_object_id::text AS "savedMemoryObjectId",
          (
            SELECT count(*) FROM dirizhor.memory_objects
            WHERE project_id = result.project_id AND type = 'ai_result'
          ) AS "aiResultCount"
        FROM dirizhor.confirmations AS confirmation
        JOIN dirizhor.agent_run_results AS result
          ON result.id = confirmation.target_id
        JOIN dirizhor.agent_runs AS run ON run.id = result.agent_run_id
        JOIN dirizhor.tasks AS task ON task.id = run.task_id
        WHERE confirmation.id = $1::uuid
      `,
      [confirmationId],
    );
    expect(state.rows[0]).toEqual({
      confirmationStatus: 'revoked',
      taskStatus: 'reviewing',
      savedMemoryObjectId: null,
      aiResultCount: 0,
    });
  });

  it('rejects a save without cancelling the completed run or review task', async () => {
    const required = await requiresConfirmation(
      results.saveAgentRunResult(ids.user, ids.run, saveRequestId, {
        title: 'Architecture recommendation',
      }),
    );
    const confirmationId = requiredString(required.details.confirmation_id);
    const rejected = await confirmations.rejectConfirmation(
      ids.user,
      confirmationId,
      rejectionRequestId,
    );
    expect(rejected.status).toBe('rejected');

    const state = await fixture.database.query<{
      runStatus: string;
      taskStatus: string;
      savedMemoryObjectId: string | null;
    }>(
      `
        SELECT
          run.status AS "runStatus",
          task.status AS "taskStatus",
          result.saved_memory_object_id::text AS "savedMemoryObjectId"
        FROM dirizhor.agent_run_results AS result
        JOIN dirizhor.agent_runs AS run ON run.id = result.agent_run_id
        JOIN dirizhor.tasks AS task ON task.id = run.task_id
        WHERE run.id = $1::uuid
      `,
      [ids.run],
    );
    expect(state.rows[0]).toEqual({
      runStatus: 'completed',
      taskStatus: 'reviewing',
      savedMemoryObjectId: null,
    });
  });

  it('enforces project, operation, and current-sensitivity permissions on reads and save', async () => {
    await fixture.database.transaction(async (transaction) => {
      await transaction.query(
        `
          INSERT INTO dirizhor.app_users (id, login, display_name, status)
          VALUES
            ($1::uuid, 'viewer@example.test', 'Result Viewer', 'active'),
            ($2::uuid, 'outsider@example.test', 'Project Outsider', 'active')
        `,
        [viewerId, outsiderId],
      );
      await transaction.query(
        `
          INSERT INTO dirizhor.role_assignments (
            principal_type, principal_id, role_id, scope_type, scope_id,
            granted_by_user_id
          )
          SELECT 'user', $1::uuid, role.id, 'project', $2::uuid, $3::uuid
          FROM dirizhor.roles AS role
          WHERE role.code = 'project_viewer'
        `,
        [viewerId, ids.project, ids.user],
      );
    });

    const tasks = new PostgresTaskRepository(fixture.database);
    await expect(
      tasks.getTask(viewerId, viewerTaskReadRequestId, ids.task),
    ).resolves.toMatchObject({ id: ids.task });
    await expect(
      tasks.getAgentRun(viewerId, viewerRunReadRequestId, ids.run),
    ).resolves.toMatchObject({ id: ids.run });
    await expect(
      tasks.getTask(outsiderId, outsiderTaskReadRequestId, ids.task),
    ).rejects.toMatchObject({
      statusCode: 404,
      code: 'not_found',
    });
    await expect(
      results.getAgentRunResult(viewerId, viewerResultReadRequestId, ids.run),
    ).resolves.toMatchObject({
      agent_run_id: ids.run,
    });
    await expect(
      results.saveAgentRunResult(viewerId, ids.run, saveRequestId, {
        title: 'Viewer cannot save this',
      }),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'access_denied',
      details: { missing_permissions: expect.arrayContaining(['ai_result.save']) },
    });

    await fixture.database.query(
      `UPDATE dirizhor.memory_objects SET sensitivity_level = 'confidential' WHERE id = $1::uuid`,
      [ids.memoryObject],
    );
    await expect(
      results.getAgentRunResult(viewerId, deniedResultReadRequestId, ids.run),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'access_denied',
      details: {
        missing_permissions: expect.arrayContaining(['memory_object.read_confidential']),
      },
    });
  });
});

class RecordingGateway implements AgentGatewayClient {
  readonly calls: AgentGatewayDispatch[] = [];

  async dispatch(input: AgentGatewayDispatch): Promise<void> {
    this.calls.push(structuredClone(input));
  }
}

async function requiresConfirmation(promise: Promise<unknown>): Promise<DirectorProtocolError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof DirectorProtocolError && error.code === 'requires_confirmation') {
      return error;
    }
    throw error;
  }
  throw new Error('Expected the operation to require confirmation.');
}

function requiredString(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('Expected a string error detail.');
  }
  return value;
}
