import {
  buildAiResultSaveConfirmationPayload,
  computeAiResultSaveConfirmationPayloadHash,
} from './agent-result-payload.js';
import type {
  AgentResultRecord,
  AgentResultRepository,
  PrepareAgentResultSaveCommand,
  PreparedAgentResultSave,
} from './agent-result-ports.js';
import type {
  RelationshipEndpointType,
  RelationshipRef,
} from './agent-result-protocol.js';
import { ConcealedAuthorizationDeniedError } from './authorization-audit.js';
import {
  insertAllowedAccessAudit,
  insertAllowAuthorizationDecision,
} from './authorization-decision.js';
import {
  confirmationFromRow,
  confirmationSelect,
  type ConfirmationRow,
} from './confirmation-record.js';
import { maximumSensitivity } from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import type {
  DocumentVersion,
  MemoryObject,
  MemoryObjectType,
} from './public-protocol.js';
import type { SensitivityLevel } from './protocol.js';
import type { SqlDatabase, SqlQueryable } from './ports.js';
import type { AgentRunStatus, TaskStatus } from './task-protocol.js';

const resultReadPermissions = [
  'project.read',
  'agent_run.read',
  'memory_object.read',
  'document_version.read',
] as const;
const resultSavePermissions = [
  ...resultReadPermissions,
  'ai_result.save',
  'memory_object.create',
  'document_version.create',
] as const;

interface StatusRow {
  status: string;
}

interface PermissionRow {
  code: string;
}

interface RunRow {
  id: string;
  taskId: string;
  projectId: string;
  status: AgentRunStatus;
  taskStatus: TaskStatus;
}

interface ResultRow {
  id: string;
  agentRunId: string;
  taskId: string;
  projectId: string;
  outputStorageUri: string;
  contentHash: string;
  sizeBytes: number | string;
  contentType: string;
  outputSummary: string | null;
  sensitivityLevel: SensitivityLevel;
  createdAt: Date | string;
  expiresAt: Date | string | null;
  savedMemoryObjectId: string | null;
  savedAt: Date | string | null;
}

interface ContextSensitivityRow {
  frozenSensitivityLevel: SensitivityLevel;
  currentSensitivityLevel: SensitivityLevel;
}

interface MemoryTargetRow {
  status: string;
  sensitivityLevel: SensitivityLevel;
}

interface MemoryObjectRow {
  id: string;
  type: MemoryObjectType;
  title: string;
  projectId: string;
  topicId: string | null;
  currentVersionId: string | null;
  authorUserId: string;
  summary: string | null;
  keywords: string[];
  status: 'active';
  sensitivityLevel: SensitivityLevel;
  createdAt: Date | string;
  updatedAt: Date | string;
  archivedAt: Date | string | null;
  documentVersionId: string;
  versionNumber: number;
  fileName: string;
  fileType: string;
  contentHash: string;
  sizeBytes: number | string;
  versionCreatedByUserId: string;
  versionCreatedAt: Date | string;
  changeSummary: string | null;
}

export class PostgresAgentResultRepository implements AgentResultRepository {
  constructor(private readonly database: SqlDatabase) {}

  async getAgentRunResult(
    userId: string,
    requestId: string,
    agentRunId: string,
    requestedAt: string,
  ): Promise<AgentResultRecord> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, userId, false);
      const run = await this.loadRun(transaction, agentRunId, false);
      if (run === undefined) {
        throw notFound('agent_run', agentRunId);
      }
      const permissions = await this.projectPermissions(
        transaction,
        userId,
        run.projectId,
        false,
        false,
      );
      this.requirePermissions(permissions, resultReadPermissions, agentRunId);
      const contextSensitivity = await this.requireContextPermissions(
        transaction,
        permissions,
        run.id,
      );
      if (run.status !== 'completed') {
        throw taskNotReady();
      }
      const result = await this.loadResult(transaction, run.id, false);
      if (result === undefined || isExpiredUnsaved(result, requestedAt)) {
        throw taskNotReady();
      }
      const record = resultRecord(result);
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: userId,
        action: 'agent_run.read',
        resourceType: 'agent_run',
        resourceId: run.id,
        projectId: run.projectId,
        requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: userId,
        authorizedAction: 'agent_run.read',
        resourceType: 'agent_run',
        resourceId: run.id,
        projectId: run.projectId,
        requestId,
        authorizationDecisionId,
        metadata: {
          view: 'result',
          agent_run_result_id: record.id,
          sensitivity_level: record.sensitivityLevel,
          context_sensitivity_level: contextSensitivity,
          saved: record.savedMemoryObjectId !== null,
        },
      });
      return record;
    });
  }

  async prepareAgentResultSave(
    command: PrepareAgentResultSaveCommand,
  ): Promise<PreparedAgentResultSave> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, command.userId, true);
      const run = await this.loadRun(transaction, command.agentRunId, true);
      if (run === undefined) {
        throw notFound('agent_run', command.agentRunId);
      }
      const permissions = await this.projectPermissions(
        transaction,
        command.userId,
        run.projectId,
        true,
        false,
      );
      this.requirePermissions(permissions, resultSavePermissions, run.id);
      const contextSensitivity = await this.requireContextPermissions(
        transaction,
        permissions,
        run.id,
      );
      if (run.status !== 'completed') {
        throw taskNotReady();
      }
      const resultRow = await this.loadResult(transaction, run.id, true);
      if (resultRow === undefined || isExpiredUnsaved(resultRow, command.requestedAt)) {
        throw taskNotReady();
      }
      const result = resultRecord(resultRow);
      await this.validateSaveReferences(
        transaction,
        permissions,
        result.projectId,
        command.input.topic_id,
        command.input.relationships,
        true,
      );
      const payloadSource = {
        result,
        saveSensitivityLevel: maximumSensitivity([
          result.sensitivityLevel,
          contextSensitivity,
        ]),
        requestedByUserId: command.userId,
        input: command.input,
      };
      const frozenPayload = buildAiResultSaveConfirmationPayload(payloadSource);
      const payloadHash = computeAiResultSaveConfirmationPayloadHash(payloadSource);

      if (result.savedMemoryObjectId !== null) {
        const consumed = await this.loadMatchingConfirmation(
          transaction,
          result.id,
          command.userId,
          payloadHash,
          'consumed',
        );
        if (consumed === undefined) {
          throw conflict('The agent result was already saved with different metadata.');
        }
        const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
          principalUserId: command.userId,
          action: 'ai_result.save',
          resourceType: 'agent_run',
          resourceId: run.id,
          projectId: result.projectId,
          requestId: command.requestId,
        });
        await insertAllowedAccessAudit(transaction, {
          actorUserId: command.userId,
          authorizedAction: 'ai_result.save',
          resourceType: 'agent_run',
          resourceId: run.id,
          projectId: result.projectId,
          requestId: command.requestId,
          authorizationDecisionId,
          metadata: {
            replay: true,
            agent_run_result_id: result.id,
            saved_memory_object_id: result.savedMemoryObjectId,
          },
        });
        return {
          outcome: 'saved',
          memoryObject: await this.loadMemoryObject(transaction, result.savedMemoryObjectId),
        };
      }
      if (run.taskStatus !== 'reviewing') {
        throw conflict('The task is not ready to save its agent result.');
      }

      const pending = await this.loadPendingConfirmation(transaction, result.id, command.userId);
      if (pending !== undefined) {
        if (pending.payloadHash !== payloadHash) {
          throw conflict('A different save confirmation is already pending for this result.');
        }
        return {
          outcome: 'requires_confirmation',
          confirmation: confirmationFromRow(pending),
        };
      }

      const authorizationDecisionId = await this.insertAuthorizationDecision(
        transaction,
        command,
        result,
        payloadHash,
      );
      const inserted = await transaction.query<{ id: string }>(
        `
          INSERT INTO dirizhor.confirmations (
            operation,
            target_type,
            target_id,
            project_id,
            requested_by_user_id,
            authorization_decision_id,
            request_id,
            frozen_payload,
            payload_hash,
            summary,
            expires_at
          )
          VALUES (
            'ai_result_save', 'agent_run_result', $1::uuid, $2::uuid, $3::uuid,
            $4::uuid, $5::uuid, $6::jsonb, $7, $8, $9::timestamptz
          )
          RETURNING id::text AS id
        `,
        [
          result.id,
          result.projectId,
          command.userId,
          authorizationDecisionId,
          command.requestId,
          JSON.stringify(frozenPayload),
          payloadHash,
          `Save AI result as "${command.input.title}".`,
          command.confirmationExpiresAt,
        ],
      );
      const confirmationId = inserted.rows[0]?.id;
      if (confirmationId === undefined) {
        throw new Error('AI result save confirmation could not be created.');
      }
      await transaction.query(
        `
          INSERT INTO dirizhor.audit_events (
            actor_type, actor_id, action, target_type, target_id,
            project_id, metadata, request_id, authorization_decision_id
          )
          VALUES (
            'user', $1::uuid, 'confirmation.created', 'confirmation', $2::uuid,
            $3::uuid, $4::jsonb, $5::uuid, $6::uuid
          )
        `,
        [
          command.userId,
          confirmationId,
          result.projectId,
          JSON.stringify({
            operation: 'ai_result_save',
            target_type: 'agent_run_result',
            target_id: result.id,
            payload_hash: payloadHash,
          }),
          command.requestId,
          authorizationDecisionId,
        ],
      );
      const confirmation = await this.loadConfirmation(transaction, confirmationId);
      return { outcome: 'requires_confirmation', confirmation: confirmationFromRow(confirmation) };
    });
  }

  private async insertAuthorizationDecision(
    transaction: SqlQueryable,
    command: PrepareAgentResultSaveCommand,
    result: AgentResultRecord,
    payloadHash: string,
  ): Promise<string> {
    const inserted = await transaction.query<{ id: string }>(
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
          obligations,
          request_id
        )
        VALUES (
          'user', $1::uuid, 'ai_result.save', 'agent_run_result', $2::uuid,
          $3::uuid, 'require_confirmation', ARRAY['ai_result_save_confirmation']::text[],
          $4::jsonb, $5::uuid
        )
        RETURNING id::text AS id
      `,
      [
        command.userId,
        result.id,
        result.projectId,
        JSON.stringify(['confirm_ai_result_save', `bind_payload:${payloadHash}`]),
        command.requestId,
      ],
    );
    const id = inserted.rows[0]?.id;
    if (id === undefined) {
      throw new Error('AI result save authorization decision could not be created.');
    }
    return id;
  }

  private async requireActiveUser(
    transaction: SqlQueryable,
    userId: string,
    lock: boolean,
  ): Promise<void> {
    const result = await transaction.query<StatusRow>(
      `
        SELECT status FROM dirizhor.app_users
        WHERE id = $1::uuid
        ${lock ? 'FOR SHARE' : ''}
      `,
      [userId],
    );
    if (result.rows[0]?.status !== 'active') {
      throw new DirectorProtocolError(401, 'unauthorized', 'Authenticated user is not active.');
    }
  }

  private async projectPermissions(
    transaction: SqlQueryable,
    userId: string,
    projectId: string,
    lock: boolean,
    checkUser = true,
  ): Promise<ReadonlySet<string>> {
    if (checkUser) {
      await this.requireActiveUser(transaction, userId, lock);
    }
    const project = await transaction.query<StatusRow>(
      `
        SELECT status FROM dirizhor.projects
        WHERE id = $1::uuid
        ${lock ? 'FOR SHARE' : ''}
      `,
      [projectId],
    );
    if (project.rows[0]?.status !== 'active') {
      throw notFound('project', projectId);
    }
    const permissions = await transaction.query<PermissionRow>(
      `
        SELECT permission.code
        FROM dirizhor.role_assignments AS assignment
        JOIN dirizhor.roles AS role ON role.id = assignment.role_id
        JOIN dirizhor.role_permissions AS role_permission
          ON role_permission.role_id = role.id
        JOIN dirizhor.permissions AS permission
          ON permission.id = role_permission.permission_id
        WHERE assignment.principal_type = 'user'
          AND assignment.principal_id = $1::uuid
          AND assignment.scope_type = 'project'
          AND assignment.scope_id = $2::uuid
          AND assignment.revoked_at IS NULL
          AND (assignment.expires_at IS NULL OR assignment.expires_at > clock_timestamp())
        ${lock ? 'FOR SHARE OF assignment, role, role_permission, permission' : ''}
      `,
      [userId, projectId],
    );
    return new Set(permissions.rows.map((row) => row.code));
  }

  private requirePermissions(
    granted: ReadonlySet<string>,
    required: readonly string[],
    concealedAgentRunId?: string,
  ): void {
    const missing = required.filter((permission) => !granted.has(permission));
    if (missing.length === 0) {
      return;
    }
    if (concealedAgentRunId !== undefined && missing.includes('project.read')) {
      throw new ConcealedAuthorizationDeniedError(
        'agent_run',
        concealedAgentRunId,
        missing,
      );
    }
    throw new DirectorProtocolError(
      403,
      'access_denied',
      'The user lacks required project permissions.',
      false,
      { missing_permissions: missing },
    );
  }

  private async requireContextPermissions(
    transaction: SqlQueryable,
    permissions: ReadonlySet<string>,
    agentRunId: string,
  ): Promise<SensitivityLevel> {
    const rows = await transaction.query<ContextSensitivityRow>(
      `
        SELECT
          context.sensitivity_level AS "frozenSensitivityLevel",
          memory.sensitivity_level AS "currentSensitivityLevel"
        FROM dirizhor.agent_run_contexts AS context
        JOIN dirizhor.memory_objects AS memory
          ON memory.id = context.memory_object_id
         AND memory.project_id = context.project_id
        WHERE context.agent_run_id = $1::uuid
      `,
      [agentRunId],
    );
    if (rows.rows.length === 0) {
      throw new DirectorProtocolError(
        409,
        'task_not_ready',
        'The agent run has no frozen context.',
      );
    }
    const sensitivities = rows.rows.flatMap((row) => [
      row.frozenSensitivityLevel,
      row.currentSensitivityLevel,
    ]);
    this.requireSensitivityPermissions(permissions, sensitivities);
    return maximumSensitivity(sensitivities);
  }

  private requireSensitivityPermissions(
    permissions: ReadonlySet<string>,
    sensitivities: readonly SensitivityLevel[],
  ): void {
    const required: string[] = [];
    if (sensitivities.includes('confidential')) {
      required.push('memory_object.read_confidential');
    }
    if (sensitivities.includes('restricted')) {
      required.push('memory_object.read_restricted');
    }
    this.requirePermissions(permissions, required);
  }

  private async validateSaveReferences(
    transaction: SqlQueryable,
    permissions: ReadonlySet<string>,
    projectId: string,
    topicId: string | null,
    relationships: readonly RelationshipRef[],
    lock: boolean,
  ): Promise<void> {
    if (topicId !== null) {
      this.requirePermissions(permissions, ['topic.read']);
      const topic = await transaction.query<{ id: string }>(
        `
          SELECT id::text AS id FROM dirizhor.topics
          WHERE id = $1::uuid AND project_id = $2::uuid
          ${lock ? 'FOR SHARE' : ''}
        `,
        [topicId, projectId],
      );
      if (topic.rowCount !== 1) {
        throw notFound('topic', topicId);
      }
    }
    for (const relationship of relationships) {
      await this.validateRelationshipTarget(
        transaction,
        permissions,
        projectId,
        relationship.target_type,
        relationship.target_id,
        lock,
      );
    }
  }

  private async validateRelationshipTarget(
    transaction: SqlQueryable,
    permissions: ReadonlySet<string>,
    projectId: string,
    targetType: RelationshipEndpointType,
    targetId: string,
    lock: boolean,
  ): Promise<void> {
    if (targetType === 'memory_object' || targetType === 'open_question') {
      const target = await this.loadMemoryTarget(
        transaction,
        projectId,
        targetType,
        targetId,
        lock,
      );
      if (target === undefined || target.status !== 'active') {
        throw notFound('relationship_target', targetId);
      }
      this.requireSensitivityPermissions(permissions, [target.sensitivityLevel]);
      return;
    }
    const table = relationshipTable(targetType);
    const requiredPermission =
      targetType === 'decision'
        ? 'decision.read'
        : targetType === 'task'
          ? 'task.read'
          : 'agent_run.read';
    this.requirePermissions(permissions, [requiredPermission]);
    const target = await transaction.query<{ id: string }>(
      `
        SELECT id::text AS id FROM dirizhor.${table}
        WHERE id = $1::uuid AND project_id = $2::uuid
        ${lock ? 'FOR SHARE' : ''}
      `,
      [targetId, projectId],
    );
    if (target.rowCount !== 1) {
      throw notFound('relationship_target', targetId);
    }
  }

  private async loadMemoryTarget(
    transaction: SqlQueryable,
    projectId: string,
    targetType: 'memory_object' | 'open_question',
    targetId: string,
    lock: boolean,
  ): Promise<MemoryTargetRow | undefined> {
    const from =
      targetType === 'memory_object'
        ? 'dirizhor.memory_objects AS memory'
        : `dirizhor.open_questions AS question
           JOIN dirizhor.memory_objects AS memory
             ON memory.id = question.memory_object_id
            AND memory.project_id = question.project_id`;
    const idColumn = targetType === 'memory_object' ? 'memory.id' : 'question.id';
    const result = await transaction.query<MemoryTargetRow>(
      `
        SELECT memory.status, memory.sensitivity_level AS "sensitivityLevel"
        FROM ${from}
        WHERE ${idColumn} = $1::uuid AND memory.project_id = $2::uuid
        ${lock ? 'FOR SHARE OF memory' : ''}
      `,
      [targetId, projectId],
    );
    return result.rows[0];
  }

  private async loadRun(
    transaction: SqlQueryable,
    agentRunId: string,
    lock: boolean,
  ): Promise<RunRow | undefined> {
    const result = await transaction.query<RunRow>(
      `
        SELECT
          run.id::text AS id,
          run.task_id::text AS "taskId",
          run.project_id::text AS "projectId",
          run.status,
          task.status AS "taskStatus"
        FROM dirizhor.agent_runs AS run
        JOIN dirizhor.tasks AS task
          ON task.id = run.task_id AND task.project_id = run.project_id
        WHERE run.id = $1::uuid
        ${lock ? 'FOR UPDATE OF run, task' : ''}
      `,
      [agentRunId],
    );
    return result.rows[0];
  }

  private async loadResult(
    transaction: SqlQueryable,
    agentRunId: string,
    lock: boolean,
  ): Promise<ResultRow | undefined> {
    const result = await transaction.query<ResultRow>(
      `
        SELECT
          result.id::text AS id,
          result.agent_run_id::text AS "agentRunId",
          run.task_id::text AS "taskId",
          result.project_id::text AS "projectId",
          result.output_storage_uri AS "outputStorageUri",
          result.content_hash AS "contentHash",
          result.size_bytes AS "sizeBytes",
          result.file_type AS "contentType",
          result.output_summary AS "outputSummary",
          result.sensitivity_level AS "sensitivityLevel",
          result.created_at AS "createdAt",
          result.expires_at AS "expiresAt",
          result.saved_memory_object_id::text AS "savedMemoryObjectId",
          result.saved_at AS "savedAt"
        FROM dirizhor.agent_run_results AS result
        JOIN dirizhor.agent_runs AS run
          ON run.id = result.agent_run_id AND run.project_id = result.project_id
        WHERE result.agent_run_id = $1::uuid
        ${lock ? 'FOR UPDATE OF result' : ''}
      `,
      [agentRunId],
    );
    return result.rows[0];
  }

  private async loadPendingConfirmation(
    transaction: SqlQueryable,
    resultId: string,
    userId: string,
  ): Promise<ConfirmationRow | undefined> {
    const result = await transaction.query<ConfirmationRow>(
      `${confirmationSelect}
       WHERE confirmation.operation = 'ai_result_save'
         AND confirmation.target_type = 'agent_run_result'
         AND confirmation.target_id = $1::uuid
         AND confirmation.requested_by_user_id = $2::uuid
         AND confirmation.status = 'pending'
       ORDER BY confirmation.created_at DESC
       LIMIT 1`,
      [resultId, userId],
    );
    return result.rows[0];
  }

  private async loadMatchingConfirmation(
    transaction: SqlQueryable,
    resultId: string,
    userId: string,
    payloadHash: string,
    status: 'consumed',
  ): Promise<ConfirmationRow | undefined> {
    const result = await transaction.query<ConfirmationRow>(
      `${confirmationSelect}
       WHERE confirmation.operation = 'ai_result_save'
         AND confirmation.target_type = 'agent_run_result'
         AND confirmation.target_id = $1::uuid
         AND confirmation.requested_by_user_id = $2::uuid
         AND confirmation.payload_hash = $3
         AND confirmation.status = $4
       ORDER BY confirmation.created_at DESC
       LIMIT 1`,
      [resultId, userId, payloadHash, status],
    );
    return result.rows[0];
  }

  private async loadConfirmation(
    transaction: SqlQueryable,
    confirmationId: string,
  ): Promise<ConfirmationRow> {
    const result = await transaction.query<ConfirmationRow>(
      `${confirmationSelect} WHERE confirmation.id = $1::uuid`,
      [confirmationId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('Committed AI result save confirmation could not be loaded.');
    }
    return row;
  }

  private async loadMemoryObject(
    transaction: SqlQueryable,
    memoryObjectId: string,
  ): Promise<MemoryObject> {
    const result = await transaction.query<MemoryObjectRow>(
      `
        SELECT
          memory.id::text AS id,
          memory.type,
          memory.title,
          memory.project_id::text AS "projectId",
          memory.topic_id::text AS "topicId",
          memory.current_version_id::text AS "currentVersionId",
          memory.author_user_id::text AS "authorUserId",
          memory.summary,
          memory.keywords,
          memory.status,
          memory.sensitivity_level AS "sensitivityLevel",
          memory.created_at AS "createdAt",
          memory.updated_at AS "updatedAt",
          memory.archived_at AS "archivedAt",
          version.id::text AS "documentVersionId",
          version.version_number AS "versionNumber",
          version.file_name AS "fileName",
          version.file_type AS "fileType",
          version.content_hash AS "contentHash",
          version.size_bytes AS "sizeBytes",
          version.created_by_user_id::text AS "versionCreatedByUserId",
          version.created_at AS "versionCreatedAt",
          version.change_summary AS "changeSummary"
        FROM dirizhor.memory_objects AS memory
        JOIN dirizhor.document_versions AS version
          ON version.id = memory.current_version_id
        WHERE memory.id = $1::uuid
      `,
      [memoryObjectId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('Saved AI result memory object could not be loaded.');
    }
    const currentVersion: DocumentVersion = {
      id: row.documentVersionId,
      memory_object_id: row.id,
      version_number: row.versionNumber,
      file_name: row.fileName,
      file_type: row.fileType,
      content_hash: row.contentHash,
      size_bytes: safeSize(row.sizeBytes),
      created_by_user_id: row.versionCreatedByUserId,
      created_at: timestamp(row.versionCreatedAt),
      change_summary: row.changeSummary,
    };
    return {
      id: row.id,
      type: row.type,
      title: row.title,
      project_id: row.projectId,
      topic_id: row.topicId,
      current_version_id: row.currentVersionId,
      current_version: currentVersion,
      author_user_id: row.authorUserId,
      summary: row.summary,
      keywords: row.keywords,
      status: row.status,
      sensitivity_level: row.sensitivityLevel,
      created_at: timestamp(row.createdAt),
      updated_at: timestamp(row.updatedAt),
      archived_at: nullableTimestamp(row.archivedAt),
    };
  }
}

function resultRecord(row: ResultRow): AgentResultRecord {
  return {
    id: row.id,
    agentRunId: row.agentRunId,
    taskId: row.taskId,
    projectId: row.projectId,
    outputStorageUri: row.outputStorageUri,
    contentHash: row.contentHash,
    sizeBytes: safeSize(row.sizeBytes),
    contentType: row.contentType,
    outputSummary: row.outputSummary,
    sensitivityLevel: row.sensitivityLevel,
    createdAt: timestamp(row.createdAt),
    expiresAt: nullableTimestamp(row.expiresAt),
    savedMemoryObjectId: row.savedMemoryObjectId,
    savedAt: nullableTimestamp(row.savedAt),
  };
}

function isExpiredUnsaved(result: ResultRow, requestedAt: string): boolean {
  return (
    result.savedMemoryObjectId === null &&
    result.expiresAt !== null &&
    Date.parse(timestamp(result.expiresAt)) <= Date.parse(requestedAt)
  );
}

function relationshipTable(targetType: Exclude<RelationshipEndpointType, 'memory_object' | 'open_question'>): string {
  switch (targetType) {
    case 'decision':
      return 'decisions';
    case 'task':
      return 'tasks';
    case 'agent_run':
      return 'agent_runs';
  }
}

function safeSize(value: number | string): number {
  const size = typeof value === 'string' ? Number(value) : value;
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error('Agent result size is outside the supported integer range.');
  }
  return size;
}

function timestamp(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error('Database returned an invalid timestamp.');
  }
  return date.toISOString();
}

function nullableTimestamp(value: Date | string | null): string | null {
  return value === null ? null : timestamp(value);
}

function notFound(
  resource: 'project' | 'agent_run' | 'topic' | 'relationship_target',
  id: string,
): DirectorProtocolError {
  return new DirectorProtocolError(404, 'not_found', `The ${resource} was not found.`, false, {
    resource,
    id,
  });
}

function taskNotReady(): DirectorProtocolError {
  return new DirectorProtocolError(
    409,
    'task_not_ready',
    'The agent run result is not available for this operation.',
  );
}

function conflict(message: string): DirectorProtocolError {
  return new DirectorProtocolError(409, 'conflict', message);
}
