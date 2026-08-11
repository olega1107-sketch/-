import {
  computeFrozenContextSetHash,
  computeRequestFingerprint,
  maximumSensitivity,
} from './canonical.js';
import type { AgentRoute } from './agent-routing.js';
import { ConcealedAuthorizationDeniedError } from './authorization-audit.js';
import {
  insertAllowedAccessAudit,
  insertAllowAuthorizationDecision,
} from './authorization-decision.js';
import {
  evaluateAgentPolicy,
  type AgentPolicyDecision,
  type ProjectAiPolicy,
} from './agent-policy.js';
import {
  buildAgentRunConfirmationPayload,
  computeAgentRunConfirmationPayloadHash,
} from './confirmation-payload.js';
import type { Confirmation } from './confirmation-protocol.js';
import {
  confirmationFromRow,
  confirmationSelect,
  type ConfirmationRow,
} from './confirmation-record.js';
import { DirectorProtocolError } from './errors.js';
import type {
  AgentExecutionRequest,
  DeploymentClass,
  SensitivityLevel,
} from './protocol.js';
import type { SqlDatabase, SqlQueryable } from './ports.js';
import type {
  CreateTaskCommand,
  PrepareAgentRunCommand,
  PreparedAgentRun,
  TaskRepository,
} from './task-ports.js';
import type {
  AgentRun,
  AgentRunContextInput,
  AgentRunStatus,
  FrozenContextDescriptor,
  Task,
  TaskStatus,
} from './task-protocol.js';

const taskPermissions = ['project.read', 'task.create'] as const;
const runPermissions = [
  'task.read',
  'agent_run.create',
  'agent_context.share',
  'memory_object.read',
  'document_version.read',
] as const;

interface StatusRow {
  status: string;
}

interface PermissionRow {
  code: string;
}

interface TaskRow {
  id: string;
  projectId: string;
  createdByUserId: string;
  title: string;
  userRequest: string;
  status: TaskStatus;
  resultMemoryObjectId: string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
  completedAt: Date | string | null;
}

interface ContextRow {
  memoryObjectId: string;
  documentVersionId: string;
  fileName: string;
  mediaType: string;
  sizeBytes: number | string;
  contentHash: string;
  sensitivityLevel: SensitivityLevel;
}

interface AgentRunRow {
  id: string;
  taskId: string;
  projectId: string;
  agentType: string;
  provider: string;
  model: string | null;
  purpose: string;
  instructions: string;
  status: AgentRunStatus;
  requestedByUserId: string;
  providerDataProfileVersion: string | null;
  deploymentClass: DeploymentClass;
  contextSetHash: string | null;
  originRequestId: string;
  requestFingerprint: string | null;
  dispatchedAt: Date | string | null;
  deadlineAt: Date | string | null;
  createdAt: Date | string;
  startedAt: Date | string | null;
  finishedAt: Date | string | null;
  errorMessage: string | null;
  capabilityId: string | null;
}

interface ExistingContextRow {
  position: number;
  memoryObjectId: string;
  documentVersionId: string;
  accessReason: string;
  sensitivityLevel: SensitivityLevel;
}

interface PolicyRow {
  externalAiEnabled: boolean;
  allowedProviderIds: string[];
  profileVersions: unknown;
  maxExternalSensitivity: SensitivityLevel;
  confirmInternalExternalShare: boolean;
  bulkContextObjectLimit: number;
}

export class PostgresTaskRepository implements TaskRepository {
  constructor(private readonly database: SqlDatabase) {}

  async createTask(command: CreateTaskCommand): Promise<Task> {
    try {
      return await this.database.transaction(async (transaction) => {
        const permissions = await this.projectPermissions(
          transaction,
          command.userId,
          command.input.project_id,
          true,
        );
        this.requirePermissions(permissions, taskPermissions, {
          concealedPermission: 'project.read',
          concealedResource: ['project', command.input.project_id],
        });
        await transaction.query(
          `
            INSERT INTO dirizhor.tasks (
              id, project_id, created_by_user_id, title, user_request
            )
            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)
          `,
          [
            command.taskId,
            command.input.project_id,
            command.userId,
            command.input.title,
            command.input.user_request,
          ],
        );
        const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
          principalUserId: command.userId,
          action: 'task.create',
          resourceType: 'project',
          resourceId: command.input.project_id,
          projectId: command.input.project_id,
          requestId: command.requestId,
        });
        await transaction.query(
          `
            INSERT INTO dirizhor.audit_events (
              id,
              actor_type,
              actor_id,
              action,
              target_type,
              target_id,
              project_id,
              metadata,
              request_id,
              authorization_decision_id
            )
            VALUES (
              $1::uuid,
              'user',
              $2::uuid,
              'task.created',
              'task',
              $3::uuid,
              $4::uuid,
              '{"status":"created"}'::jsonb,
              $1::uuid,
              $5::uuid
            )
          `,
          [
            command.requestId,
            command.userId,
            command.taskId,
            command.input.project_id,
            authorizationDecisionId,
          ],
        );
        return this.loadTask(transaction, command.taskId);
      });
    } catch (error) {
      if (sqlState(error) !== '23505') {
        throw error;
      }
      const existing = await this.loadAuthorizedTaskByRequest(command);
      if (existing !== undefined) {
        return existing;
      }
      throw conflict('Task creation conflicts with an existing resource.');
    }
  }

  async prepareAgentRun(command: PrepareAgentRunCommand): Promise<PreparedAgentRun> {
    try {
      return await this.database.transaction((transaction) =>
        this.prepareAgentRunTransaction(transaction, command),
      );
    } catch (error) {
      if (sqlState(error) !== '23505') {
        throw error;
      }
      const existing = await this.database.transaction((transaction) =>
        this.loadAuthorizedExistingRun(transaction, command),
      );
      if (existing !== undefined) {
        return existing;
      }
      throw conflict('Agent run creation conflicts with an existing resource.');
    }
  }

  async getTask(userId: string, requestId: string, taskId: string): Promise<Task> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, userId, false);
      const identity = await this.loadTaskIdentity(transaction, taskId, false);
      if (identity === undefined) {
        throw notFound('task', taskId);
      }
      const permissions = await this.projectPermissions(
        transaction,
        userId,
        identity.projectId,
        false,
        false,
      );
      this.requirePermissions(permissions, ['project.read', 'task.read'], {
        concealedPermission: 'project.read',
        concealedResource: ['task', taskId],
      });
      const task = await this.loadTask(transaction, taskId);
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: userId,
        action: 'task.read',
        resourceType: 'task',
        resourceId: task.id,
        projectId: identity.projectId,
        requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: userId,
        authorizedAction: 'task.read',
        resourceType: 'task',
        resourceId: task.id,
        projectId: identity.projectId,
        requestId,
        authorizationDecisionId,
        metadata: { status: task.status },
      });
      return task;
    });
  }

  async getAgentRun(
    userId: string,
    requestId: string,
    agentRunId: string,
  ): Promise<AgentRun> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, userId, false);
      const identity = await this.loadAgentRunIdentity(transaction, agentRunId);
      if (identity === undefined) {
        throw notFound('agent_run', agentRunId);
      }
      const permissions = await this.projectPermissions(
        transaction,
        userId,
        identity.projectId,
        false,
        false,
      );
      this.requirePermissions(permissions, ['project.read', 'agent_run.read'], {
        concealedPermission: 'project.read',
        concealedResource: ['agent_run', agentRunId],
      });
      const run = await this.loadAgentRun(transaction, agentRunId);
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: userId,
        action: 'agent_run.read',
        resourceType: 'agent_run',
        resourceId: run.id,
        projectId: identity.projectId,
        requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: userId,
        authorizedAction: 'agent_run.read',
        resourceType: 'agent_run',
        resourceId: run.id,
        projectId: identity.projectId,
        requestId,
        authorizationDecisionId,
        metadata: {
          status: run.status,
          agent_type: run.agent_type,
          deployment_class: run.deployment_class,
        },
      });
      return run;
    });
  }

  private async prepareAgentRunTransaction(
    transaction: SqlQueryable,
    command: PrepareAgentRunCommand,
  ): Promise<PreparedAgentRun> {
    await this.requireActiveUser(transaction, command.userId, true);
    const task = await this.loadTaskIdentity(transaction, command.taskId, true);
    if (task === undefined) {
      throw notFound('task', command.taskId);
    }
    const permissions = await this.projectPermissions(
      transaction,
      command.userId,
      task.projectId,
      true,
      false,
    );
    this.requirePermissions(permissions, runPermissions, {
      concealedPermission: 'task.read',
      concealedResource: ['task', command.taskId],
    });

    const existing = await this.loadExistingRun(transaction, command.requestId);
    if (existing !== undefined) {
      return this.validateExistingRun(transaction, existing, command, permissions);
    }
    if (!['created', 'planning', 'awaiting_context'].includes(task.status)) {
      throw conflict('Task is not ready for a new agent run.');
    }
    const route = command.route;
    if (route === null) {
      throw new DirectorProtocolError(
        409,
        'agent_route_unavailable',
        'No enabled provider route is configured for the requested agent type.',
      );
    }

    const context = await this.loadFrozenContext(
      transaction,
      task.projectId,
      command.input.context,
    );
    this.requireContextPermissions(permissions, context);
    if (route.deploymentClass === 'external') {
      this.requirePermissions(permissions, ['agent_provider.use_external']);
    }
    const policy = await this.loadProjectAiPolicy(transaction, task.projectId);

    const contextSetHash = computeFrozenContextSetHash(
      command.agentRunId,
      task.projectId,
      context,
    );
    const maxContextSensitivity = maximumSensitivity(
      context.map((item) => item.sensitivityLevel),
    );
    const policyDecision = evaluateAgentPolicy(policy, {
      deploymentClass: route.deploymentClass,
      provider: route.provider,
      providerDataProfileVersion: route.providerDataProfileVersion,
      maximumContextSensitivity: maxContextSensitivity,
      contextItemCount: context.length,
    });
    if (policyDecision.confirmationOperation !== null) {
      await this.insertPendingRun(transaction, command, route, task.projectId, contextSetHash);
      await this.insertContexts(transaction, command.agentRunId, task.projectId, context);
      const confirmation = await this.insertPendingConfirmation(
        transaction,
        command,
        route,
        task.projectId,
        contextSetHash,
        context,
        policyDecision,
      );
      await this.advanceTaskToAwaitingConfirmation(transaction, task.id, task.status);
      await this.insertContextAudits(
        transaction,
        command.userId,
        command.agentRunId,
        task.projectId,
        command.requestId,
        confirmation.authorization_decision_id,
        context,
      );
      return {
        outcome: 'requires_confirmation',
        run: await this.loadAgentRun(transaction, command.agentRunId),
        confirmation,
      };
    }

    const gatewayPrincipalId = await this.loadGatewayPrincipal(transaction);
    const executionRequest: AgentExecutionRequest = {
      protocol_version: '1.0',
      project_id: task.projectId,
      task_id: task.id,
      origin_request_id: command.requestId,
      request_fingerprint: `sha256:${'0'.repeat(64)}`,
      agent_type: command.input.agent_type,
      provider: route.provider,
      model: route.model,
      purpose: command.input.purpose,
      instructions: command.input.instructions,
      deployment_class: route.deploymentClass,
      provider_data_profile_version: route.providerDataProfileVersion,
      context_set_hash: contextSetHash,
      context_item_count: context.length,
      max_context_sensitivity: maxContextSensitivity,
      dispatched_at: command.dispatchedAt,
      deadline_at: command.deadlineAt,
    };
    executionRequest.request_fingerprint = computeRequestFingerprint(
      command.agentRunId,
      executionRequest,
    );

    const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
      principalUserId: command.userId,
      action: 'agent_run.create',
      resourceType: 'task',
      resourceId: task.id,
      projectId: task.projectId,
      requestId: command.requestId,
      obligations: ['audit_access_decision', 'bind_capability_to_context_set'],
    });

    await this.insertRun(transaction, command, task.projectId, executionRequest);
    await this.insertContexts(transaction, command.agentRunId, task.projectId, context);
    await this.insertCapability(
      transaction,
      command,
      task.projectId,
      gatewayPrincipalId,
      contextSetHash,
      context,
    );
    await this.advanceTaskToRunning(transaction, task.id, task.status);
    await this.insertDispatchAudit(
      transaction,
      command,
      task.projectId,
      executionRequest,
      authorizationDecisionId,
    );
    await this.insertContextAudits(
      transaction,
      command.userId,
      command.agentRunId,
      task.projectId,
      command.requestId,
      authorizationDecisionId,
      context,
    );

    return {
      outcome: 'dispatch',
      run: await this.loadAgentRun(transaction, command.agentRunId),
      capabilityId: command.capabilityId,
      executionRequest,
    };
  }

  private async loadAuthorizedTaskByRequest(
    command: CreateTaskCommand,
  ): Promise<Task | undefined> {
    return this.database.transaction(async (transaction) => {
      const permissions = await this.projectPermissions(
        transaction,
        command.userId,
        command.input.project_id,
        false,
      );
      this.requirePermissions(permissions, taskPermissions, {
        concealedPermission: 'project.read',
        concealedResource: ['project', command.input.project_id],
      });
      const result = await transaction.query<{ taskId: string }>(
        `
          SELECT target_id::text AS "taskId"
          FROM dirizhor.audit_events
          WHERE id = $1::uuid
            AND request_id = $1::uuid
            AND actor_type = 'user'
            AND actor_id = $2::uuid
            AND action = 'task.created'
            AND target_type = 'task'
            AND project_id = $3::uuid
        `,
        [command.requestId, command.userId, command.input.project_id],
      );
      const taskId = result.rows[0]?.taskId;
      if (taskId === undefined) {
        return undefined;
      }
      const task = await this.loadTask(transaction, taskId);
      return task.title === command.input.title && task.user_request === command.input.user_request
        ? task
        : undefined;
    });
  }

  private async loadAuthorizedExistingRun(
    transaction: SqlQueryable,
    command: PrepareAgentRunCommand,
  ): Promise<PreparedAgentRun | undefined> {
    await this.requireActiveUser(transaction, command.userId, false);
    const task = await this.loadTaskIdentity(transaction, command.taskId, false);
    if (task === undefined) {
      throw notFound('task', command.taskId);
    }
    const permissions = await this.projectPermissions(
      transaction,
      command.userId,
      task.projectId,
      false,
      false,
    );
    this.requirePermissions(permissions, runPermissions, {
      concealedPermission: 'task.read',
      concealedResource: ['task', command.taskId],
    });
    const existing = await this.loadExistingRun(transaction, command.requestId);
    return existing === undefined
      ? undefined
      : this.validateExistingRun(transaction, existing, command, permissions);
  }

  private async validateExistingRun(
    transaction: SqlQueryable,
    existing: AgentRunRow,
    command: PrepareAgentRunCommand,
    permissions: ReadonlySet<string>,
  ): Promise<PreparedAgentRun> {
    const contexts = await this.loadExistingContexts(transaction, existing.id);
    const inputMatches =
      existing.taskId === command.taskId &&
      existing.requestedByUserId === command.userId &&
      existing.agentType === command.input.agent_type &&
      existing.purpose === command.input.purpose &&
      existing.instructions === command.input.instructions &&
      sameContext(contexts, command.input.context);
    if (!inputMatches) {
      throw conflict('X-Request-Id was already used for a different agent run.');
    }
    this.requireContextPermissions(permissions, contexts);
    if (existing.deploymentClass === 'external') {
      this.requirePermissions(permissions, ['agent_provider.use_external']);
      const policy = await this.loadProjectAiPolicy(transaction, existing.projectId);
      evaluateAgentPolicy(policy, {
        deploymentClass: existing.deploymentClass,
        provider: existing.provider,
        providerDataProfileVersion: existing.providerDataProfileVersion,
        maximumContextSensitivity: maximumSensitivity(
          contexts.map((item) => item.sensitivityLevel),
        ),
        contextItemCount: contexts.length,
      });
    }
    if (existing.status === 'awaiting_user_confirmation') {
      const confirmation = await this.loadPendingConfirmationForRun(transaction, existing.id);
      return {
        outcome: 'requires_confirmation',
        run: agentRun(existing),
        confirmation,
      };
    }
    if (existing.capabilityId === null) {
      throw conflict('Existing agent run has no dispatch capability.');
    }
    const executionRequest = executionRequestFrom(existing, contexts);
    return {
      outcome: 'dispatch',
      run: agentRun(existing),
      capabilityId: existing.capabilityId,
      executionRequest,
    };
  }

  private async requireActiveUser(
    transaction: SqlQueryable,
    userId: string,
    lock: boolean,
  ): Promise<void> {
    const result = await transaction.query<StatusRow>(
      `
        SELECT status
        FROM dirizhor.app_users
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
        SELECT status
        FROM dirizhor.projects
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
    conceal?: {
      concealedPermission: string;
      concealedResource: readonly ['project' | 'task' | 'agent_run', string];
    },
  ): void {
    const missing = required.filter((permission) => !granted.has(permission));
    if (missing.length === 0) {
      return;
    }
    if (conceal !== undefined && missing.includes(conceal.concealedPermission)) {
      throw new ConcealedAuthorizationDeniedError(
        conceal.concealedResource[0],
        conceal.concealedResource[1],
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

  private requireContextPermissions(
    granted: ReadonlySet<string>,
    context: readonly { sensitivityLevel: SensitivityLevel }[],
  ): void {
    const required: string[] = [];
    if (context.some((item) => item.sensitivityLevel === 'confidential')) {
      required.push('memory_object.read_confidential', 'agent_context.share_confidential');
    }
    if (context.some((item) => item.sensitivityLevel === 'restricted')) {
      required.push('memory_object.read_restricted');
    }
    this.requirePermissions(granted, required);
  }

  private async loadTaskIdentity(
    transaction: SqlQueryable,
    taskId: string,
    lock: boolean,
  ): Promise<{ id: string; projectId: string; status: TaskStatus } | undefined> {
    const result = await transaction.query<{ id: string; projectId: string; status: TaskStatus }>(
      `
        SELECT id::text AS id, project_id::text AS "projectId", status
        FROM dirizhor.tasks
        WHERE id = $1::uuid
        ${lock ? 'FOR UPDATE' : ''}
      `,
      [taskId],
    );
    return result.rows[0];
  }

  private async loadAgentRunIdentity(
    transaction: SqlQueryable,
    agentRunId: string,
  ): Promise<{ id: string; projectId: string } | undefined> {
    const result = await transaction.query<{ id: string; projectId: string }>(
      `
        SELECT id::text AS id, project_id::text AS "projectId"
        FROM dirizhor.agent_runs
        WHERE id = $1::uuid
      `,
      [agentRunId],
    );
    return result.rows[0];
  }

  private async loadFrozenContext(
    transaction: SqlQueryable,
    projectId: string,
    requested: readonly AgentRunContextInput[],
  ): Promise<FrozenContextDescriptor[]> {
    const context: FrozenContextDescriptor[] = [];
    for (const [index, item] of requested.entries()) {
      const result = await transaction.query<ContextRow>(
        `
          SELECT
            memory.id::text AS "memoryObjectId",
            version.id::text AS "documentVersionId",
            version.file_name AS "fileName",
            version.file_type AS "mediaType",
            version.size_bytes AS "sizeBytes",
            version.content_hash AS "contentHash",
            memory.sensitivity_level AS "sensitivityLevel"
          FROM dirizhor.memory_objects AS memory
          JOIN dirizhor.document_versions AS version
            ON version.memory_object_id = memory.id
          WHERE memory.id = $1::uuid
            AND memory.project_id = $2::uuid
            AND memory.status = 'active'
            AND version.id = $3::uuid
          FOR SHARE OF memory, version
        `,
        [item.memory_object_id, projectId, item.document_version_id],
      );
      const row = result.rows[0];
      if (row === undefined) {
        throw notFound('context', item.document_version_id);
      }
      context.push({
        position: index + 1,
        memory_object_id: row.memoryObjectId,
        document_version_id: row.documentVersionId,
        access_reason: item.access_reason,
        fileName: row.fileName,
        mediaType: row.mediaType,
        sizeBytes: safeSize(row.sizeBytes),
        contentHash: row.contentHash,
        sensitivityLevel: row.sensitivityLevel,
      });
    }
    return context;
  }

  private async loadProjectAiPolicy(
    transaction: SqlQueryable,
    projectId: string,
  ): Promise<ProjectAiPolicy> {
    const result = await transaction.query<PolicyRow>(
      `
        SELECT
          external_ai_enabled AS "externalAiEnabled",
          allowed_provider_ids AS "allowedProviderIds",
          provider_data_profile_versions AS "profileVersions",
          max_external_sensitivity_level AS "maxExternalSensitivity",
          confirm_internal_external_share AS "confirmInternalExternalShare",
          bulk_context_object_limit AS "bulkContextObjectLimit"
        FROM dirizhor.project_ai_policies
        WHERE project_id = $1::uuid
        FOR SHARE
      `,
      [projectId],
    );
    const row = result.rows[0];
    if (row === undefined || !isRecord(row.profileVersions)) {
      throw new Error('Project AI policy is missing.');
    }
    if (!Number.isSafeInteger(row.bulkContextObjectLimit) || row.bulkContextObjectLimit < 1) {
      throw new Error('Project AI policy has an invalid bulk context limit.');
    }
    return {
      externalAiEnabled: row.externalAiEnabled,
      allowedProviderIds: row.allowedProviderIds,
      profileVersions: row.profileVersions,
      maxExternalSensitivity: row.maxExternalSensitivity,
      confirmInternalExternalShare: row.confirmInternalExternalShare,
      bulkContextObjectLimit: row.bulkContextObjectLimit,
    };
  }

  private async loadGatewayPrincipal(transaction: SqlQueryable): Promise<string> {
    const result = await transaction.query<{ id: string }>(
      `
        SELECT id::text AS id
        FROM dirizhor.service_principals
        WHERE code = 'agent-gateway'
          AND status = 'active'
        FOR SHARE
      `,
    );
    const id = result.rows[0]?.id;
    if (id === undefined) {
      throw new Error('Active Agent Gateway service principal is missing.');
    }
    return id;
  }

  private async insertRun(
    transaction: SqlQueryable,
    command: PrepareAgentRunCommand,
    projectId: string,
    request: AgentExecutionRequest,
  ): Promise<void> {
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
          $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, 'queued',
          $9::uuid, $10, $11, $12, $13::uuid, $14,
          $15::timestamptz, $16::timestamptz
        )
      `,
      [
        command.agentRunId,
        command.taskId,
        projectId,
        request.agent_type,
        request.provider,
        request.model,
        request.purpose,
        request.instructions,
        command.userId,
        request.provider_data_profile_version,
        request.deployment_class,
        request.context_set_hash,
        command.requestId,
        request.request_fingerprint,
        request.dispatched_at,
        request.deadline_at,
      ],
    );
  }

  private async insertPendingRun(
    transaction: SqlQueryable,
    command: PrepareAgentRunCommand,
    route: AgentRoute,
    projectId: string,
    contextSetHash: string,
  ): Promise<void> {
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
          origin_request_id
        )
        VALUES (
          $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8,
          'awaiting_user_confirmation', $9::uuid, $10, $11, $12, $13::uuid
        )
      `,
      [
        command.agentRunId,
        command.taskId,
        projectId,
        command.input.agent_type,
        route.provider,
        route.model,
        command.input.purpose,
        command.input.instructions,
        command.userId,
        route.providerDataProfileVersion,
        route.deploymentClass,
        contextSetHash,
        command.requestId,
      ],
    );
  }

  private async insertContexts(
    transaction: SqlQueryable,
    agentRunId: string,
    projectId: string,
    context: readonly FrozenContextDescriptor[],
  ): Promise<void> {
    for (const item of context) {
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
          VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7)
        `,
        [
          agentRunId,
          projectId,
          item.memory_object_id,
          item.document_version_id,
          item.position,
          item.access_reason,
          item.sensitivityLevel,
        ],
      );
    }
  }

  private async insertPendingConfirmation(
    transaction: SqlQueryable,
    command: PrepareAgentRunCommand,
    route: AgentRoute,
    projectId: string,
    contextSetHash: string,
    context: readonly FrozenContextDescriptor[],
    policyDecision: AgentPolicyDecision,
  ): Promise<Confirmation> {
    const operation = policyDecision.confirmationOperation;
    if (operation === null) {
      throw new Error('Pending confirmation requires a confirmation operation.');
    }
    const payloadSource = {
      agentRunId: command.agentRunId,
      taskId: command.taskId,
      projectId,
      requestedByUserId: command.userId,
      originRequestId: command.requestId,
      provider: route.provider,
      model: route.model,
      deploymentClass: route.deploymentClass,
      providerDataProfileVersion: route.providerDataProfileVersion,
      input: command.input,
      contextSetHash,
      context,
      confirmationReasons: policyDecision.confirmationReasons,
    };
    const frozenPayload = buildAgentRunConfirmationPayload(payloadSource);
    const payloadHash = computeAgentRunConfirmationPayloadHash(payloadSource);
    const decision = await transaction.query<{ id: string }>(
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
          'user', $1::uuid, 'agent_context.share', 'agent_run', $2::uuid,
          $3::uuid, 'require_confirmation', $4::text[], $5::jsonb, $6::uuid
        )
        RETURNING id::text AS id
      `,
      [
        command.userId,
        command.agentRunId,
        projectId,
        policyDecision.confirmationReasons,
        JSON.stringify(['audit_access_decision', 'bind_capability_to_context_set']),
        command.requestId,
      ],
    );
    const authorizationDecisionId = decision.rows[0]?.id;
    if (authorizationDecisionId === undefined) {
      throw new Error('Authorization decision could not be created.');
    }
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
          $1, 'agent_run', $2::uuid, $3::uuid, $4::uuid, $5::uuid,
          $6::uuid, $7::jsonb, $8, $9, $10::timestamptz
        )
        RETURNING id::text AS id
      `,
      [
        operation,
        command.agentRunId,
        projectId,
        command.userId,
        authorizationDecisionId,
        command.requestId,
        JSON.stringify(frozenPayload),
        payloadHash,
        confirmationSummary(route.provider, context.length, policyDecision),
        command.confirmationExpiresAt,
      ],
    );
    const confirmationId = inserted.rows[0]?.id;
    if (confirmationId === undefined) {
      throw new Error('Confirmation could not be created.');
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
        projectId,
        JSON.stringify({
          operation,
          target_type: 'agent_run',
          target_id: command.agentRunId,
          payload_hash: payloadHash,
        }),
        command.requestId,
        authorizationDecisionId,
      ],
    );
    return this.loadConfirmation(transaction, confirmationId);
  }

  private async insertCapability(
    transaction: SqlQueryable,
    command: PrepareAgentRunCommand,
    projectId: string,
    gatewayPrincipalId: string,
    contextSetHash: string,
    context: readonly FrozenContextDescriptor[],
  ): Promise<void> {
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
        command.capabilityId,
        command.agentRunId,
        projectId,
        gatewayPrincipalId,
        contextSetHash,
        command.capabilityTokenHash,
        command.dispatchedAt,
        command.capabilityExpiresAt,
      ],
    );
    for (const item of context) {
      await transaction.query(
        `
          INSERT INTO dirizhor.agent_capability_resources (
            agent_capability_id, project_id, memory_object_id, document_version_id
          )
          VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)
        `,
        [
          command.capabilityId,
          projectId,
          item.memory_object_id,
          item.document_version_id,
        ],
      );
    }
  }

  private async advanceTaskToRunning(
    transaction: SqlQueryable,
    taskId: string,
    initialStatus: TaskStatus,
  ): Promise<void> {
    if (initialStatus === 'created') {
      await this.setTaskStatus(transaction, taskId, 'planning');
      await this.setTaskStatus(transaction, taskId, 'awaiting_context');
    } else if (initialStatus === 'planning') {
      await this.setTaskStatus(transaction, taskId, 'awaiting_context');
    }
    await this.setTaskStatus(transaction, taskId, 'running_agent');
  }

  private async advanceTaskToAwaitingConfirmation(
    transaction: SqlQueryable,
    taskId: string,
    initialStatus: TaskStatus,
  ): Promise<void> {
    if (initialStatus === 'created') {
      await this.setTaskStatus(transaction, taskId, 'planning');
      await this.setTaskStatus(transaction, taskId, 'awaiting_context');
    } else if (initialStatus === 'planning') {
      await this.setTaskStatus(transaction, taskId, 'awaiting_context');
    }
    await this.setTaskStatus(transaction, taskId, 'awaiting_user_confirmation');
  }

  private async setTaskStatus(
    transaction: SqlQueryable,
    taskId: string,
    status: TaskStatus,
  ): Promise<void> {
    await transaction.query(
      `UPDATE dirizhor.tasks SET status = $2 WHERE id = $1::uuid`,
      [taskId, status],
    );
  }

  private async insertDispatchAudit(
    transaction: SqlQueryable,
    command: PrepareAgentRunCommand,
    projectId: string,
    request: AgentExecutionRequest,
    authorizationDecisionId: string,
  ): Promise<void> {
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'user', $1::uuid, 'agent_run.dispatched', 'agent_run', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        command.userId,
        command.agentRunId,
        projectId,
        JSON.stringify({
          agent_type: request.agent_type,
          provider: request.provider,
          model: request.model,
          deployment_class: request.deployment_class,
          context_set_hash: request.context_set_hash,
          context_item_count: request.context_item_count,
          max_context_sensitivity: request.max_context_sensitivity,
          deadline_at: request.deadline_at,
        }),
        command.requestId,
        authorizationDecisionId,
      ],
    );
  }

  private async insertContextAudits(
    transaction: SqlQueryable,
    userId: string,
    agentRunId: string,
    projectId: string,
    requestId: string,
    authorizationDecisionId: string,
    context: readonly FrozenContextDescriptor[],
  ): Promise<void> {
    for (const item of context) {
      await transaction.query(
        `
          INSERT INTO dirizhor.audit_events (
            actor_type, actor_id, action, target_type, target_id,
            project_id, metadata, request_id, authorization_decision_id
          )
          VALUES
            (
              'user', $1::uuid, 'memory_object.read', 'memory_object', $2::uuid,
              $3::uuid, $4::jsonb, $5::uuid, $8::uuid
            ),
            (
              'user', $1::uuid, 'agent_context.attached', 'agent_run', $6::uuid,
              $3::uuid, $7::jsonb, $5::uuid, $8::uuid
            )
        `,
        [
          userId,
          item.memory_object_id,
          projectId,
          JSON.stringify({ document_version_id: item.document_version_id }),
          requestId,
          agentRunId,
          JSON.stringify({
            position: item.position,
            memory_object_id: item.memory_object_id,
            document_version_id: item.document_version_id,
            sensitivity_level: item.sensitivityLevel,
          }),
          authorizationDecisionId,
        ],
      );
    }
  }

  private async loadExistingRun(
    transaction: SqlQueryable,
    requestId: string,
  ): Promise<AgentRunRow | undefined> {
    const result = await transaction.query<AgentRunRow>(
      `${agentRunSelect}
       WHERE run.origin_request_id = $1::uuid
       ORDER BY capability.issued_at DESC
       LIMIT 1`,
      [requestId],
    );
    return result.rows[0];
  }

  private async loadExistingContexts(
    transaction: SqlQueryable,
    agentRunId: string,
  ): Promise<ExistingContextRow[]> {
    const result = await transaction.query<ExistingContextRow>(
      `
        SELECT
          position,
          memory_object_id::text AS "memoryObjectId",
          document_version_id::text AS "documentVersionId",
          access_reason AS "accessReason",
          sensitivity_level AS "sensitivityLevel"
        FROM dirizhor.agent_run_contexts
        WHERE agent_run_id = $1::uuid
        ORDER BY position
      `,
      [agentRunId],
    );
    return result.rows;
  }

  private async loadPendingConfirmationForRun(
    transaction: SqlQueryable,
    agentRunId: string,
  ): Promise<Confirmation> {
    const result = await transaction.query<ConfirmationRow>(
      `${confirmationSelect}
       WHERE confirmation.target_type = 'agent_run'
         AND confirmation.target_id = $1::uuid
         AND confirmation.status = 'pending'
       ORDER BY confirmation.created_at DESC
       LIMIT 1`,
      [agentRunId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw conflict('Pending agent run has no active confirmation.');
    }
    return confirmationFromRow(row);
  }

  private async loadConfirmation(
    transaction: SqlQueryable,
    confirmationId: string,
  ): Promise<Confirmation> {
    const result = await transaction.query<ConfirmationRow>(
      `${confirmationSelect}
       WHERE confirmation.id = $1::uuid`,
      [confirmationId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('Committed confirmation could not be loaded.');
    }
    return confirmationFromRow(row);
  }

  private async loadTask(transaction: SqlQueryable, taskId: string): Promise<Task> {
    const result = await transaction.query<TaskRow>(
      `
        SELECT
          id::text AS id,
          project_id::text AS "projectId",
          created_by_user_id::text AS "createdByUserId",
          title,
          user_request AS "userRequest",
          status,
          result_memory_object_id::text AS "resultMemoryObjectId",
          created_at AS "createdAt",
          updated_at AS "updatedAt",
          completed_at AS "completedAt"
        FROM dirizhor.tasks
        WHERE id = $1::uuid
      `,
      [taskId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('Committed task could not be loaded.');
    }
    return task(row);
  }

  private async loadAgentRun(transaction: SqlQueryable, agentRunId: string): Promise<AgentRun> {
    const result = await transaction.query<AgentRunRow>(
      `${agentRunSelect}
       WHERE run.id = $1::uuid
       ORDER BY capability.issued_at DESC
       LIMIT 1`,
      [agentRunId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('Committed agent run could not be loaded.');
    }
    return agentRun(row);
  }
}

const agentRunSelect = `
  SELECT
    run.id::text AS id,
    run.task_id::text AS "taskId",
    run.project_id::text AS "projectId",
    run.agent_type AS "agentType",
    run.provider,
    run.model,
    run.purpose,
    run.instructions,
    run.status,
    run.requested_by_user_id::text AS "requestedByUserId",
    run.provider_data_profile_version AS "providerDataProfileVersion",
    run.deployment_class AS "deploymentClass",
    run.context_set_hash AS "contextSetHash",
    run.origin_request_id::text AS "originRequestId",
    run.request_fingerprint AS "requestFingerprint",
    run.dispatched_at AS "dispatchedAt",
    run.deadline_at AS "deadlineAt",
    run.created_at AS "createdAt",
    run.started_at AS "startedAt",
    run.finished_at AS "finishedAt",
    run.error_message AS "errorMessage",
    capability.id::text AS "capabilityId"
  FROM dirizhor.agent_runs AS run
  LEFT JOIN dirizhor.agent_capabilities AS capability
    ON capability.agent_run_id = run.id
`;

function task(row: TaskRow): Task {
  return {
    id: row.id,
    project_id: row.projectId,
    created_by_user_id: row.createdByUserId,
    title: row.title,
    user_request: row.userRequest,
    status: row.status,
    result_memory_object_id: row.resultMemoryObjectId,
    created_at: timestamp(row.createdAt),
    updated_at: timestamp(row.updatedAt),
    completed_at: row.completedAt === null ? null : timestamp(row.completedAt),
  };
}

function agentRun(row: AgentRunRow): AgentRun {
  return {
    id: row.id,
    task_id: row.taskId,
    project_id: row.projectId,
    agent_type: row.agentType,
    provider: row.provider,
    model: row.model,
    purpose: row.purpose,
    status: row.status,
    requested_by_user_id: row.requestedByUserId,
    provider_data_profile_version: row.providerDataProfileVersion,
    deployment_class: row.deploymentClass,
    context_set_hash: row.contextSetHash,
    origin_request_id: row.originRequestId,
    request_fingerprint: row.requestFingerprint,
    dispatched_at: nullableTimestamp(row.dispatchedAt),
    deadline_at: nullableTimestamp(row.deadlineAt),
    created_at: timestamp(row.createdAt),
    started_at: nullableTimestamp(row.startedAt),
    finished_at: nullableTimestamp(row.finishedAt),
    error_message: row.errorMessage,
  };
}

function executionRequestFrom(
  row: AgentRunRow,
  context: readonly ExistingContextRow[],
): AgentExecutionRequest {
  if (
    row.contextSetHash === null ||
    row.requestFingerprint === null ||
    row.dispatchedAt === null ||
    row.deadlineAt === null
  ) {
    throw conflict('Existing agent run is not dispatch-ready.');
  }
  return {
    protocol_version: '1.0',
    project_id: row.projectId,
    task_id: row.taskId,
    origin_request_id: row.originRequestId,
    request_fingerprint: row.requestFingerprint,
    agent_type: row.agentType,
    provider: row.provider,
    model: row.model,
    purpose: row.purpose,
    instructions: row.instructions,
    deployment_class: row.deploymentClass,
    provider_data_profile_version: row.providerDataProfileVersion,
    context_set_hash: row.contextSetHash,
    context_item_count: context.length,
    max_context_sensitivity: maximumSensitivity(
      context.map((item) => item.sensitivityLevel),
    ),
    dispatched_at: timestamp(row.dispatchedAt),
    deadline_at: timestamp(row.deadlineAt),
  };
}

function sameContext(
  existing: readonly ExistingContextRow[],
  requested: readonly AgentRunContextInput[],
): boolean {
  return (
    existing.length === requested.length &&
    existing.every((item, index) => {
      const candidate = requested[index];
      return (
        candidate !== undefined &&
        item.position === index + 1 &&
        item.memoryObjectId === candidate.memory_object_id &&
        item.documentVersionId === candidate.document_version_id &&
        item.accessReason === candidate.access_reason
      );
    })
  );
}

function confirmationSummary(
  provider: string,
  contextItemCount: number,
  decision: AgentPolicyDecision,
): string {
  const reason = decision.confirmationReasons.includes('bulk_context_share')
    ? 'bulk context'
    : 'protected context';
  return `Share ${contextItemCount} ${reason} item(s) with provider ${provider}.`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function safeSize(value: number | string): number {
  const size = typeof value === 'string' ? Number(value) : value;
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error('Document size is outside the supported integer range.');
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
  resource: 'project' | 'task' | 'agent_run' | 'context',
  id: string,
): DirectorProtocolError {
  return new DirectorProtocolError(404, 'not_found', `The ${resource} was not found.`, false, {
    resource,
    id,
  });
}

function conflict(message: string): DirectorProtocolError {
  return new DirectorProtocolError(409, 'conflict', message);
}

function sqlState(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return undefined;
  }
  return typeof error.code === 'string' ? error.code : undefined;
}
