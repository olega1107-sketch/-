import {
  evaluateAgentPolicy,
  type AgentPolicyDecision,
  type ProjectAiPolicy,
} from './agent-policy.js';
import {
  computeAiResultSaveConfirmationPayloadHash,
} from './agent-result-payload.js';
import type { AgentResultRecord } from './agent-result-ports.js';
import {
  AiResultSaveConfirmationPayloadSchema,
  type AiResultSaveConfirmationPayload,
  type RelationshipEndpointType,
  type RelationshipRef,
} from './agent-result-protocol.js';
import { Value } from '@sinclair/typebox/value';
import { ConcealedAuthorizationDeniedError } from './authorization-audit.js';
import {
  insertAllowedAccessAudit,
  insertAllowAuthorizationDecision,
} from './authorization-decision.js';
import {
  computeFrozenContextSetHash,
  computeRequestFingerprint,
  hashCanonical,
  maximumSensitivity,
} from './canonical.js';
import { computeAgentRunConfirmationPayloadHash } from './confirmation-payload.js';
import {
  buildDecisionConfirmationPayload,
  computeDecisionConfirmationPayloadHash,
  validatedDecisionConfirmationPayload,
  type DecisionConfirmationPayload,
} from './decision-confirmation-payload.js';
import type {
  ApprovedConfirmation,
  ApproveConfirmationCommand,
  ConfirmationListSlice,
  ConfirmationDispatch,
  ConfirmationRepository,
  ListConfirmationsQuery,
} from './confirmation-ports.js';
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
  AgentRunCreate,
  AgentRunStatus,
  FrozenContextDescriptor,
  TaskStatus,
} from './task-protocol.js';

const requesterPermissions = [
  'task.read',
  'agent_run.create',
  'agent_context.share',
  'memory_object.read',
  'document_version.read',
] as const;
const approverOperationPermissions = [
  'task.read',
  'agent_context.share',
  'memory_object.read',
  'document_version.read',
] as const;
const resultSaveOperationPermissions = [
  'project.read',
  'agent_run.read',
  'ai_result.save',
  'memory_object.read',
  'memory_object.create',
  'document_version.read',
  'document_version.create',
] as const;
const decisionApproveOperationPermissions = [
  'project.read',
  'decision.read',
  'decision.approve',
  'memory_object.read',
] as const;
const decisionSupersedeOperationPermissions = [
  ...decisionApproveOperationPermissions,
  'decision.create',
  'decision.supersede',
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
  taskStatus: TaskStatus;
}

interface ContextRow {
  position: number;
  memoryObjectId: string;
  documentVersionId: string;
  fileName: string;
  mediaType: string;
  sizeBytes: number | string;
  contentHash: string;
  sensitivityLevel: SensitivityLevel;
  currentSensitivityLevel: SensitivityLevel;
  accessReason: string;
}

interface PolicyRow {
  externalAiEnabled: boolean;
  allowedProviderIds: string[];
  profileVersions: unknown;
  maxExternalSensitivity: SensitivityLevel;
  confirmInternalExternalShare: boolean;
  bulkContextObjectLimit: number;
}

interface ResultSaveRow {
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
  runStatus: AgentRunStatus;
  taskStatus: TaskStatus;
}

interface MemoryTargetRow {
  status: string;
  sensitivityLevel: SensitivityLevel;
}

interface DecisionOperationRow {
  id: string;
  memoryObjectId: string;
  projectId: string;
  topicId: string | null;
  title: string;
  decisionText: string;
  rationale: string | null;
  status: 'draft' | 'proposed' | 'approved' | 'rejected' | 'superseded';
  supersedesDecisionId: string | null;
  sensitivityLevel: SensitivityLevel;
}

interface ValidatedOperation {
  run: RunRow;
  frozenContext: FrozenContextDescriptor[];
  currentContext: FrozenContextDescriptor[];
  policyDecision: AgentPolicyDecision;
}

type ApprovalTransactionResult =
  | { outcome: 'approved'; value: ApprovedConfirmation }
  | { outcome: 'error'; error: DirectorProtocolError };

type RejectTransactionResult =
  | { outcome: 'rejected'; confirmation: Confirmation }
  | { outcome: 'error'; error: DirectorProtocolError };

export class PostgresConfirmationRepository implements ConfirmationRepository {
  constructor(private readonly database: SqlDatabase) {}

  async listConfirmations(query: ListConfirmationsQuery): Promise<ConfirmationListSlice> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, query.userId, false);
      const permissions = await this.projectPermissions(
        transaction,
        query.userId,
        query.projectId,
        false,
        false,
        true,
      );
      if (!permissions.has('project.read')) {
        throw new ConcealedAuthorizationDeniedError(
          'project',
          query.projectId,
          ['project.read'],
        );
      }
      this.requirePermissions(permissions, ['confirmation.read']);
      const rows = await this.listConfirmationRows(transaction, query);
      const visibleRows = rows.slice(0, query.limit);
      const items = visibleRows.map(confirmationFromRow);
      const last = rows.length > query.limit ? visibleRows.at(-1) : undefined;
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: query.userId,
        action: 'confirmation.read',
        resourceType: 'project',
        resourceId: query.projectId,
        projectId: query.projectId,
        requestId: query.requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: query.userId,
        authorizedAction: 'confirmation.read',
        resourceType: 'project',
        resourceId: query.projectId,
        projectId: query.projectId,
        requestId: query.requestId,
        authorizationDecisionId,
        metadata: {
          view: 'confirmation_inbox',
          status: query.status,
          returned_count: items.length,
          page_limit: query.limit,
          continued: query.after !== null,
        },
      });
      return {
        items,
        nextPosition: last === undefined
          ? null
          : {
              createdAt: timestamp(last.createdAt),
              confirmationId: last.id,
            },
      };
    });
  }

  async getConfirmation(
    userId: string,
    requestId: string,
    confirmationId: string,
  ): Promise<Confirmation> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, userId, false);
      const row = await this.loadConfirmationRow(transaction, confirmationId, false);
      if (row === undefined) {
        throw notFound(confirmationId);
      }
      const permissions = await this.projectPermissions(
        transaction,
        userId,
        row.projectId,
        false,
        false,
      );
      this.requirePermissions(permissions, ['project.read'], true, confirmationId);
      this.requirePermissions(permissions, ['confirmation.read']);
      await this.insertAllowedConfirmationAudit(
        transaction,
        userId,
        requestId,
        row,
        'confirmation.read',
      );
      return confirmationFromRow(row);
    });
  }

  async approveConfirmation(command: ApproveConfirmationCommand): Promise<ApprovedConfirmation> {
    const result = await this.database.transaction((transaction) =>
      this.approveTransaction(transaction, command),
    );
    if (result.outcome === 'error') {
      throw result.error;
    }
    return result.value;
  }

  async rejectConfirmation(
    userId: string,
    confirmationId: string,
    requestId: string,
    decidedAt: string,
  ): Promise<Confirmation> {
    const result = await this.database.transaction((transaction) =>
      this.rejectTransaction(transaction, userId, confirmationId, requestId, decidedAt),
    );
    if (result.outcome === 'error') {
      throw result.error;
    }
    return result.confirmation;
  }

  private async approveTransaction(
    transaction: SqlQueryable,
    command: ApproveConfirmationCommand,
  ): Promise<ApprovalTransactionResult> {
    await this.requireActiveUser(transaction, command.userId, true);
    const confirmation = await this.loadConfirmationRow(
      transaction,
      command.confirmationId,
      true,
    );
    if (confirmation === undefined) {
      throw notFound(command.confirmationId);
    }
    const approverPermissions = await this.projectPermissions(
      transaction,
      command.userId,
      confirmation.projectId,
      true,
      false,
    );
    this.requirePermissions(approverPermissions, ['project.read'], true, confirmation.id);
    this.requirePermissions(approverPermissions, ['confirmation.approve']);
    if (isDecisionConfirmation(confirmation)) {
      return this.approveDecisionConfirmation(
        transaction,
        command,
        confirmation,
        approverPermissions,
      );
    }
    if (isAiResultSaveConfirmation(confirmation)) {
      return this.approveAiResultSaveConfirmation(
        transaction,
        command,
        confirmation,
        approverPermissions,
      );
    }
    return this.approveAgentRunConfirmation(
      transaction,
      command,
      confirmation,
      approverPermissions,
    );
  }

  private async approveAgentRunConfirmation(
    transaction: SqlQueryable,
    command: ApproveConfirmationCommand,
    confirmation: ConfirmationRow,
    approverPermissions: ReadonlySet<string>,
  ): Promise<ApprovalTransactionResult> {
    this.requireAgentRunTarget(confirmation);

    const run = await this.loadRun(transaction, confirmation.targetId, true);
    if (run === undefined || run.projectId !== confirmation.projectId) {
      throw notFound(confirmation.id);
    }
    if (confirmation.status === 'consumed') {
      const dispatch =
        run.status === 'queued'
          ? await this.rebuildConsumedDispatch(
              transaction,
              confirmation,
              run,
              command.userId,
              approverPermissions,
            )
          : null;
      await this.insertAllowedConfirmationAudit(
        transaction,
        command.userId,
        command.requestId,
        confirmation,
        'confirmation.approve',
        { replay: true },
      );
      return {
        outcome: 'approved',
        value: { confirmation: confirmationFromRow(confirmation), dispatch },
      };
    }
    if (confirmation.status !== 'pending') {
      throw conflict(`Confirmation is already ${confirmation.status}.`);
    }
    if (Date.parse(confirmation.expiresAt.toString()) <= Date.parse(command.dispatchedAt)) {
      await this.terminateWaitingWorkflow(
        transaction,
        confirmation,
        run,
        'expired',
        command.requestId,
        command.dispatchedAt,
      );
      return { outcome: 'error', error: conflict('Confirmation has expired.') };
    }
    if (
      run.status !== 'awaiting_user_confirmation' ||
      run.taskStatus !== 'awaiting_user_confirmation'
    ) {
      throw conflict('Confirmation target is not awaiting user confirmation.');
    }

    const validated = await this.validateOperation(
      transaction,
      confirmation,
      run,
      command.userId,
      approverPermissions,
    );
    if (!validated) {
      await this.terminateWaitingWorkflow(
        transaction,
        confirmation,
        run,
        'revoked',
        command.requestId,
        command.dispatchedAt,
      );
      return {
        outcome: 'error',
        error: conflict('Confirmation payload no longer matches the protected operation.'),
      };
    }

    const executionRequest = executionRequestForApproval(run, validated.frozenContext, command);
    await this.insertAllowedConfirmationAudit(
      transaction,
      command.userId,
      command.requestId,
      confirmation,
      'confirmation.approve',
      { replay: false },
    );
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'approved',
            decided_by_user_id = $2::uuid,
            decided_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, command.userId, command.dispatchedAt],
    );
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'queued',
            request_fingerprint = $2,
            dispatched_at = $3::timestamptz,
            deadline_at = $4::timestamptz
        WHERE id = $1::uuid
      `,
      [
        run.id,
        executionRequest.request_fingerprint,
        executionRequest.dispatched_at,
        executionRequest.deadline_at,
      ],
    );
    const gatewayPrincipalId = await this.loadGatewayPrincipal(transaction);
    await this.insertCapability(
      transaction,
      command,
      run,
      gatewayPrincipalId,
      validated.frozenContext,
    );
    await transaction.query(
      `UPDATE dirizhor.tasks SET status = 'running_agent' WHERE id = $1::uuid`,
      [run.taskId],
    );
    await this.insertApprovalAudits(
      transaction,
      confirmation,
      run,
      command,
      executionRequest,
    );
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'consumed', consumed_at = $2::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, command.dispatchedAt],
    );
    const committed = await this.loadConfirmationRow(transaction, confirmation.id, false);
    if (committed === undefined) {
      throw new Error('Consumed confirmation could not be loaded.');
    }
    return {
      outcome: 'approved',
      value: {
        confirmation: confirmationFromRow(committed),
        dispatch: {
          agentRunId: run.id,
          capabilityId: command.capabilityId,
          executionRequest,
        },
      },
    };
  }

  private async approveAiResultSaveConfirmation(
    transaction: SqlQueryable,
    command: ApproveConfirmationCommand,
    confirmation: ConfirmationRow,
    approverPermissions: ReadonlySet<string>,
  ): Promise<ApprovalTransactionResult> {
    const resultRow = await this.loadResultSaveTarget(transaction, confirmation.targetId, true);
    if (resultRow === undefined || resultRow.projectId !== confirmation.projectId) {
      throw notFound(confirmation.id);
    }
    if (confirmation.status === 'consumed') {
      if (resultRow.savedMemoryObjectId === null) {
        throw conflict('Consumed result-save confirmation has no saved memory object.');
      }
      await this.insertAllowedConfirmationAudit(
        transaction,
        command.userId,
        command.requestId,
        confirmation,
        'confirmation.approve',
        { replay: true },
      );
      return {
        outcome: 'approved',
        value: { confirmation: confirmationFromRow(confirmation), dispatch: null },
      };
    }
    if (confirmation.status !== 'pending') {
      throw conflict(`Confirmation is already ${confirmation.status}.`);
    }
    if (Date.parse(confirmation.expiresAt.toString()) <= Date.parse(command.dispatchedAt)) {
      await this.terminatePassiveConfirmation(
        transaction,
        confirmation,
        'expired',
        command.requestId,
        resultRow.id,
      );
      return { outcome: 'error', error: conflict('Confirmation has expired.') };
    }
    if (
      resultRow.runStatus !== 'completed' ||
      resultRow.taskStatus !== 'reviewing' ||
      resultRow.savedMemoryObjectId !== null
    ) {
      await this.terminatePassiveConfirmation(
        transaction,
        confirmation,
        'revoked',
        command.requestId,
        resultRow.id,
      );
      return {
        outcome: 'error',
        error: conflict('The AI result is no longer ready to be saved.'),
      };
    }
    if (
      resultRow.expiresAt !== null &&
      Date.parse(timestamp(resultRow.expiresAt)) <= Date.parse(command.dispatchedAt)
    ) {
      await this.terminatePassiveConfirmation(
        transaction,
        confirmation,
        'revoked',
        command.requestId,
        resultRow.id,
      );
      return { outcome: 'error', error: conflict('The temporary AI result has expired.') };
    }

    const payload = validatedResultSavePayload(confirmation);
    if (payload === undefined) {
      await this.terminatePassiveConfirmation(
        transaction,
        confirmation,
        'revoked',
        command.requestId,
        resultRow.id,
      );
      return {
        outcome: 'error',
        error: conflict('Confirmation payload no longer matches the protected operation.'),
      };
    }
    const result = resultSaveRecord(resultRow);
    const requesterPermissions =
      confirmation.requestedByUserId === command.userId
        ? approverPermissions
        : await this.projectPermissions(
            transaction,
            confirmation.requestedByUserId,
            confirmation.projectId,
            true,
          );
    const saveSensitivityLevel = await this.validateResultSaveAuthorization(
      transaction,
      requesterPermissions,
      result,
      payload,
    );
    await this.validateResultSaveAuthorization(
      transaction,
      approverPermissions,
      result,
      payload,
    );
    const currentPayloadSource = {
      result,
      saveSensitivityLevel,
      requestedByUserId: confirmation.requestedByUserId,
      input: payload.input,
    };
    const storedPayloadValid = hashCanonical(confirmation.frozenPayload) === confirmation.payloadHash;
    const currentPayloadHash = computeAiResultSaveConfirmationPayloadHash(currentPayloadSource);
    if (!storedPayloadValid || currentPayloadHash !== confirmation.payloadHash) {
      await this.terminatePassiveConfirmation(
        transaction,
        confirmation,
        'revoked',
        command.requestId,
        result.id,
      );
      return {
        outcome: 'error',
        error: conflict('Confirmation payload no longer matches the protected operation.'),
      };
    }

    await this.insertAllowedConfirmationAudit(
      transaction,
      command.userId,
      command.requestId,
      confirmation,
      'confirmation.approve',
      { replay: false },
    );
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'approved', decided_by_user_id = $2::uuid,
            decided_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, command.userId, command.dispatchedAt],
    );
    const memoryObject = await transaction.query<{ id: string }>(
      `
        INSERT INTO dirizhor.memory_objects (
          type, title, project_id, topic_id, author_user_id,
          summary, keywords, sensitivity_level
        )
        VALUES (
          'ai_result', $1, $2::uuid, $3::uuid, $4::uuid, $5, $6::text[], $7
        )
        RETURNING id::text AS id
      `,
      [
        payload.input.title,
        result.projectId,
        payload.input.topic_id,
        confirmation.requestedByUserId,
        payload.input.summary,
        payload.input.keywords,
        payload.save_sensitivity_level,
      ],
    );
    const memoryObjectId = memoryObject.rows[0]?.id;
    if (memoryObjectId === undefined) {
      throw new Error('AI result memory object could not be created.');
    }
    const documentVersion = await transaction.query<{ id: string }>(
      `
        INSERT INTO dirizhor.document_versions (
          memory_object_id, version_number, storage_uri, file_name, file_type,
          content_hash, size_bytes, created_by_user_id, change_summary
        )
        VALUES ($1::uuid, 1, $2, $3, $4, $5, $6, $7::uuid, $8)
        RETURNING id::text AS id
      `,
      [
        memoryObjectId,
        result.outputStorageUri,
        resultFileName(result),
        result.contentType,
        result.contentHash,
        result.sizeBytes,
        confirmation.requestedByUserId,
        'Saved from an approved AI agent result.',
      ],
    );
    const documentVersionId = documentVersion.rows[0]?.id;
    if (documentVersionId === undefined) {
      throw new Error('AI result document version could not be created.');
    }
    await this.insertResultRelationships(
      transaction,
      result.projectId,
      memoryObjectId,
      confirmation.requestedByUserId,
      payload.input.relationships,
    );
    await transaction.query(
      `
        UPDATE dirizhor.agent_run_results
        SET saved_memory_object_id = $2::uuid, saved_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [result.id, memoryObjectId, command.dispatchedAt],
    );
    await transaction.query(
      `
        UPDATE dirizhor.tasks
        SET status = 'completed', result_memory_object_id = $2::uuid,
            completed_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [result.taskId, memoryObjectId, command.dispatchedAt],
    );
    await this.insertResultSaveAudits(
      transaction,
      confirmation,
      command,
      result,
      memoryObjectId,
      documentVersionId,
      payload.input.relationships.length,
      payload.save_sensitivity_level,
    );
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'consumed', consumed_at = $2::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, command.dispatchedAt],
    );
    const committed = await this.loadConfirmationRow(transaction, confirmation.id, false);
    if (committed === undefined) {
      throw new Error('Consumed AI result save confirmation could not be loaded.');
    }
    return {
      outcome: 'approved',
      value: { confirmation: confirmationFromRow(committed), dispatch: null },
    };
  }

  private async approveDecisionConfirmation(
    transaction: SqlQueryable,
    command: ApproveConfirmationCommand,
    confirmation: ConfirmationRow,
    approverPermissions: ReadonlySet<string>,
  ): Promise<ApprovalTransactionResult> {
    const target = await this.loadDecisionOperationTarget(
      transaction,
      confirmation.targetId,
      true,
    );
    if (target === undefined || target.projectId !== confirmation.projectId) {
      throw notFound(confirmation.id);
    }
    const payload = validatedDecisionConfirmationPayload(confirmation.frozenPayload);
    if (
      payload === undefined ||
      payload.operation !== confirmation.operation ||
      payload.target_decision_id !== target.id ||
      payload.requested_by_user_id !== confirmation.requestedByUserId ||
      computeDecisionConfirmationPayloadHash(payload) !== confirmation.payloadHash
    ) {
      await this.terminateDecisionConfirmation(
        transaction,
        confirmation,
        'revoked',
        command.requestId,
      );
      return {
        outcome: 'error',
        error: conflict('Confirmation payload no longer matches the protected operation.'),
      };
    }
    if (
      confirmation.operation === 'decision_supersede' &&
      !validSupersedePayloadShape(payload, target)
    ) {
      await this.terminateDecisionConfirmation(
        transaction,
        confirmation,
        'revoked',
        command.requestId,
      );
      return {
        outcome: 'error',
        error: conflict('Frozen supersede payload is invalid for the target decision.'),
      };
    }
    if (confirmation.status === 'consumed') {
      await this.assertConsumedDecisionConfirmation(transaction, confirmation, target, payload);
      await this.insertAllowedConfirmationAudit(
        transaction,
        command.userId,
        command.requestId,
        confirmation,
        'confirmation.approve',
        { replay: true },
      );
      return {
        outcome: 'approved',
        value: { confirmation: confirmationFromRow(confirmation), dispatch: null },
      };
    }
    if (confirmation.status !== 'pending') {
      throw conflict(`Confirmation is already ${confirmation.status}.`);
    }
    if (Date.parse(confirmation.expiresAt.toString()) <= Date.parse(command.dispatchedAt)) {
      await this.terminateDecisionConfirmation(
        transaction,
        confirmation,
        'expired',
        command.requestId,
      );
      return { outcome: 'error', error: conflict('Confirmation has expired.') };
    }

    const requesterPermissions =
      confirmation.requestedByUserId === command.userId
        ? approverPermissions
        : await this.projectPermissions(
            transaction,
            confirmation.requestedByUserId,
            confirmation.projectId,
            true,
          );
    const required = confirmation.operation === 'decision_approve'
      ? decisionApproveOperationPermissions
      : decisionSupersedeOperationPermissions;
    this.requirePermissions(requesterPermissions, required);
    this.requirePermissions(approverPermissions, required);
    this.requireResultSensitivityPermissions(
      requesterPermissions,
      [target.sensitivityLevel, payload.decision.sensitivity_level],
    );
    this.requireResultSensitivityPermissions(
      approverPermissions,
      [target.sensitivityLevel, payload.decision.sensitivity_level],
    );

    if (confirmation.operation === 'decision_approve') {
      const relationships = await this.loadDecisionRelationshipRefs(transaction, target.id);
      const currentPayload = buildDecisionConfirmationPayload({
        operation: 'decision_approve',
        requestedByUserId: confirmation.requestedByUserId,
        targetDecisionId: target.id,
        decision: frozenDecisionFromOperationRow(target, relationships),
      });
      if (
        (target.status !== 'draft' && target.status !== 'proposed') ||
        computeDecisionConfirmationPayloadHash(currentPayload) !== confirmation.payloadHash
      ) {
        await this.terminateDecisionConfirmation(
          transaction,
          confirmation,
          'revoked',
          command.requestId,
        );
        return {
          outcome: 'error',
          error: conflict('Decision no longer matches the frozen approval request.'),
        };
      }
      await this.validateResultSaveReferences(
        transaction,
        requesterPermissions,
        target.projectId,
        target.topicId,
        relationships,
      );
      await this.validateResultSaveReferences(
        transaction,
        approverPermissions,
        target.projectId,
        target.topicId,
        relationships,
      );
      await this.beginDecisionConfirmationApproval(transaction, command, confirmation);
      await transaction.query(
        `
          UPDATE dirizhor.decisions
          SET status = 'approved', decided_by_user_id = $2::uuid,
              decided_at = $3::timestamptz, updated_at = $3::timestamptz
          WHERE id = $1::uuid
        `,
        [target.id, command.userId, command.dispatchedAt],
      );
      await this.insertDecisionConfirmationAudits(
        transaction,
        confirmation,
        command,
        [{ action: 'decision.approved', targetId: target.id }],
      );
    } else {
      if (target.status !== 'approved') {
        await this.terminateDecisionConfirmation(
          transaction,
          confirmation,
          'revoked',
          command.requestId,
        );
        return {
          outcome: 'error',
          error: conflict('The decision is no longer eligible for supersede.'),
        };
      }
      await this.validateResultSaveReferences(
        transaction,
        requesterPermissions,
        payload.decision.project_id,
        payload.decision.topic_id,
        payload.decision.relationships,
      );
      await this.validateResultSaveReferences(
        transaction,
        approverPermissions,
        payload.decision.project_id,
        payload.decision.topic_id,
        payload.decision.relationships,
      );
      const successor = await this.loadEffectiveSuccessor(transaction, target.id);
      if (successor !== undefined) {
        await this.terminateDecisionConfirmation(
          transaction,
          confirmation,
          'revoked',
          command.requestId,
        );
        return {
          outcome: 'error',
          error: conflict('The decision already has an effective successor.'),
        };
      }
      await this.beginDecisionConfirmationApproval(transaction, command, confirmation);
      await this.createApprovedSuccessor(
        transaction,
        confirmation,
        command,
        target,
        payload,
      );
      await this.insertDecisionConfirmationAudits(
        transaction,
        confirmation,
        command,
        [
          { action: 'decision.created', targetId: payload.decision.id },
          { action: 'decision.approved', targetId: payload.decision.id },
          { action: 'decision.superseded', targetId: target.id },
        ],
      );
    }
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'consumed', consumed_at = $2::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, command.dispatchedAt],
    );
    const committed = await this.loadConfirmationRow(transaction, confirmation.id, false);
    if (committed === undefined) {
      throw new Error('Consumed decision confirmation could not be loaded.');
    }
    return {
      outcome: 'approved',
      value: { confirmation: confirmationFromRow(committed), dispatch: null },
    };
  }

  private async rejectDecisionConfirmation(
    transaction: SqlQueryable,
    userId: string,
    requestId: string,
    decidedAt: string,
    confirmation: ConfirmationRow,
    permissions: ReadonlySet<string>,
  ): Promise<RejectTransactionResult> {
    const target = await this.loadDecisionOperationTarget(
      transaction,
      confirmation.targetId,
      true,
    );
    if (target === undefined || target.projectId !== confirmation.projectId) {
      throw notFound(confirmation.id);
    }
    const payload = validatedDecisionConfirmationPayload(confirmation.frozenPayload);
    if (
      payload === undefined ||
      payload.operation !== confirmation.operation ||
      payload.target_decision_id !== target.id ||
      payload.requested_by_user_id !== confirmation.requestedByUserId ||
      computeDecisionConfirmationPayloadHash(payload) !== confirmation.payloadHash ||
      (confirmation.operation === 'decision_supersede' &&
        !validSupersedePayloadShape(payload, target))
    ) {
      await this.terminateDecisionConfirmation(
        transaction,
        confirmation,
        'revoked',
        requestId,
      );
      return {
        outcome: 'error',
        error: conflict('Confirmation payload no longer matches the protected operation.'),
      };
    }
    const required = confirmation.operation === 'decision_approve'
      ? decisionApproveOperationPermissions
      : decisionSupersedeOperationPermissions;
    this.requirePermissions(permissions, required);
    this.requireResultSensitivityPermissions(
      permissions,
      [target.sensitivityLevel, payload.decision.sensitivity_level],
    );
    if (confirmation.status === 'rejected') {
      if (confirmation.operation === 'decision_approve' && target.status !== 'rejected') {
        throw conflict('Rejected approval confirmation has no rejected decision.');
      }
      await this.insertAllowedConfirmationAudit(
        transaction,
        userId,
        requestId,
        confirmation,
        'confirmation.reject',
        { replay: true },
      );
      return { outcome: 'rejected', confirmation: confirmationFromRow(confirmation) };
    }
    if (confirmation.status !== 'pending') {
      throw conflict(`Confirmation is already ${confirmation.status}.`);
    }
    if (Date.parse(confirmation.expiresAt.toString()) <= Date.parse(decidedAt)) {
      await this.terminateDecisionConfirmation(
        transaction,
        confirmation,
        'expired',
        requestId,
      );
      return { outcome: 'error', error: conflict('Confirmation has expired.') };
    }
    const requesterPermissions =
      confirmation.requestedByUserId === userId
        ? permissions
        : await this.projectPermissions(
            transaction,
            confirmation.requestedByUserId,
            confirmation.projectId,
            true,
          );
    this.requirePermissions(requesterPermissions, required);
    this.requireResultSensitivityPermissions(
      requesterPermissions,
      [target.sensitivityLevel, payload.decision.sensitivity_level],
    );
    if (confirmation.operation === 'decision_approve') {
      const relationships = await this.loadDecisionRelationshipRefs(transaction, target.id);
      const currentPayload = buildDecisionConfirmationPayload({
        operation: 'decision_approve',
        requestedByUserId: confirmation.requestedByUserId,
        targetDecisionId: target.id,
        decision: frozenDecisionFromOperationRow(target, relationships),
      });
      if (
        (target.status !== 'draft' && target.status !== 'proposed') ||
        computeDecisionConfirmationPayloadHash(currentPayload) !== confirmation.payloadHash
      ) {
        await this.terminateDecisionConfirmation(
          transaction,
          confirmation,
          'revoked',
          requestId,
        );
        return {
          outcome: 'error',
          error: conflict('Decision no longer matches the frozen approval request.'),
        };
      }
      await this.validateResultSaveReferences(
        transaction,
        requesterPermissions,
        target.projectId,
        target.topicId,
        relationships,
      );
      await this.validateResultSaveReferences(
        transaction,
        permissions,
        target.projectId,
        target.topicId,
        relationships,
      );
    } else {
      if (target.status !== 'approved') {
        await this.terminateDecisionConfirmation(
          transaction,
          confirmation,
          'revoked',
          requestId,
        );
        return {
          outcome: 'error',
          error: conflict('The decision is no longer eligible for supersede.'),
        };
      }
      await this.validateResultSaveReferences(
        transaction,
        requesterPermissions,
        payload.decision.project_id,
        payload.decision.topic_id,
        payload.decision.relationships,
      );
      await this.validateResultSaveReferences(
        transaction,
        permissions,
        payload.decision.project_id,
        payload.decision.topic_id,
        payload.decision.relationships,
      );
    }
    await this.insertAllowedConfirmationAudit(
      transaction,
      userId,
      requestId,
      confirmation,
      'confirmation.reject',
      { replay: false },
    );
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'rejected', decided_by_user_id = $2::uuid,
            decided_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, userId, decidedAt],
    );
    if (confirmation.operation === 'decision_approve') {
      await transaction.query(
        `
          UPDATE dirizhor.decisions
          SET status = 'rejected', decided_by_user_id = $2::uuid,
              decided_at = $3::timestamptz, updated_at = $3::timestamptz
          WHERE id = $1::uuid
        `,
        [target.id, userId, decidedAt],
      );
    }
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'user', $1::uuid, 'confirmation.rejected', 'confirmation', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        userId,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({
          operation: confirmation.operation,
          target_type: 'decision',
          target_id: target.id,
        }),
        requestId,
        confirmation.authorizationDecisionId,
      ],
    );
    if (confirmation.operation === 'decision_approve') {
      await transaction.query(
        `
          INSERT INTO dirizhor.audit_events (
            actor_type, actor_id, action, target_type, target_id,
            project_id, metadata, request_id, authorization_decision_id
          )
          VALUES (
            'user', $1::uuid, 'decision.rejected', 'decision', $2::uuid,
            $3::uuid, $4::jsonb, $5::uuid, $6::uuid
          )
        `,
        [
          userId,
          target.id,
          confirmation.projectId,
          JSON.stringify({ confirmation_id: confirmation.id }),
          requestId,
          confirmation.authorizationDecisionId,
        ],
      );
    }
    const rejected = await this.loadConfirmationRow(transaction, confirmation.id, false);
    if (rejected === undefined) {
      throw new Error('Rejected decision confirmation could not be loaded.');
    }
    return { outcome: 'rejected', confirmation: confirmationFromRow(rejected) };
  }

  private async rejectTransaction(
    transaction: SqlQueryable,
    userId: string,
    confirmationId: string,
    requestId: string,
    decidedAt: string,
  ): Promise<RejectTransactionResult> {
    await this.requireActiveUser(transaction, userId, true);
    const confirmation = await this.loadConfirmationRow(transaction, confirmationId, true);
    if (confirmation === undefined) {
      throw notFound(confirmationId);
    }
    const permissions = await this.projectPermissions(
      transaction,
      userId,
      confirmation.projectId,
      true,
      false,
    );
    this.requirePermissions(permissions, ['project.read'], true, confirmation.id);
    this.requirePermissions(permissions, ['confirmation.reject']);
    if (isDecisionConfirmation(confirmation)) {
      return this.rejectDecisionConfirmation(
        transaction,
        userId,
        requestId,
        decidedAt,
        confirmation,
        permissions,
      );
    }
    if (isAiResultSaveConfirmation(confirmation)) {
      return this.rejectAiResultSaveConfirmation(
        transaction,
        userId,
        requestId,
        decidedAt,
        confirmation,
      );
    }
    return this.rejectAgentRunConfirmation(
      transaction,
      userId,
      requestId,
      decidedAt,
      confirmation,
    );
  }

  private async rejectAgentRunConfirmation(
    transaction: SqlQueryable,
    userId: string,
    requestId: string,
    decidedAt: string,
    confirmation: ConfirmationRow,
  ): Promise<RejectTransactionResult> {
    this.requireAgentRunTarget(confirmation);
    if (confirmation.status === 'rejected') {
      await this.insertAllowedConfirmationAudit(
        transaction,
        userId,
        requestId,
        confirmation,
        'confirmation.reject',
        { replay: true },
      );
      return { outcome: 'rejected', confirmation: confirmationFromRow(confirmation) };
    }
    if (confirmation.status !== 'pending') {
      throw conflict(`Confirmation is already ${confirmation.status}.`);
    }
    const run = await this.loadRun(transaction, confirmation.targetId, true);
    if (run === undefined || run.projectId !== confirmation.projectId) {
      throw notFound(confirmation.id);
    }
    if (Date.parse(confirmation.expiresAt.toString()) <= Date.parse(decidedAt)) {
      await this.terminateWaitingWorkflow(
        transaction,
        confirmation,
        run,
        'expired',
        requestId,
        decidedAt,
      );
      return { outcome: 'error', error: conflict('Confirmation has expired.') };
    }
    if (
      run.status !== 'awaiting_user_confirmation' ||
      run.taskStatus !== 'awaiting_user_confirmation'
    ) {
      throw conflict('Confirmation target is not awaiting user confirmation.');
    }
    await this.insertAllowedConfirmationAudit(
      transaction,
      userId,
      requestId,
      confirmation,
      'confirmation.reject',
      { replay: false },
    );
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'rejected',
            decided_by_user_id = $2::uuid,
            decided_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, userId, decidedAt],
    );
    await this.cancelRunAndTask(transaction, run, decidedAt);
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'user', $1::uuid, 'confirmation.rejected', 'confirmation', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        userId,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({ target_type: 'agent_run', target_id: run.id }),
        requestId,
        confirmation.authorizationDecisionId,
      ],
    );
    const rejected = await this.loadConfirmationRow(transaction, confirmation.id, false);
    if (rejected === undefined) {
      throw new Error('Rejected confirmation could not be loaded.');
    }
    return { outcome: 'rejected', confirmation: confirmationFromRow(rejected) };
  }

  private async rejectAiResultSaveConfirmation(
    transaction: SqlQueryable,
    userId: string,
    requestId: string,
    decidedAt: string,
    confirmation: ConfirmationRow,
  ): Promise<RejectTransactionResult> {
    if (confirmation.status === 'rejected') {
      await this.insertAllowedConfirmationAudit(
        transaction,
        userId,
        requestId,
        confirmation,
        'confirmation.reject',
        { replay: true },
      );
      return { outcome: 'rejected', confirmation: confirmationFromRow(confirmation) };
    }
    if (confirmation.status !== 'pending') {
      throw conflict(`Confirmation is already ${confirmation.status}.`);
    }
    const result = await this.loadResultSaveTarget(transaction, confirmation.targetId, true);
    if (result === undefined || result.projectId !== confirmation.projectId) {
      throw notFound(confirmation.id);
    }
    if (Date.parse(confirmation.expiresAt.toString()) <= Date.parse(decidedAt)) {
      await this.terminatePassiveConfirmation(
        transaction,
        confirmation,
        'expired',
        requestId,
        result.id,
      );
      return { outcome: 'error', error: conflict('Confirmation has expired.') };
    }
    await this.insertAllowedConfirmationAudit(
      transaction,
      userId,
      requestId,
      confirmation,
      'confirmation.reject',
      { replay: false },
    );
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'rejected', decided_by_user_id = $2::uuid,
            decided_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, userId, decidedAt],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'user', $1::uuid, 'confirmation.rejected', 'confirmation', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        userId,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({ target_type: 'agent_run_result', target_id: result.id }),
        requestId,
        confirmation.authorizationDecisionId,
      ],
    );
    const rejected = await this.loadConfirmationRow(transaction, confirmation.id, false);
    if (rejected === undefined) {
      throw new Error('Rejected AI result save confirmation could not be loaded.');
    }
    return { outcome: 'rejected', confirmation: confirmationFromRow(rejected) };
  }

  private async beginDecisionConfirmationApproval(
    transaction: SqlQueryable,
    command: ApproveConfirmationCommand,
    confirmation: ConfirmationRow,
  ): Promise<void> {
    await this.insertAllowedConfirmationAudit(
      transaction,
      command.userId,
      command.requestId,
      confirmation,
      'confirmation.approve',
      { replay: false },
    );
    await transaction.query(
      `
        UPDATE dirizhor.confirmations
        SET status = 'approved', decided_by_user_id = $2::uuid,
            decided_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [confirmation.id, command.userId, command.dispatchedAt],
    );
  }

  private async createApprovedSuccessor(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    command: ApproveConfirmationCommand,
    target: DecisionOperationRow,
    payload: DecisionConfirmationPayload,
  ): Promise<void> {
    if (!validSupersedePayloadShape(payload, target)) {
      throw conflict('Frozen supersede payload is invalid for the target decision.');
    }
    await transaction.query(
      `
        INSERT INTO dirizhor.memory_objects (
          id, type, title, project_id, topic_id, author_user_id,
          summary, keywords, sensitivity_level
        )
        VALUES ($1::uuid, 'decision', $2, $3::uuid, $4::uuid, $5::uuid, $6, '{}', $7)
      `,
      [
        payload.decision.memory_object_id,
        payload.decision.title,
        payload.decision.project_id,
        payload.decision.topic_id,
        confirmation.requestedByUserId,
        payload.decision.rationale,
        payload.decision.sensitivity_level,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.decisions (
          id, memory_object_id, project_id, topic_id, title, decision_text,
          rationale, status, supersedes_decision_id, decided_by_user_id, decided_at,
          updated_at
        )
        VALUES (
          $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6,
          $7, 'approved', $8::uuid, $9::uuid, $10::timestamptz, $10::timestamptz
        )
      `,
      [
        payload.decision.id,
        payload.decision.memory_object_id,
        payload.decision.project_id,
        payload.decision.topic_id,
        payload.decision.title,
        payload.decision.decision_text,
        payload.decision.rationale,
        target.id,
        command.userId,
        command.dispatchedAt,
      ],
    );
    for (const relationship of payload.decision.relationships) {
      await transaction.query(
        `
          INSERT INTO dirizhor.relationships (
            project_id, source_type, source_id, target_type, target_id,
            relation_type, description, created_by_user_id
          )
          VALUES ($1::uuid, 'decision', $2::uuid, $3, $4::uuid, $5, $6, $7::uuid)
        `,
        [
          payload.decision.project_id,
          payload.decision.id,
          relationship.target_type,
          relationship.target_id,
          relationship.relation_type,
          relationship.description ?? null,
          confirmation.requestedByUserId,
        ],
      );
    }
    await transaction.query(
      `
        UPDATE dirizhor.decisions
        SET status = 'superseded', updated_at = $2::timestamptz
        WHERE id = $1::uuid
      `,
      [target.id, command.dispatchedAt],
    );
  }

  private async insertDecisionConfirmationAudits(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    command: ApproveConfirmationCommand,
    decisionEvents: readonly { action: string; targetId: string }[],
  ): Promise<void> {
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'user', $1::uuid, 'confirmation.approved', 'confirmation', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        command.userId,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({
          operation: confirmation.operation,
          target_type: 'decision',
          target_id: confirmation.targetId,
          self_approved: command.userId === confirmation.requestedByUserId,
        }),
        command.requestId,
        confirmation.authorizationDecisionId,
      ],
    );
    for (const event of decisionEvents) {
      await transaction.query(
        `
          INSERT INTO dirizhor.audit_events (
            actor_type, actor_id, action, target_type, target_id,
            project_id, metadata, request_id, authorization_decision_id
          )
          VALUES (
            'user', $1::uuid, $2, 'decision', $3::uuid,
            $4::uuid, $5::jsonb, $6::uuid, $7::uuid
          )
        `,
        [
          command.userId,
          event.action,
          event.targetId,
          confirmation.projectId,
          JSON.stringify({ confirmation_id: confirmation.id }),
          command.requestId,
          confirmation.authorizationDecisionId,
        ],
      );
    }
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'user', $1::uuid, 'confirmation.consumed', 'confirmation', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        command.userId,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({
          operation: confirmation.operation,
          target_type: 'decision',
          target_id: confirmation.targetId,
        }),
        command.requestId,
        confirmation.authorizationDecisionId,
      ],
    );
  }

  private async assertConsumedDecisionConfirmation(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    target: DecisionOperationRow,
    payload: DecisionConfirmationPayload,
  ): Promise<void> {
    if (confirmation.operation === 'decision_approve') {
      if (target.status !== 'approved') {
        throw conflict('Consumed approval confirmation has no approved decision.');
      }
      return;
    }
    const successor = await this.loadDecisionOperationTarget(
      transaction,
      payload.decision.id,
      false,
    );
    if (
      target.status !== 'superseded' ||
      successor === undefined ||
      successor.status !== 'approved' ||
      successor.supersedesDecisionId !== target.id
    ) {
      throw conflict('Consumed supersede confirmation has no effective successor.');
    }
  }

  private async terminateDecisionConfirmation(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    status: 'expired' | 'revoked',
    requestId: string,
  ): Promise<void> {
    await transaction.query(
      `UPDATE dirizhor.confirmations SET status = $2 WHERE id = $1::uuid`,
      [confirmation.id, status],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'system', NULL, $1, 'confirmation', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        `confirmation.${status}`,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({
          operation: confirmation.operation,
          target_type: 'decision',
          target_id: confirmation.targetId,
        }),
        requestId,
        confirmation.authorizationDecisionId,
      ],
    );
  }

  private async loadDecisionOperationTarget(
    transaction: SqlQueryable,
    decisionId: string,
    lock: boolean,
  ): Promise<DecisionOperationRow | undefined> {
    const result = await transaction.query<DecisionOperationRow>(
      `
        SELECT
          decision.id::text AS id,
          decision.memory_object_id::text AS "memoryObjectId",
          decision.project_id::text AS "projectId",
          decision.topic_id::text AS "topicId",
          decision.title,
          decision.decision_text AS "decisionText",
          decision.rationale,
          decision.status,
          decision.supersedes_decision_id::text AS "supersedesDecisionId",
          memory.sensitivity_level AS "sensitivityLevel"
        FROM dirizhor.decisions AS decision
        JOIN dirizhor.memory_objects AS memory
          ON memory.id = decision.memory_object_id
         AND memory.project_id = decision.project_id
        WHERE decision.id = $1::uuid
        ${lock ? 'FOR UPDATE OF decision' : ''}
      `,
      [decisionId],
    );
    return result.rows[0];
  }

  private async loadDecisionRelationshipRefs(
    transaction: SqlQueryable,
    decisionId: string,
  ): Promise<RelationshipRef[]> {
    const result = await transaction.query<{
      targetType: RelationshipEndpointType;
      targetId: string;
      relationType: RelationshipRef['relation_type'];
      description: string | null;
    }>(
      `
        SELECT
          target_type AS "targetType",
          target_id::text AS "targetId",
          relation_type AS "relationType",
          description
        FROM dirizhor.relationships
        WHERE source_type = 'decision' AND source_id = $1::uuid
        ORDER BY target_type, target_id, relation_type, id
      `,
      [decisionId],
    );
    return result.rows.map((row) => ({
      target_type: row.targetType,
      target_id: row.targetId,
      relation_type: row.relationType,
      description: row.description,
    }));
  }

  private async loadEffectiveSuccessor(
    transaction: SqlQueryable,
    decisionId: string,
  ): Promise<string | undefined> {
    const result = await transaction.query<{ id: string }>(
      `
        SELECT id::text AS id
        FROM dirizhor.decisions
        WHERE supersedes_decision_id = $1::uuid
          AND status IN ('approved', 'superseded')
        ORDER BY created_at, id
        LIMIT 1
        FOR UPDATE
      `,
      [decisionId],
    );
    return result.rows[0]?.id;
  }

  private async insertAllowedConfirmationAudit(
    transaction: SqlQueryable,
    userId: string,
    requestId: string,
    confirmation: ConfirmationRow,
    action: 'confirmation.read' | 'confirmation.approve' | 'confirmation.reject',
    metadata: Readonly<Record<string, unknown>> = {},
  ): Promise<void> {
    const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
      principalUserId: userId,
      action,
      resourceType: 'confirmation',
      resourceId: confirmation.id,
      projectId: confirmation.projectId,
      requestId,
    });
    await insertAllowedAccessAudit(transaction, {
      actorUserId: userId,
      authorizedAction: action,
      resourceType: 'confirmation',
      resourceId: confirmation.id,
      projectId: confirmation.projectId,
      requestId,
      authorizationDecisionId,
      metadata: {
        ...metadata,
        operation: confirmation.operation,
        status_before: confirmation.status,
        protected_authorization_decision_id: confirmation.authorizationDecisionId,
      },
    });
  }

  private async validateOperation(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    run: RunRow,
    approverId: string,
    approverPermissions: ReadonlySet<string>,
  ): Promise<ValidatedOperation | undefined> {
    const contexts = await this.loadContexts(transaction, run.id, run.projectId, true);
    const frozenContext = contexts.map((row) => contextDescriptor(row, false));
    const currentContext = contexts.map((row) => contextDescriptor(row, true));
    const requesterPermissions =
      run.requestedByUserId === approverId
        ? approverPermissions
        : await this.projectPermissions(transaction, run.requestedByUserId, run.projectId, true);
    this.requirePermissions(requesterPermissions, requesterPermissionsFor(currentContext, run));
    this.requirePermissions(approverPermissions, approverPermissionsFor(currentContext, run));

    const contextSetHash = run.contextSetHash;
    if (
      contextSetHash === null ||
      computeFrozenContextSetHash(run.id, run.projectId, frozenContext) !== contextSetHash
    ) {
      throw conflict('Frozen agent context hash is invalid.');
    }
    const policy = await this.loadProjectAiPolicy(transaction, run.projectId);
    const policyDecision = evaluateAgentPolicy(policy, {
      deploymentClass: run.deploymentClass,
      provider: run.provider,
      providerDataProfileVersion: run.providerDataProfileVersion,
      maximumContextSensitivity: maximumSensitivity(
        currentContext.map((item) => item.sensitivityLevel),
      ),
      contextItemCount: currentContext.length,
    });
    const source = confirmationPayloadSource(
      run,
      currentContext,
      contextSetHash,
      policyDecision,
    );
    const storedPayloadValid = hashCanonical(confirmation.frozenPayload) === confirmation.payloadHash;
    const currentPayloadHash = computeAgentRunConfirmationPayloadHash(source);
    if (
      !storedPayloadValid ||
      policyDecision.confirmationOperation !== confirmation.operation ||
      currentPayloadHash !== confirmation.payloadHash
    ) {
      return undefined;
    }
    return { run, frozenContext, currentContext, policyDecision };
  }

  private async rebuildConsumedDispatch(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    run: RunRow,
    approverId: string,
    approverPermissions: ReadonlySet<string>,
  ): Promise<ConfirmationDispatch> {
    const validated = await this.validateOperation(
      transaction,
      confirmation,
      run,
      approverId,
      approverPermissions,
    );
    if (validated === undefined) {
      throw conflict('Consumed confirmation no longer passes current policy checks.');
    }
    const capability = await transaction.query<{ id: string }>(
      `
        SELECT id::text AS id
        FROM dirizhor.agent_capabilities
        WHERE agent_run_id = $1::uuid
        ORDER BY issued_at DESC
        LIMIT 1
        FOR SHARE
      `,
      [run.id],
    );
    const capabilityId = capability.rows[0]?.id;
    if (capabilityId === undefined) {
      throw conflict('Consumed confirmation has no dispatch capability.');
    }
    return {
      agentRunId: run.id,
      capabilityId,
      executionRequest: executionRequestFromRun(run, validated.frozenContext),
    };
  }

  private async terminateWaitingWorkflow(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    run: RunRow,
    status: 'expired' | 'revoked',
    requestId: string,
    occurredAt: string,
  ): Promise<void> {
    await transaction.query(
      `UPDATE dirizhor.confirmations SET status = $2 WHERE id = $1::uuid`,
      [confirmation.id, status],
    );
    await this.cancelRunAndTask(transaction, run, occurredAt);
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'system', NULL, $1, 'confirmation', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        `confirmation.${status}`,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({ target_type: 'agent_run', target_id: run.id }),
        requestId,
        confirmation.authorizationDecisionId,
      ],
    );
  }

  private async terminatePassiveConfirmation(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    status: 'expired' | 'revoked',
    requestId: string,
    resultId: string,
  ): Promise<void> {
    await transaction.query(
      `UPDATE dirizhor.confirmations SET status = $2 WHERE id = $1::uuid`,
      [confirmation.id, status],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'system', NULL, $1, 'confirmation', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        `confirmation.${status}`,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({ target_type: 'agent_run_result', target_id: resultId }),
        requestId,
        confirmation.authorizationDecisionId,
      ],
    );
  }

  private async validateResultSaveAuthorization(
    transaction: SqlQueryable,
    permissions: ReadonlySet<string>,
    result: AgentResultRecord,
    payload: AiResultSaveConfirmationPayload,
  ): Promise<SensitivityLevel> {
    this.requirePermissions(permissions, resultSaveOperationPermissions);
    const contexts = await this.loadContexts(transaction, result.agentRunId, result.projectId, true);
    const sensitivities = contexts.flatMap((context) => [
      context.sensitivityLevel,
      context.currentSensitivityLevel,
    ]);
    sensitivities.push(result.sensitivityLevel);
    this.requireResultSensitivityPermissions(permissions, sensitivities);
    await this.validateResultSaveReferences(
      transaction,
      permissions,
      result.projectId,
      payload.input.topic_id,
      payload.input.relationships,
    );
    return maximumSensitivity(sensitivities);
  }

  private requireResultSensitivityPermissions(
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

  private async validateResultSaveReferences(
    transaction: SqlQueryable,
    permissions: ReadonlySet<string>,
    projectId: string,
    topicId: string | null,
    relationships: readonly RelationshipRef[],
  ): Promise<void> {
    if (topicId !== null) {
      this.requirePermissions(permissions, ['topic.read']);
      const topic = await transaction.query<{ id: string }>(
        `
          SELECT id::text AS id FROM dirizhor.topics
          WHERE id = $1::uuid AND project_id = $2::uuid
          FOR SHARE
        `,
        [topicId, projectId],
      );
      if (topic.rowCount !== 1) {
        throw conflict('The frozen result topic is no longer available.');
      }
    }
    for (const relationship of relationships) {
      await this.validateResultRelationshipTarget(
        transaction,
        permissions,
        projectId,
        relationship.target_type,
        relationship.target_id,
      );
    }
  }

  private async validateResultRelationshipTarget(
    transaction: SqlQueryable,
    permissions: ReadonlySet<string>,
    projectId: string,
    targetType: RelationshipEndpointType,
    targetId: string,
  ): Promise<void> {
    if (targetType === 'memory_object' || targetType === 'open_question') {
      const target = await this.loadResultMemoryTarget(
        transaction,
        projectId,
        targetType,
        targetId,
      );
      if (target === undefined || target.status !== 'active') {
        throw conflict('A frozen relationship target is no longer available.');
      }
      this.requireResultSensitivityPermissions(permissions, [target.sensitivityLevel]);
      return;
    }
    const requiredPermission =
      targetType === 'decision'
        ? 'decision.read'
        : targetType === 'task'
          ? 'task.read'
          : 'agent_run.read';
    this.requirePermissions(permissions, [requiredPermission]);
    if (targetType === 'decision') {
      const decision = await transaction.query<{ sensitivityLevel: SensitivityLevel }>(
        `
          SELECT memory.sensitivity_level AS "sensitivityLevel"
          FROM dirizhor.decisions AS decision
          JOIN dirizhor.memory_objects AS memory
            ON memory.id = decision.memory_object_id
           AND memory.project_id = decision.project_id
          WHERE decision.id = $1::uuid AND decision.project_id = $2::uuid
          FOR SHARE OF decision, memory
        `,
        [targetId, projectId],
      );
      const row = decision.rows[0];
      if (row === undefined) {
        throw conflict('A frozen relationship target is no longer available.');
      }
      this.requireResultSensitivityPermissions(permissions, [row.sensitivityLevel]);
      return;
    }
    const target = await transaction.query<{ id: string }>(
      `
        SELECT id::text AS id FROM dirizhor.${relationshipTable(targetType)}
        WHERE id = $1::uuid AND project_id = $2::uuid
        FOR SHARE
      `,
      [targetId, projectId],
    );
    if (target.rowCount !== 1) {
      throw conflict('A frozen relationship target is no longer available.');
    }
  }

  private async loadResultMemoryTarget(
    transaction: SqlQueryable,
    projectId: string,
    targetType: 'memory_object' | 'open_question',
    targetId: string,
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
        FOR SHARE OF memory
      `,
      [targetId, projectId],
    );
    return result.rows[0];
  }

  private async insertResultRelationships(
    transaction: SqlQueryable,
    projectId: string,
    memoryObjectId: string,
    requestedByUserId: string,
    relationships: readonly RelationshipRef[],
  ): Promise<void> {
    for (const relationship of relationships) {
      await transaction.query(
        `
          INSERT INTO dirizhor.relationships (
            project_id, source_type, source_id, target_type, target_id,
            relation_type, description, created_by_user_id
          )
          VALUES (
            $1::uuid, 'memory_object', $2::uuid, $3, $4::uuid, $5, $6, $7::uuid
          )
        `,
        [
          projectId,
          memoryObjectId,
          relationship.target_type,
          relationship.target_id,
          relationship.relation_type,
          relationship.description ?? null,
          requestedByUserId,
        ],
      );
    }
  }

  private async insertResultSaveAudits(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    command: ApproveConfirmationCommand,
    result: AgentResultRecord,
    memoryObjectId: string,
    documentVersionId: string,
    relationshipCount: number,
    saveSensitivityLevel: SensitivityLevel,
  ): Promise<void> {
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES
          (
            'user', $1::uuid, 'confirmation.approved', 'confirmation', $2::uuid,
            $3::uuid, $4::jsonb, $5::uuid, $6::uuid
          ),
          (
            'user', $1::uuid, 'memory_object.created', 'memory_object', $7::uuid,
            $3::uuid, $8::jsonb, $5::uuid, $6::uuid
          ),
          (
            'user', $1::uuid, 'document_version.created', 'document_version', $9::uuid,
            $3::uuid, $10::jsonb, $5::uuid, $6::uuid
          ),
          (
            'user', $1::uuid, 'ai_result.saved', 'memory_object', $7::uuid,
            $3::uuid, $11::jsonb, $5::uuid, $6::uuid
          ),
          (
            'user', $1::uuid, 'task.completed', 'task', $12::uuid,
            $3::uuid, $13::jsonb, $5::uuid, $6::uuid
          ),
          (
            'user', $1::uuid, 'confirmation.consumed', 'confirmation', $2::uuid,
            $3::uuid, $14::jsonb, $5::uuid, $6::uuid
          )
      `,
      [
        command.userId,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({
          target_type: 'agent_run_result',
          target_id: result.id,
          self_approved: command.userId === confirmation.requestedByUserId,
        }),
        command.requestId,
        confirmation.authorizationDecisionId,
        memoryObjectId,
        JSON.stringify({
          type: 'ai_result',
          sensitivity_level: saveSensitivityLevel,
          source_agent_run_id: result.agentRunId,
        }),
        documentVersionId,
        JSON.stringify({
          memory_object_id: memoryObjectId,
          version_number: 1,
          file_type: result.contentType,
          content_hash: result.contentHash,
          size_bytes: result.sizeBytes,
        }),
        JSON.stringify({
          agent_run_id: result.agentRunId,
          agent_run_result_id: result.id,
          document_version_id: documentVersionId,
          relationship_count: relationshipCount,
        }),
        result.taskId,
        JSON.stringify({ result_memory_object_id: memoryObjectId }),
        JSON.stringify({ target_type: 'agent_run_result', target_id: result.id }),
      ],
    );
  }

  private async cancelRunAndTask(
    transaction: SqlQueryable,
    run: RunRow,
    finishedAt: string,
  ): Promise<void> {
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'cancelled', finished_at = $2::timestamptz
        WHERE id = $1::uuid
      `,
      [run.id, finishedAt],
    );
    await transaction.query(
      `UPDATE dirizhor.tasks SET status = 'cancelled' WHERE id = $1::uuid`,
      [run.taskId],
    );
  }

  private async insertCapability(
    transaction: SqlQueryable,
    command: ApproveConfirmationCommand,
    run: RunRow,
    gatewayPrincipalId: string,
    context: readonly FrozenContextDescriptor[],
  ): Promise<void> {
    if (run.contextSetHash === null) {
      throw conflict('Agent run has no frozen context hash.');
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
          $1::uuid, $2::uuid, $3::uuid, $4::uuid,
          ARRAY['context_bundle.read']::text[], $5, $6,
          $7::timestamptz, $8::timestamptz
        )
      `,
      [
        command.capabilityId,
        run.id,
        run.projectId,
        gatewayPrincipalId,
        run.contextSetHash,
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
          run.projectId,
          item.memory_object_id,
          item.document_version_id,
        ],
      );
    }
  }

  private async insertApprovalAudits(
    transaction: SqlQueryable,
    confirmation: ConfirmationRow,
    run: RunRow,
    command: ApproveConfirmationCommand,
    request: AgentExecutionRequest,
  ): Promise<void> {
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES
          (
            'user', $1::uuid, 'confirmation.approved', 'confirmation', $2::uuid,
            $3::uuid, $4::jsonb, $5::uuid, $6::uuid
          ),
          (
            'user', $1::uuid, 'agent_run.dispatched', 'agent_run', $7::uuid,
            $3::uuid, $8::jsonb, $5::uuid, $6::uuid
          ),
          (
            'user', $1::uuid, 'confirmation.consumed', 'confirmation', $2::uuid,
            $3::uuid, $9::jsonb, $5::uuid, $6::uuid
          )
      `,
      [
        command.userId,
        confirmation.id,
        confirmation.projectId,
        JSON.stringify({
          target_type: 'agent_run',
          target_id: run.id,
          self_approved: command.userId === confirmation.requestedByUserId,
        }),
        command.requestId,
        confirmation.authorizationDecisionId,
        run.id,
        JSON.stringify({
          agent_type: request.agent_type,
          provider: request.provider,
          model: request.model,
          deployment_class: request.deployment_class,
          provider_data_profile_version: request.provider_data_profile_version,
          context_set_hash: request.context_set_hash,
          context_item_count: request.context_item_count,
          max_context_sensitivity: request.max_context_sensitivity,
          deadline_at: request.deadline_at,
        }),
        JSON.stringify({ target_type: 'agent_run', target_id: run.id }),
      ],
    );
  }

  private async loadConfirmationRow(
    transaction: SqlQueryable,
    confirmationId: string,
    lock: boolean,
  ): Promise<ConfirmationRow | undefined> {
    const result = await transaction.query<ConfirmationRow>(
      `${confirmationSelect}
       WHERE confirmation.id = $1::uuid
       ${lock ? 'FOR UPDATE' : ''}`,
      [confirmationId],
    );
    return result.rows[0];
  }

  private async listConfirmationRows(
    transaction: SqlQueryable,
    query: ListConfirmationsQuery,
  ): Promise<ConfirmationRow[]> {
    const result = await transaction.query<ConfirmationRow>(
      `${confirmationSelect}
       WHERE confirmation.project_id = $1::uuid
         AND confirmation.status = $2
         AND (
           $3::timestamptz IS NULL
           OR (confirmation.created_at, confirmation.id) < ($3::timestamptz, $4::uuid)
         )
       ORDER BY confirmation.created_at DESC, confirmation.id DESC
       LIMIT $5`,
      [
        query.projectId,
        query.status,
        query.after?.createdAt ?? null,
        query.after?.confirmationId ?? null,
        query.limit + 1,
      ],
    );
    return result.rows;
  }

  private async loadResultSaveTarget(
    transaction: SqlQueryable,
    resultId: string,
    lock: boolean,
  ): Promise<ResultSaveRow | undefined> {
    const result = await transaction.query<ResultSaveRow>(
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
          result.saved_at AS "savedAt",
          run.status AS "runStatus",
          task.status AS "taskStatus"
        FROM dirizhor.agent_run_results AS result
        JOIN dirizhor.agent_runs AS run
          ON run.id = result.agent_run_id AND run.project_id = result.project_id
        JOIN dirizhor.tasks AS task
          ON task.id = run.task_id AND task.project_id = run.project_id
        WHERE result.id = $1::uuid
        ${lock ? 'FOR UPDATE OF result, run, task' : ''}
      `,
      [resultId],
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

  private async loadContexts(
    transaction: SqlQueryable,
    agentRunId: string,
    projectId: string,
    lock: boolean,
  ): Promise<ContextRow[]> {
    const result = await transaction.query<ContextRow>(
      `
        SELECT
          context.position,
          context.memory_object_id::text AS "memoryObjectId",
          context.document_version_id::text AS "documentVersionId",
          version.file_name AS "fileName",
          version.file_type AS "mediaType",
          version.size_bytes AS "sizeBytes",
          version.content_hash AS "contentHash",
          context.sensitivity_level AS "sensitivityLevel",
          memory.sensitivity_level AS "currentSensitivityLevel",
          context.access_reason AS "accessReason"
        FROM dirizhor.agent_run_contexts AS context
        JOIN dirizhor.document_versions AS version
          ON version.id = context.document_version_id
         AND version.memory_object_id = context.memory_object_id
        JOIN dirizhor.memory_objects AS memory
          ON memory.id = context.memory_object_id
         AND memory.project_id = context.project_id
        WHERE context.agent_run_id = $1::uuid
          AND context.project_id = $2::uuid
        ORDER BY context.position
        ${lock ? 'FOR SHARE OF context, version, memory' : ''}
      `,
      [agentRunId, projectId],
    );
    if (
      result.rows.length === 0 ||
      result.rows.some((row, index) => row.position !== index + 1)
    ) {
      throw conflict('Frozen agent context is incomplete.');
    }
    return result.rows;
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
    if (
      row === undefined ||
      !isRecord(row.profileVersions) ||
      !Number.isSafeInteger(row.bulkContextObjectLimit) ||
      row.bulkContextObjectLimit < 1
    ) {
      throw new Error('Project AI policy is missing or invalid.');
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
        WHERE code = 'agent-gateway' AND status = 'active'
        FOR SHARE
      `,
    );
    const id = result.rows[0]?.id;
    if (id === undefined) {
      throw new Error('Active Agent Gateway service principal is missing.');
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
    reportMissingProject = false,
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
      throw reportMissingProject ? projectNotFound(projectId) : notFound(projectId);
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
    conceal = false,
    confirmationId?: string,
  ): void {
    const missing = required.filter((permission) => !granted.has(permission));
    if (missing.length === 0) {
      return;
    }
    if (conceal && confirmationId !== undefined) {
      throw new ConcealedAuthorizationDeniedError('confirmation', confirmationId, missing);
    }
    throw new DirectorProtocolError(
      403,
      'access_denied',
      'The user lacks required project permissions.',
      false,
      { missing_permissions: missing },
    );
  }

  private requireAgentRunTarget(confirmation: ConfirmationRow): void {
    if (
      confirmation.targetType !== 'agent_run' ||
      !['agent_context_share', 'bulk_context_share'].includes(confirmation.operation)
    ) {
      throw conflict('Confirmation target is not supported by this workflow.');
    }
  }
}

function isDecisionConfirmation(confirmation: ConfirmationRow): boolean {
  if (
    confirmation.operation !== 'decision_approve' &&
    confirmation.operation !== 'decision_supersede'
  ) {
    return false;
  }
  if (confirmation.targetType !== 'decision') {
    throw conflict('Decision confirmation has an invalid target.');
  }
  return true;
}

function frozenDecisionFromOperationRow(
  decision: DecisionOperationRow,
  relationships: readonly RelationshipRef[],
): DecisionConfirmationPayload['decision'] {
  return {
    id: decision.id,
    memory_object_id: decision.memoryObjectId,
    project_id: decision.projectId,
    topic_id: decision.topicId,
    title: decision.title,
    decision_text: decision.decisionText,
    rationale: decision.rationale,
    sensitivity_level: decision.sensitivityLevel,
    relationships: [...relationships],
  };
}

function validSupersedePayloadShape(
  payload: DecisionConfirmationPayload,
  target: DecisionOperationRow,
): boolean {
  if (
    payload.operation !== 'decision_supersede' ||
    payload.target_decision_id !== target.id ||
    payload.decision.project_id !== target.projectId ||
    payload.decision.topic_id !== target.topicId ||
    payload.decision.id === target.id ||
    payload.decision.memory_object_id === target.memoryObjectId
  ) {
    return false;
  }
  const supersedes = payload.decision.relationships.filter(
    (relationship) =>
      relationship.target_type === 'decision' &&
      relationship.target_id === target.id &&
      relationship.relation_type === 'supersedes',
  );
  return supersedes.length === 1;
}

function isAiResultSaveConfirmation(confirmation: ConfirmationRow): boolean {
  if (confirmation.operation !== 'ai_result_save') {
    return false;
  }
  if (confirmation.targetType !== 'agent_run_result') {
    throw conflict('AI result save confirmation has an invalid target.');
  }
  return true;
}

function validatedResultSavePayload(
  confirmation: ConfirmationRow,
): AiResultSaveConfirmationPayload | undefined {
  if (!Value.Check(AiResultSaveConfirmationPayloadSchema, confirmation.frozenPayload)) {
    return undefined;
  }
  const payload = confirmation.frozenPayload;
  if (
    payload.operation !== confirmation.operation ||
    payload.result.id !== confirmation.targetId ||
    payload.result.project_id !== confirmation.projectId ||
    payload.requested_by_user_id !== confirmation.requestedByUserId
  ) {
    return undefined;
  }
  return payload;
}

function resultSaveRecord(row: ResultSaveRow): AgentResultRecord {
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
    expiresAt: row.expiresAt === null ? null : timestamp(row.expiresAt),
    savedMemoryObjectId: row.savedMemoryObjectId,
    savedAt: row.savedAt === null ? null : timestamp(row.savedAt),
  };
}

function relationshipTable(
  targetType: Exclude<RelationshipEndpointType, 'memory_object' | 'open_question'>,
): string {
  switch (targetType) {
    case 'decision':
      return 'decisions';
    case 'task':
      return 'tasks';
    case 'agent_run':
      return 'agent_runs';
  }
}

function resultFileName(result: AgentResultRecord): string {
  const extension =
    result.contentType === 'text/markdown'
      ? '.md'
      : result.contentType === 'application/json'
        ? '.json'
        : result.contentType.startsWith('text/')
          ? '.txt'
          : '.bin';
  return `ai-result-${result.id}${extension}`;
}

function contextDescriptor(row: ContextRow, current: boolean): FrozenContextDescriptor {
  return {
    position: row.position,
    memory_object_id: row.memoryObjectId,
    document_version_id: row.documentVersionId,
    access_reason: row.accessReason,
    fileName: row.fileName,
    mediaType: row.mediaType,
    sizeBytes: safeSize(row.sizeBytes),
    contentHash: row.contentHash,
    sensitivityLevel: current ? row.currentSensitivityLevel : row.sensitivityLevel,
  };
}

function requesterPermissionsFor(
  context: readonly FrozenContextDescriptor[],
  run: RunRow,
): string[] {
  return [...requesterPermissions, ...conditionalPermissions(context, run)];
}

function approverPermissionsFor(
  context: readonly FrozenContextDescriptor[],
  run: RunRow,
): string[] {
  return [...approverOperationPermissions, ...conditionalPermissions(context, run)];
}

function conditionalPermissions(
  context: readonly FrozenContextDescriptor[],
  run: RunRow,
): string[] {
  const required: string[] = [];
  if (context.some((item) => item.sensitivityLevel === 'confidential')) {
    required.push('memory_object.read_confidential', 'agent_context.share_confidential');
  }
  if (context.some((item) => item.sensitivityLevel === 'restricted')) {
    required.push('memory_object.read_restricted');
  }
  if (run.deploymentClass === 'external') {
    required.push('agent_provider.use_external');
  }
  return required;
}

function confirmationPayloadSource(
  run: RunRow,
  context: readonly FrozenContextDescriptor[],
  contextSetHash: string,
  policyDecision: AgentPolicyDecision,
) {
  return {
    agentRunId: run.id,
    taskId: run.taskId,
    projectId: run.projectId,
    requestedByUserId: run.requestedByUserId,
    originRequestId: run.originRequestId,
    provider: run.provider,
    model: run.model,
    deploymentClass: run.deploymentClass,
    providerDataProfileVersion: run.providerDataProfileVersion,
    input: runInput(run),
    contextSetHash,
    context,
    confirmationReasons: policyDecision.confirmationReasons,
  };
}

function runInput(run: RunRow): AgentRunCreate {
  return {
    agent_type: run.agentType,
    purpose: run.purpose,
    instructions: run.instructions,
    context: [],
  };
}

function executionRequestForApproval(
  run: RunRow,
  context: readonly FrozenContextDescriptor[],
  command: ApproveConfirmationCommand,
): AgentExecutionRequest {
  if (run.contextSetHash === null) {
    throw conflict('Agent run has no frozen context hash.');
  }
  const request: AgentExecutionRequest = {
    protocol_version: '1.0',
    project_id: run.projectId,
    task_id: run.taskId,
    origin_request_id: run.originRequestId,
    request_fingerprint: `sha256:${'0'.repeat(64)}`,
    agent_type: run.agentType,
    provider: run.provider,
    model: run.model,
    purpose: run.purpose,
    instructions: run.instructions,
    deployment_class: run.deploymentClass,
    provider_data_profile_version: run.providerDataProfileVersion,
    context_set_hash: run.contextSetHash,
    context_item_count: context.length,
    max_context_sensitivity: maximumSensitivity(
      context.map((item) => item.sensitivityLevel),
    ),
    dispatched_at: command.dispatchedAt,
    deadline_at: command.deadlineAt,
  };
  request.request_fingerprint = computeRequestFingerprint(run.id, request);
  return request;
}

function executionRequestFromRun(
  run: RunRow,
  context: readonly FrozenContextDescriptor[],
): AgentExecutionRequest {
  if (
    run.contextSetHash === null ||
    run.requestFingerprint === null ||
    run.dispatchedAt === null ||
    run.deadlineAt === null
  ) {
    throw conflict('Consumed confirmation target is not dispatch-ready.');
  }
  return {
    protocol_version: '1.0',
    project_id: run.projectId,
    task_id: run.taskId,
    origin_request_id: run.originRequestId,
    request_fingerprint: run.requestFingerprint,
    agent_type: run.agentType,
    provider: run.provider,
    model: run.model,
    purpose: run.purpose,
    instructions: run.instructions,
    deployment_class: run.deploymentClass,
    provider_data_profile_version: run.providerDataProfileVersion,
    context_set_hash: run.contextSetHash,
    context_item_count: context.length,
    max_context_sensitivity: maximumSensitivity(
      context.map((item) => item.sensitivityLevel),
    ),
    dispatched_at: timestamp(run.dispatchedAt),
    deadline_at: timestamp(run.deadlineAt),
  };
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function notFound(confirmationId: string): DirectorProtocolError {
  return new DirectorProtocolError(
    404,
    'not_found',
    'The confirmation was not found.',
    false,
    { resource: 'confirmation', id: confirmationId },
  );
}

function projectNotFound(projectId: string): DirectorProtocolError {
  return new DirectorProtocolError(
    404,
    'not_found',
    'The project was not found.',
    false,
    { resource: 'project', id: projectId },
  );
}

function conflict(message: string): DirectorProtocolError {
  return new DirectorProtocolError(409, 'conflict', message);
}
