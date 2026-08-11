import { maximumSensitivity, sensitivityRank } from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import type {
  ContextDescriptor,
  ContextGrant,
  ContextGrantRequest,
  DirectorRepository,
  EventApplyOutcome,
  EventPreflightOutcome,
  SqlDatabase,
  SqlQueryable,
  StagedAgentResult,
} from './ports.js';
import type {
  AgentRunCompletedEvent,
  AgentRunFailedEvent,
  AgentRunStartedEvent,
  GatewayEvent,
  SensitivityLevel,
} from './protocol.js';

interface CapabilityRunRow {
  capabilityId: string;
  agentRunId: string;
  projectId: string;
  servicePrincipalId: string;
  allowedActions: string[];
  capabilityContextHash: string;
  expiresAt: string;
  usedAt: string | null;
  revokedAt: string | null;
  runStatus: string;
  requestFingerprint: string | null;
  runContextHash: string | null;
  deadlineAt: string | null;
  deploymentClass: 'internal' | 'external';
  provider: string;
  model: string | null;
  providerDataProfileVersion: string | null;
}

interface ServicePrincipalRow {
  code: string;
  status: string;
}

interface ProjectRow {
  status: string;
}

interface PolicyRow {
  externalAiEnabled: boolean;
  allowedProviderIds: string[];
  profileVersions: unknown;
  maxExternalSensitivity: SensitivityLevel;
}

interface ContextRow {
  position: number;
  memoryObjectId: string;
  documentVersionId: string;
  storageUri: string;
  fileName: string;
  mediaType: string;
  sizeBytes: number | string;
  contentHash: string;
  sensitivityLevel: SensitivityLevel;
  currentSensitivityLevel: SensitivityLevel;
  accessReason: string;
}

interface ResourceRow {
  memoryObjectId: string;
  documentVersionId: string;
}

interface AgentRunRow {
  id: string;
  taskId: string;
  projectId: string;
  status: string;
  provider: string;
  model: string | null;
  contextSetHash: string;
  originRequestId: string;
  requestFingerprint: string;
  dispatchedAt: string;
  startedAt: string | null;
}

interface EventReservationRow {
  id: string;
}

interface ExistingEventRow {
  eventHash: string | null;
  projectId: string | null;
  targetId: string | null;
  action: string;
}

interface GatewayPrincipalRow {
  id: string;
}

interface SensitivityRow {
  sensitivityLevel: SensitivityLevel;
}

export class PostgresDirectorRepository implements DirectorRepository {
  constructor(private readonly database: SqlDatabase) {}

  async inspectContextGrant(request: ContextGrantRequest): Promise<ContextGrant> {
    return this.database.transaction((transaction) =>
      this.loadContextGrant(transaction, request, false),
    );
  }

  async consumeContextGrant(
    request: ContextGrantRequest,
    expectedCapabilityId: string,
  ): Promise<ContextGrant> {
    return this.database.transaction(async (transaction) => {
      const grant = await this.loadContextGrant(transaction, request, true);
      if (grant.capabilityId !== expectedCapabilityId) {
        throw capabilityInvalid();
      }
      const consumed = await transaction.query<{ id: string }>(
        `
          UPDATE dirizhor.agent_capabilities
          SET used_at = GREATEST($2::timestamptz, clock_timestamp())
          WHERE id = $1::uuid
            AND used_at IS NULL
            AND revoked_at IS NULL
            AND expires_at > GREATEST($2::timestamptz, clock_timestamp())
          RETURNING id::text AS id
        `,
        [grant.capabilityId, request.now],
      );
      if (consumed.rowCount !== 1) {
        const expiry = await transaction.query<{ expired: boolean }>(
          `
            SELECT expires_at <= clock_timestamp() AS expired
            FROM dirizhor.agent_capabilities
            WHERE id = $1::uuid
          `,
          [grant.capabilityId],
        );
        if (expiry.rows[0]?.expired === true) {
          throw new DirectorProtocolError(410, 'capability_expired', 'Capability has expired.');
        }
        throw capabilityInvalid();
      }
      await transaction.query(
        `
          INSERT INTO dirizhor.audit_events (
            actor_type,
            actor_id,
            action,
            target_type,
            target_id,
            project_id,
            metadata,
            request_id
          )
          VALUES (
            'service',
            $1::uuid,
            'agent_context.redeemed',
            'agent_run',
            $2::uuid,
            $3::uuid,
            $4::jsonb,
            $5::uuid
          )
        `,
        [
          grant.servicePrincipalId,
          grant.agentRunId,
          grant.projectId,
          JSON.stringify({
            capability_id: grant.capabilityId,
            context_set_hash: grant.contextSetHash,
            item_count: grant.contexts.length,
            max_sensitivity_level: maximumSensitivity(
              grant.contexts.map((context) => context.sensitivityLevel),
            ),
          }),
          request.requestId,
        ],
      );
      return grant;
    });
  }

  async applyGatewayEvent(
    event: GatewayEvent,
    stagedResult: StagedAgentResult | undefined,
  ): Promise<EventApplyOutcome> {
    return this.database.transaction(async (transaction) => {
      const run = await this.loadAgentRun(transaction, event.agent_run_id, true);
      const gatewayPrincipalId = await this.loadGatewayPrincipal(transaction);
      const metadata = eventAuditMetadata(event);
      const reservation = await transaction.query<EventReservationRow>(
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
            request_id
          )
          VALUES (
            $1::uuid,
            'service',
            $2::uuid,
            $3,
            'agent_run',
            $4::uuid,
            $5::uuid,
            $6::jsonb,
            $7::uuid
          )
          ON CONFLICT (id) DO NOTHING
          RETURNING id::text AS id
        `,
        [
          event.event_id,
          gatewayPrincipalId,
          event.event_type,
          run.id,
          run.projectId,
          JSON.stringify(metadata),
          event.origin_request_id,
        ],
      );

      if (reservation.rowCount === 0) {
        const row = await this.loadExistingEvent(transaction, event.event_id);
        if (this.existingEventOutcome(row, run, event) === 'duplicate') {
          return 'duplicate';
        }
        await transaction.query(
          `
            INSERT INTO dirizhor.audit_events (
              actor_type,
              actor_id,
              action,
              target_type,
              target_id,
              project_id,
              metadata,
              request_id
            )
            VALUES (
              'service',
              $1::uuid,
              'agent_gateway.event_conflict',
              'agent_run',
              $2::uuid,
              $3::uuid,
              $4::jsonb,
              $5::uuid
            )
          `,
          [
            gatewayPrincipalId,
            run.id,
            run.projectId,
            JSON.stringify({
              existing_event_id: event.event_id,
              existing_event_hash: row?.eventHash ?? null,
              existing_action: row?.action ?? null,
              incoming_event_hash: event.event_hash,
            }),
            event.origin_request_id,
          ],
        );
        return 'conflict';
      }

      this.validateEventIdentity(run, event);
      await this.validateEventState(transaction, run, event, stagedResult, true);
      switch (event.event_type) {
        case 'agent_run.started':
          await this.applyStarted(transaction, run, event);
          break;
        case 'agent_run.completed':
          await this.applyCompleted(transaction, run, event, stagedResult);
          break;
        case 'agent_run.failed':
          await this.applyFailed(transaction, run, event);
          break;
        case 'agent_run.cancelled':
          await this.applyCancelled(transaction, run, event);
          break;
      }
      return 'applied';
    });
  }

  async preflightGatewayEvent(event: GatewayEvent): Promise<EventPreflightOutcome> {
    return this.database.transaction(async (transaction) => {
      const run = await this.loadAgentRun(transaction, event.agent_run_id, false);
      const existing = await this.loadExistingEvent(transaction, event.event_id);
      const existingOutcome = this.existingEventOutcome(existing, run, event);
      if (existingOutcome !== 'new') {
        return existingOutcome;
      }
      this.validateEventIdentity(run, event);
      await this.validateEventState(transaction, run, event, undefined, false);
      return 'new';
    });
  }

  private async loadContextGrant(
    transaction: SqlQueryable,
    request: ContextGrantRequest,
    lock: boolean,
  ): Promise<ContextGrant> {
    const header = await transaction.query<CapabilityRunRow>(
      `
        SELECT
          capability.id::text AS "capabilityId",
          capability.agent_run_id::text AS "agentRunId",
          capability.project_id::text AS "projectId",
          capability.issued_to_service_principal_id::text AS "servicePrincipalId",
          capability.allowed_actions AS "allowedActions",
          capability.context_set_hash AS "capabilityContextHash",
          capability.expires_at::text AS "expiresAt",
          capability.used_at::text AS "usedAt",
          capability.revoked_at::text AS "revokedAt",
          run.status AS "runStatus",
          run.request_fingerprint AS "requestFingerprint",
          run.context_set_hash AS "runContextHash",
          run.deadline_at::text AS "deadlineAt",
          run.deployment_class AS "deploymentClass",
          run.provider,
          run.model,
          run.provider_data_profile_version AS "providerDataProfileVersion"
        FROM dirizhor.agent_capabilities AS capability
        JOIN dirizhor.agent_runs AS run
          ON run.id = capability.agent_run_id
         AND run.project_id = capability.project_id
        WHERE capability.token_hash = $1
          AND capability.agent_run_id = $2::uuid
        ${lock ? 'FOR UPDATE OF capability, run' : ''}
      `,
      [request.tokenHash, request.agentRunId],
    );
    const row = header.rows[0];
    if (row === undefined) {
      throw capabilityInvalid();
    }

    const service = await transaction.query<ServicePrincipalRow>(
      `
        SELECT code, status
        FROM dirizhor.service_principals
        WHERE id = $1::uuid
        ${lock ? 'FOR SHARE' : ''}
      `,
      [row.servicePrincipalId],
    );
    const project = await transaction.query<ProjectRow>(
      `
        SELECT status
        FROM dirizhor.projects
        WHERE id = $1::uuid
        ${lock ? 'FOR SHARE' : ''}
      `,
      [row.projectId],
    );
    const policy = await transaction.query<PolicyRow>(
      `
        SELECT
          external_ai_enabled AS "externalAiEnabled",
          allowed_provider_ids AS "allowedProviderIds",
          provider_data_profile_versions AS "profileVersions",
          max_external_sensitivity_level AS "maxExternalSensitivity"
        FROM dirizhor.project_ai_policies
        WHERE project_id = $1::uuid
        ${lock ? 'FOR SHARE' : ''}
      `,
      [row.projectId],
    );
    const contexts = await transaction.query<ContextRow>(
      `
        SELECT
          context.position,
          context.memory_object_id::text AS "memoryObjectId",
          context.document_version_id::text AS "documentVersionId",
          version.storage_uri AS "storageUri",
          version.file_name AS "fileName",
          version.file_type AS "mediaType",
          version.size_bytes AS "sizeBytes",
          version.content_hash AS "contentHash",
          context.sensitivity_level AS "sensitivityLevel",
          object.sensitivity_level AS "currentSensitivityLevel",
          context.access_reason AS "accessReason"
        FROM dirizhor.agent_run_contexts AS context
        JOIN dirizhor.document_versions AS version
          ON version.id = context.document_version_id
         AND version.memory_object_id = context.memory_object_id
        JOIN dirizhor.memory_objects AS object
          ON object.id = context.memory_object_id
         AND object.project_id = context.project_id
        WHERE context.agent_run_id = $1::uuid
          AND context.project_id = $2::uuid
        ORDER BY context.position
        ${lock ? 'FOR SHARE OF context, version, object' : ''}
      `,
      [row.agentRunId, row.projectId],
    );
    const resources = await transaction.query<ResourceRow>(
      `
        SELECT
          memory_object_id::text AS "memoryObjectId",
          document_version_id::text AS "documentVersionId"
        FROM dirizhor.agent_capability_resources
        WHERE agent_capability_id = $1::uuid
          AND project_id = $2::uuid
        ORDER BY memory_object_id, document_version_id
        ${lock ? 'FOR SHARE' : ''}
      `,
      [row.capabilityId, row.projectId],
    );

    const descriptors = contexts.rows.map(contextDescriptor);
    this.validateGrant(row, service.rows[0], project.rows[0], policy.rows[0], descriptors, resources.rows, request);
    return {
      capabilityId: row.capabilityId,
      servicePrincipalId: row.servicePrincipalId,
      agentRunId: row.agentRunId,
      projectId: row.projectId,
      requestFingerprint: row.requestFingerprint!,
      contextSetHash: row.runContextHash!,
      expiresAt: row.expiresAt,
      contexts: descriptors,
    };
  }

  private validateGrant(
    row: CapabilityRunRow,
    service: ServicePrincipalRow | undefined,
    project: ProjectRow | undefined,
    policy: PolicyRow | undefined,
    contexts: readonly ContextDescriptor[],
    resources: readonly ResourceRow[],
    request: ContextGrantRequest,
  ): void {
    if (row.usedAt !== null) {
      throw new DirectorProtocolError(409, 'capability_used', 'Capability was already used.');
    }
    if (row.revokedAt !== null) {
      throw capabilityInvalid();
    }
    const now = Date.parse(request.now);
    if (Date.parse(row.expiresAt) <= now || Date.parse(row.deadlineAt ?? '') <= now) {
      throw new DirectorProtocolError(410, 'capability_expired', 'Capability has expired.');
    }
    if (
      service?.code !== 'agent-gateway' ||
      service.status !== 'active' ||
      project?.status !== 'active' ||
      row.allowedActions.length !== 1 ||
      row.allowedActions[0] !== 'context_bundle.read'
    ) {
      throw capabilityInvalid();
    }
    if (row.runStatus !== 'queued') {
      throw new DirectorProtocolError(409, 'invalid_state', 'Agent run is not queued.');
    }
    if (
      row.agentRunId !== request.agentRunId ||
      row.requestFingerprint !== request.requestFingerprint ||
      row.runContextHash !== request.contextSetHash ||
      row.capabilityContextHash !== request.contextSetHash
    ) {
      throw capabilityInvalid();
    }
    if (contexts.length === 0 || contexts.some((context, index) => context.position !== index + 1)) {
      throw new DirectorProtocolError(
        422,
        'context_hash_mismatch',
        'Frozen context positions are invalid.',
      );
    }
    if (
      contexts.some(
        (context) =>
          sensitivityRank(context.currentSensitivityLevel) >
          sensitivityRank(context.sensitivityLevel),
      )
    ) {
      throw new DirectorProtocolError(
        403,
        'access_denied',
        'Current context sensitivity exceeds the frozen grant.',
      );
    }
    const expectedResources = contexts
      .map((context) => `${context.memoryObjectId}:${context.documentVersionId}`)
      .sort();
    const actualResources = resources
      .map((resource) => `${resource.memoryObjectId}:${resource.documentVersionId}`)
      .sort();
    if (
      expectedResources.length !== actualResources.length ||
      expectedResources.some((value, index) => value !== actualResources[index])
    ) {
      throw capabilityInvalid();
    }
    if (row.deploymentClass === 'external') {
      this.validateExternalPolicy(row, policy, maximumSensitivity(contexts.map((item) => item.sensitivityLevel)));
    }
  }

  private validateExternalPolicy(
    row: CapabilityRunRow,
    policy: PolicyRow | undefined,
    maximumContextSensitivity: SensitivityLevel,
  ): void {
    const profiles = isRecord(policy?.profileVersions) ? policy.profileVersions : {};
    if (
      policy === undefined ||
      !policy.externalAiEnabled ||
      !policy.allowedProviderIds.includes(row.provider) ||
      profiles[row.provider] !== row.providerDataProfileVersion ||
      sensitivityRank(maximumContextSensitivity) >
        sensitivityRank(policy.maxExternalSensitivity)
    ) {
      throw new DirectorProtocolError(
        403,
        'policy_violation',
        'Current project policy does not allow this external execution.',
      );
    }
  }

  private async loadAgentRun(
    transaction: SqlQueryable,
    agentRunId: string,
    lock: boolean,
  ): Promise<AgentRunRow> {
    const result = await transaction.query<AgentRunRow>(
      `
        SELECT
          id::text AS id,
          task_id::text AS "taskId",
          project_id::text AS "projectId",
          status,
          provider,
          model,
          context_set_hash AS "contextSetHash",
          origin_request_id::text AS "originRequestId",
          request_fingerprint AS "requestFingerprint",
          dispatched_at::text AS "dispatchedAt",
          started_at::text AS "startedAt"
        FROM dirizhor.agent_runs
        WHERE id = $1::uuid
        ${lock ? 'FOR UPDATE' : ''}
      `,
      [agentRunId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new DirectorProtocolError(404, 'not_found', 'Agent run was not found.');
    }
    return row;
  }

  private async loadExistingEvent(
    transaction: SqlQueryable,
    eventId: string,
  ): Promise<ExistingEventRow | undefined> {
    const existing = await transaction.query<ExistingEventRow>(
      `
        SELECT
          metadata ->> 'event_hash' AS "eventHash",
          project_id::text AS "projectId",
          target_id::text AS "targetId",
          action
        FROM dirizhor.audit_events
        WHERE id = $1::uuid
      `,
      [eventId],
    );
    return existing.rows[0];
  }

  private existingEventOutcome(
    existing: ExistingEventRow | undefined,
    run: AgentRunRow,
    event: GatewayEvent,
  ): EventPreflightOutcome {
    if (existing === undefined) {
      return 'new';
    }
    return existing.eventHash === event.event_hash &&
      existing.action === event.event_type &&
      existing.targetId === run.id &&
      existing.projectId === run.projectId
      ? 'duplicate'
      : 'conflict';
  }

  private async loadGatewayPrincipal(transaction: SqlQueryable): Promise<string> {
    const result = await transaction.query<GatewayPrincipalRow>(
      `
        SELECT id::text AS id
        FROM dirizhor.service_principals
        WHERE code = 'agent-gateway' AND status = 'active'
        FOR SHARE
      `,
    );
    const id = result.rows[0]?.id;
    if (id === undefined) {
      throw new DirectorProtocolError(
        503,
        'unavailable',
        'Agent Gateway service principal is unavailable.',
        true,
      );
    }
    return id;
  }

  private validateEventIdentity(run: AgentRunRow, event: GatewayEvent): void {
    if (
      event.project_id !== run.projectId ||
      event.origin_request_id !== run.originRequestId ||
      event.request_fingerprint !== run.requestFingerprint
    ) {
      throw new DirectorProtocolError(
        409,
        'idempotency_conflict',
        'Gateway event does not match the frozen agent run.',
      );
    }
    const occurredAt = Date.parse(event.occurred_at);
    const lowerBound = Date.parse(run.startedAt ?? run.dispatchedAt);
    if (!Number.isFinite(occurredAt) || occurredAt < lowerBound) {
      throw new DirectorProtocolError(422, 'invalid_state', 'Gateway event time is invalid.');
    }
  }

  private async validateEventState(
    transaction: SqlQueryable,
    run: AgentRunRow,
    event: GatewayEvent,
    stagedResult: StagedAgentResult | undefined,
    requireStagedResult: boolean,
  ): Promise<void> {
    switch (event.event_type) {
      case 'agent_run.started':
        if (
          run.status !== 'queued' ||
          event.provider !== run.provider ||
          (event.model ?? null) !== run.model ||
          event.context_set_hash !== run.contextSetHash
        ) {
          throw invalidEventOrder();
        }
        break;
      case 'agent_run.completed': {
        if (
          run.status !== 'running' ||
          event.provider !== run.provider ||
          (event.model ?? null) !== run.model ||
          (requireStagedResult && stagedResult === undefined)
        ) {
          throw invalidEventOrder();
        }
        const sensitivity = await this.maximumRunSensitivity(transaction, run.id);
        if (event.result.sensitivity_level !== sensitivity) {
          throw new DirectorProtocolError(
            422,
            'context_hash_mismatch',
            'Result sensitivity does not match the frozen context.',
          );
        }
        break;
      }
      case 'agent_run.failed': {
        const directFailureAllowed =
          run.status === 'queued' && ['admission', 'context'].includes(event.failure.phase);
        if (
          !(directFailureAllowed || run.status === 'running') ||
          (event.provider ?? run.provider) !== run.provider ||
          (event.model ?? run.model) !== run.model
        ) {
          throw invalidEventOrder();
        }
        break;
      }
      case 'agent_run.cancelled':
        if (!['queued', 'running'].includes(run.status)) {
          throw invalidEventOrder();
        }
        break;
    }
  }

  private async applyStarted(
    transaction: SqlQueryable,
    run: AgentRunRow,
    event: AgentRunStartedEvent,
  ): Promise<void> {
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'running', started_at = $2::timestamptz
        WHERE id = $1::uuid
      `,
      [run.id, event.occurred_at],
    );
  }

  private async applyCompleted(
    transaction: SqlQueryable,
    run: AgentRunRow,
    event: AgentRunCompletedEvent,
    stagedResult: StagedAgentResult | undefined,
  ): Promise<void> {
    if (stagedResult === undefined) {
      throw invalidEventOrder();
    }
    await transaction.query(
      `
        INSERT INTO dirizhor.agent_run_results (
          agent_run_id,
          project_id,
          output_storage_uri,
          content_hash,
          size_bytes,
          file_type,
          output_summary,
          sensitivity_level,
          expires_at
        )
        VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9::timestamptz)
      `,
      [
        run.id,
        run.projectId,
        stagedResult.storageUri,
        event.result.content_hash,
        event.result.size_bytes,
        event.result.content_type,
        event.result.output_summary ?? null,
        event.result.sensitivity_level,
        stagedResult.expiresAt,
      ],
    );
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET
          status = 'completed',
          output_summary = $2,
          finished_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [run.id, event.result.output_summary ?? null, event.occurred_at],
    );
    await transaction.query(
      `UPDATE dirizhor.tasks SET status = 'reviewing' WHERE id = $1::uuid`,
      [run.taskId],
    );
  }

  private async applyFailed(
    transaction: SqlQueryable,
    run: AgentRunRow,
    event: AgentRunFailedEvent,
  ): Promise<void> {
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'failed', error_message = $2, finished_at = $3::timestamptz
        WHERE id = $1::uuid
      `,
      [run.id, event.failure.message, event.occurred_at],
    );
    await transaction.query(
      `UPDATE dirizhor.tasks SET status = 'failed' WHERE id = $1::uuid`,
      [run.taskId],
    );
  }

  private async applyCancelled(
    transaction: SqlQueryable,
    run: AgentRunRow,
    event: GatewayEvent & { event_type: 'agent_run.cancelled' },
  ): Promise<void> {
    await transaction.query(
      `
        UPDATE dirizhor.agent_runs
        SET status = 'cancelled', finished_at = $2::timestamptz
        WHERE id = $1::uuid
      `,
      [run.id, event.occurred_at],
    );
    await transaction.query(
      `UPDATE dirizhor.tasks SET status = 'cancelled' WHERE id = $1::uuid`,
      [run.taskId],
    );
  }

  private async maximumRunSensitivity(
    transaction: SqlQueryable,
    agentRunId: string,
  ): Promise<SensitivityLevel> {
    const result = await transaction.query<SensitivityRow>(
      `
        SELECT sensitivity_level AS "sensitivityLevel"
        FROM dirizhor.agent_run_contexts
        WHERE agent_run_id = $1::uuid
        ORDER BY dirizhor.sensitivity_rank(sensitivity_level) DESC
        LIMIT 1
      `,
      [agentRunId],
    );
    const sensitivity = result.rows[0]?.sensitivityLevel;
    if (sensitivity === undefined) {
      throw new DirectorProtocolError(
        422,
        'context_hash_mismatch',
        'Agent run has no frozen context.',
      );
    }
    return sensitivity;
  }
}

function contextDescriptor(row: ContextRow): ContextDescriptor {
  const sizeBytes = typeof row.sizeBytes === 'string' ? Number(row.sizeBytes) : row.sizeBytes;
  if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 0) {
    throw new DirectorProtocolError(
      422,
      'context_hash_mismatch',
      'Context size is outside the supported range.',
    );
  }
  return {
    position: row.position,
    memoryObjectId: row.memoryObjectId,
    documentVersionId: row.documentVersionId,
    storageUri: row.storageUri,
    fileName: row.fileName,
    mediaType: row.mediaType,
    sizeBytes,
    contentHash: row.contentHash,
    sensitivityLevel: row.sensitivityLevel,
    currentSensitivityLevel: row.currentSensitivityLevel,
    accessReason: row.accessReason,
  };
}

function capabilityInvalid(): DirectorProtocolError {
  return new DirectorProtocolError(403, 'capability_invalid', 'Capability is invalid.');
}

function invalidEventOrder(): DirectorProtocolError {
  return new DirectorProtocolError(409, 'invalid_state', 'Gateway event is out of order.');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function eventAuditMetadata(event: GatewayEvent): Record<string, unknown> {
  const metadata: Record<string, unknown> = {
    protocol_version: event.protocol_version,
    event_hash: event.event_hash,
    request_fingerprint: event.request_fingerprint,
  };
  switch (event.event_type) {
    case 'agent_run.started':
      return {
        ...metadata,
        provider: event.provider,
        model: event.model ?? null,
        adapter_version: event.adapter_version,
        context_set_hash: event.context_set_hash,
      };
    case 'agent_run.completed':
      return {
        ...metadata,
        provider: event.provider,
        model: event.model ?? null,
        adapter_version: event.adapter_version,
        provider_request_id: event.provider_request_id,
        content_hash: event.result.content_hash,
        size_bytes: event.result.size_bytes,
        sensitivity_level: event.result.sensitivity_level,
        finish_reason: event.result.finish_reason,
        usage: event.result.usage ?? null,
      };
    case 'agent_run.failed':
      return {
        ...metadata,
        provider: event.provider ?? null,
        model: event.model ?? null,
        adapter_version: event.adapter_version,
        provider_request_id: event.provider_request_id,
        failure_code: event.failure.code,
        failure_phase: event.failure.phase,
        retryable: event.failure.retryable,
        provider_status: event.failure.provider_status ?? null,
      };
    case 'agent_run.cancelled':
      return {
        ...metadata,
        reason_code: event.reason_code,
        provider_request_id: event.provider_request_id,
      };
  }
}
