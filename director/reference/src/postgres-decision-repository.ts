import type {
  RelationshipEndpointType,
  RelationshipRef,
  RelationshipType,
} from './agent-result-protocol.js';
import { ConcealedAuthorizationDeniedError } from './authorization-audit.js';
import {
  insertAllowedAccessAudit,
  insertAllowAuthorizationDecision,
} from './authorization-decision.js';
import type {
  CreateDecisionCommand,
  DecisionRepository,
  NormalizedDecisionCreate,
} from './decision-ports.js';
import type {
  Decision,
  DecisionAuditEvent,
  DecisionProvenance,
  DecisionProvenanceAgentRun,
  DecisionRelatedMemoryObject,
  DecisionRelationship,
  DecisionSourceVersion,
  DecisionStatus,
} from './decision-protocol.js';
import { DirectorProtocolError } from './errors.js';
import type { MemoryObjectType } from './public-protocol.js';
import type {
  DeploymentClass,
  SensitivityLevel,
} from './protocol.js';
import type { SqlDatabase, SqlQueryable } from './ports.js';
import type { AgentRunStatus } from './task-protocol.js';

const createPermissions = ['project.read', 'decision.create'] as const;
const readPermissions = ['project.read', 'decision.read', 'memory_object.read'] as const;

interface StatusRow {
  status: string;
}

interface PermissionRow {
  code: string;
}

interface DecisionIdentityRow {
  projectId: string;
  memoryObjectId: string;
  sensitivityLevel: SensitivityLevel;
}

interface DecisionRow extends DecisionIdentityRow {
  id: string;
  topicId: string | null;
  title: string;
  decisionText: string;
  rationale: string | null;
  status: DecisionStatus;
  supersedesDecisionId: string | null;
  decidedByUserId: string | null;
  decidedAt: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

interface RelationshipRow {
  id: string;
  sourceType: RelationshipEndpointType;
  sourceId: string;
  targetType: RelationshipEndpointType;
  targetId: string;
  relationType: RelationshipType;
  description: string | null;
  createdByUserId: string;
  createdAt: Date | string;
}

interface MemoryTargetRow {
  id: string;
  type: MemoryObjectType;
  title: string;
  status: string;
  currentVersionId: string | null;
  sensitivityLevel: SensitivityLevel;
}

interface RunRow {
  id: string;
  taskId: string;
  agentType: string;
  provider: string;
  model: string | null;
  status: AgentRunStatus;
  deploymentClass: DeploymentClass;
  contextSetHash: string | null;
  resultMemoryObjectId: string | null;
  requestedByUserId: string;
  originRequestId: string;
  createdAt: Date | string;
  dispatchedAt: Date | string | null;
  startedAt: Date | string | null;
  finishedAt: Date | string | null;
}

interface SourceVersionRow {
  agentRunId: string;
  position: number;
  memoryObjectId: string;
  memoryObjectTitle: string;
  documentVersionId: string;
  versionNumber: number;
  fileName: string;
  fileType: string;
  contentHash: string;
  sizeBytes: number | string;
  accessReason: string;
  frozenSensitivityLevel: SensitivityLevel;
  currentSensitivityLevel: SensitivityLevel;
}

interface AuditRow {
  id: string;
  actorType: string;
  actorId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  requestId: string;
  createdAt: Date | string;
}

export class PostgresDecisionRepository implements DecisionRepository {
  constructor(private readonly database: SqlDatabase) {}

  async createDecision(command: CreateDecisionCommand): Promise<Decision> {
    try {
      return await this.database.transaction(async (transaction) => {
        await this.requireActiveUser(transaction, command.userId, true);
        const permissions = await this.projectPermissions(
          transaction,
          command.userId,
          command.input.project_id,
          true,
          false,
        );
        this.requirePermissions(permissions, createPermissions, {
          concealedPermission: 'project.read',
          concealedResource: ['project', command.input.project_id],
        });
        await this.validateReferences(
          transaction,
          permissions,
          command.input.project_id,
          command.input.topic_id,
          command.input.relationships,
          true,
        );
        const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
          principalUserId: command.userId,
          action: 'decision.create',
          resourceType: 'project',
          resourceId: command.input.project_id,
          projectId: command.input.project_id,
          requestId: command.requestId,
        });
        await this.insertDecision(transaction, command);
        await this.insertRelationships(transaction, command);
        await transaction.query(
          `
            INSERT INTO dirizhor.audit_events (
              id, actor_type, actor_id, action, target_type, target_id,
              project_id, metadata, request_id, authorization_decision_id
            )
            VALUES (
              $1::uuid, 'user', $2::uuid, 'decision.created', 'decision', $3::uuid,
              $4::uuid, $5::jsonb, $1::uuid, $6::uuid
            )
          `,
          [
            command.requestId,
            command.userId,
            command.decisionId,
            command.input.project_id,
            JSON.stringify({
              memory_object_id: command.memoryObjectId,
              status: command.input.status,
              sensitivity_level: command.input.sensitivity_level,
              relationship_count: command.input.relationships.length,
            }),
            authorizationDecisionId,
          ],
        );
        return this.loadDecision(transaction, command.decisionId);
      });
    } catch (error) {
      if (sqlState(error) !== '23505') {
        throw error;
      }
      const existing = await this.loadAuthorizedDecisionByRequest(command);
      if (existing !== undefined) {
        return existing;
      }
      throw conflict('Decision creation conflicts with an existing resource.');
    }
  }

  async getDecision(userId: string, requestId: string, decisionId: string): Promise<Decision> {
    return this.database.transaction(async (transaction) => {
      const { identity, permissions } = await this.authorizeDecisionRead(
        transaction,
        userId,
        decisionId,
      );
      const decision = await this.loadDecision(transaction, decisionId);
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: userId,
        action: 'decision.read',
        resourceType: 'decision',
        resourceId: decisionId,
        projectId: identity.projectId,
        requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: userId,
        authorizedAction: 'decision.read',
        resourceType: 'decision',
        resourceId: decisionId,
        projectId: identity.projectId,
        requestId,
        authorizationDecisionId,
        metadata: {
          status: decision.status,
          sensitivity_level: identity.sensitivityLevel,
          view: 'decision',
          permission_count: permissions.size,
        },
      });
      return decision;
    });
  }

  async getDecisionProvenance(
    userId: string,
    requestId: string,
    decisionId: string,
  ): Promise<DecisionProvenance> {
    return this.database.transaction(async (transaction) => {
      const { identity, permissions } = await this.authorizeDecisionRead(
        transaction,
        userId,
        decisionId,
      );
      const decision = await this.loadDecision(transaction, decisionId);
      const relationshipRows = await this.loadDecisionRelationships(
        transaction,
        identity.projectId,
        decisionId,
        identity.memoryObjectId,
      );
      await this.validateProvenanceRelationships(
        transaction,
        permissions,
        identity,
        decisionId,
        relationshipRows,
      );
      const relatedMemoryRows = await this.loadRelatedMemoryObjects(
        transaction,
        identity.projectId,
        decisionId,
        identity.memoryObjectId,
      );
      for (const memory of relatedMemoryRows) {
        this.requireSensitivityPermission(permissions, memory.sensitivityLevel);
      }
      const runRows = await this.loadProvenanceRuns(
        transaction,
        identity.projectId,
        decisionId,
        identity.memoryObjectId,
      );
      if (runRows.length > 0) {
        this.requirePermissions(permissions, [
          'task.read',
          'agent_run.read',
          'memory_object.read',
          'document_version.read',
        ]);
      }
      const sourceRows = await this.loadSourceVersions(
        transaction,
        runRows.map((run) => run.id),
      );
      for (const source of sourceRows) {
        this.requireSensitivityPermission(permissions, source.frozenSensitivityLevel);
        this.requireSensitivityPermission(permissions, source.currentSensitivityLevel);
      }
      const auditRows = await this.loadProvenanceAudits(
        transaction,
        identity.projectId,
        decision,
        relatedMemoryRows,
        runRows,
        sourceRows,
      );
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: userId,
        action: 'decision.read',
        resourceType: 'decision',
        resourceId: decisionId,
        projectId: identity.projectId,
        requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: userId,
        authorizedAction: 'decision.read',
        resourceType: 'decision',
        resourceId: decisionId,
        projectId: identity.projectId,
        requestId,
        authorizationDecisionId,
        metadata: {
          view: 'provenance',
          relationship_count: relationshipRows.length,
          related_memory_object_count: relatedMemoryRows.length,
          agent_run_count: runRows.length,
          source_version_count: sourceRows.length,
          audit_event_count: auditRows.length,
        },
      });
      return {
        decision,
        provenance_complete: true,
        relationships: relationshipRows.map(relationshipFromRow),
        related_memory_objects: relatedMemoryRows.map(relatedMemoryFromRow),
        agent_runs: runRows.map(runFromRow),
        source_versions: sourceRows.map(sourceVersionFromRow),
        audit_events: auditRows.map(auditFromRow),
      };
    });
  }

  private async authorizeDecisionRead(
    transaction: SqlQueryable,
    userId: string,
    decisionId: string,
  ): Promise<{ identity: DecisionIdentityRow; permissions: ReadonlySet<string> }> {
    await this.requireActiveUser(transaction, userId, false);
    const identity = await this.loadDecisionIdentity(transaction, decisionId, false);
    if (identity === undefined) {
      throw notFound('decision', decisionId);
    }
    const permissions = await this.projectPermissions(
      transaction,
      userId,
      identity.projectId,
      false,
      false,
    );
    this.requirePermissions(permissions, readPermissions, {
      concealedPermission: 'project.read',
      concealedResource: ['decision', decisionId],
    });
    this.requireSensitivityPermission(permissions, identity.sensitivityLevel);
    return { identity, permissions };
  }

  private async insertDecision(
    transaction: SqlQueryable,
    command: CreateDecisionCommand,
  ): Promise<void> {
    await transaction.query(
      `
        INSERT INTO dirizhor.memory_objects (
          id, type, title, project_id, topic_id, author_user_id,
          summary, keywords, sensitivity_level
        )
        VALUES ($1::uuid, 'decision', $2, $3::uuid, $4::uuid, $5::uuid, $6, '{}', $7)
      `,
      [
        command.memoryObjectId,
        command.input.title,
        command.input.project_id,
        command.input.topic_id,
        command.userId,
        command.input.rationale,
        command.input.sensitivity_level,
      ],
    );
    await transaction.query(
      `
        INSERT INTO dirizhor.decisions (
          id, memory_object_id, project_id, topic_id, title,
          decision_text, rationale, status
        )
        VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8)
      `,
      [
        command.decisionId,
        command.memoryObjectId,
        command.input.project_id,
        command.input.topic_id,
        command.input.title,
        command.input.decision_text,
        command.input.rationale,
        command.input.status,
      ],
    );
  }

  private async insertRelationships(
    transaction: SqlQueryable,
    command: CreateDecisionCommand,
  ): Promise<void> {
    for (const relationship of command.input.relationships) {
      await transaction.query(
        `
          INSERT INTO dirizhor.relationships (
            project_id, source_type, source_id, target_type, target_id,
            relation_type, description, created_by_user_id
          )
          VALUES ($1::uuid, 'decision', $2::uuid, $3, $4::uuid, $5, $6, $7::uuid)
        `,
        [
          command.input.project_id,
          command.decisionId,
          relationship.target_type,
          relationship.target_id,
          relationship.relation_type,
          relationship.description ?? null,
          command.userId,
        ],
      );
    }
  }

  private async validateReferences(
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
      if (topic.rows[0] === undefined) {
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
      this.requirePermissions(permissions, ['memory_object.read']);
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
      this.requireSensitivityPermission(permissions, target.sensitivityLevel);
      return;
    }
    if (targetType === 'decision') {
      this.requirePermissions(permissions, ['decision.read', 'memory_object.read']);
      const target = await this.loadDecisionIdentity(transaction, targetId, lock, projectId);
      if (target === undefined) {
        throw notFound('relationship_target', targetId);
      }
      this.requireSensitivityPermission(permissions, target.sensitivityLevel);
      return;
    }
    const requiredPermission = targetType === 'task' ? 'task.read' : 'agent_run.read';
    this.requirePermissions(permissions, [requiredPermission]);
    const target = await transaction.query<{ id: string }>(
      `
        SELECT id::text AS id FROM dirizhor.${relationshipTable(targetType)}
        WHERE id = $1::uuid AND project_id = $2::uuid
        ${lock ? 'FOR SHARE' : ''}
      `,
      [targetId, projectId],
    );
    if (target.rows[0] === undefined) {
      throw notFound('relationship_target', targetId);
    }
  }

  private async validateProvenanceRelationships(
    transaction: SqlQueryable,
    permissions: ReadonlySet<string>,
    identity: DecisionIdentityRow,
    decisionId: string,
    relationships: readonly RelationshipRow[],
  ): Promise<void> {
    for (const relationship of relationships) {
      const endpoint =
        (relationship.sourceType === 'decision' && relationship.sourceId === decisionId) ||
        (relationship.sourceType === 'memory_object' &&
          relationship.sourceId === identity.memoryObjectId)
          ? { type: relationship.targetType, id: relationship.targetId }
          : { type: relationship.sourceType, id: relationship.sourceId };
      await this.validateRelationshipTarget(
        transaction,
        permissions,
        identity.projectId,
        endpoint.type,
        endpoint.id,
        false,
      );
    }
  }

  private async loadAuthorizedDecisionByRequest(
    command: CreateDecisionCommand,
  ): Promise<Decision | undefined> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, command.userId, false);
      const permissions = await this.projectPermissions(
        transaction,
        command.userId,
        command.input.project_id,
        false,
        false,
      );
      this.requirePermissions(permissions, createPermissions, {
        concealedPermission: 'project.read',
        concealedResource: ['project', command.input.project_id],
      });
      const result = await transaction.query<{ decisionId: string }>(
        `
          SELECT target_id::text AS "decisionId"
          FROM dirizhor.audit_events
          WHERE id = $1::uuid
            AND request_id = $1::uuid
            AND actor_type = 'user'
            AND actor_id = $2::uuid
            AND action = 'decision.created'
            AND target_type = 'decision'
            AND project_id = $3::uuid
        `,
        [command.requestId, command.userId, command.input.project_id],
      );
      const decisionId = result.rows[0]?.decisionId;
      if (decisionId === undefined) {
        return undefined;
      }
      const decision = await this.loadDecision(transaction, decisionId);
      const relationships = await this.loadOutgoingRelationships(transaction, decisionId);
      return matchesCreate(decision, relationships, command.input) ? decision : undefined;
    });
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
    conceal?: {
      concealedPermission: string;
      concealedResource: readonly [string, string];
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

  private requireSensitivityPermission(
    permissions: ReadonlySet<string>,
    sensitivityLevel: SensitivityLevel,
  ): void {
    const required = sensitivityPermission(sensitivityLevel);
    if (required !== null) {
      this.requirePermissions(permissions, [required]);
    }
  }

  private async loadDecisionIdentity(
    transaction: SqlQueryable,
    decisionId: string,
    lock: boolean,
    projectId?: string,
  ): Promise<DecisionIdentityRow | undefined> {
    const result = await transaction.query<DecisionIdentityRow>(
      `
        SELECT
          decision.project_id::text AS "projectId",
          decision.memory_object_id::text AS "memoryObjectId",
          memory.sensitivity_level AS "sensitivityLevel"
        FROM dirizhor.decisions AS decision
        JOIN dirizhor.memory_objects AS memory
          ON memory.id = decision.memory_object_id
         AND memory.project_id = decision.project_id
        WHERE decision.id = $1::uuid
          AND ($2::uuid IS NULL OR decision.project_id = $2::uuid)
        ${lock ? 'FOR SHARE OF decision, memory' : ''}
      `,
      [decisionId, projectId ?? null],
    );
    return result.rows[0];
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
        SELECT
          memory.id::text AS id,
          memory.type,
          memory.title,
          memory.status,
          memory.current_version_id::text AS "currentVersionId",
          memory.sensitivity_level AS "sensitivityLevel"
        FROM ${from}
        WHERE ${idColumn} = $1::uuid AND memory.project_id = $2::uuid
        ${lock ? 'FOR SHARE OF memory' : ''}
      `,
      [targetId, projectId],
    );
    return result.rows[0];
  }

  private async loadDecision(
    transaction: SqlQueryable,
    decisionId: string,
  ): Promise<Decision> {
    const result = await transaction.query<DecisionRow>(
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
          decision.decided_by_user_id::text AS "decidedByUserId",
          decision.decided_at AS "decidedAt",
          memory.sensitivity_level AS "sensitivityLevel",
          decision.created_at AS "createdAt",
          decision.updated_at AS "updatedAt"
        FROM dirizhor.decisions AS decision
        JOIN dirizhor.memory_objects AS memory
          ON memory.id = decision.memory_object_id
         AND memory.project_id = decision.project_id
        WHERE decision.id = $1::uuid
      `,
      [decisionId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw notFound('decision', decisionId);
    }
    return decisionFromRow(row);
  }

  private async loadOutgoingRelationships(
    transaction: SqlQueryable,
    decisionId: string,
  ): Promise<RelationshipRow[]> {
    const result = await transaction.query<RelationshipRow>(
      `${relationshipSelect}
       WHERE relationship.source_type = 'decision'
         AND relationship.source_id = $1::uuid
       ORDER BY relationship.target_type, relationship.target_id, relationship.relation_type`,
      [decisionId],
    );
    return result.rows;
  }

  private async loadDecisionRelationships(
    transaction: SqlQueryable,
    projectId: string,
    decisionId: string,
    memoryObjectId: string,
  ): Promise<RelationshipRow[]> {
    const result = await transaction.query<RelationshipRow>(
      `${relationshipSelect}
       WHERE relationship.project_id = $1::uuid
         AND (
           (relationship.source_type = 'decision' AND relationship.source_id = $2::uuid)
           OR (relationship.target_type = 'decision' AND relationship.target_id = $2::uuid)
           OR (relationship.source_type = 'memory_object' AND relationship.source_id = $3::uuid)
           OR (relationship.target_type = 'memory_object' AND relationship.target_id = $3::uuid)
         )
       ORDER BY relationship.created_at, relationship.id`,
      [projectId, decisionId, memoryObjectId],
    );
    return result.rows;
  }

  private async loadRelatedMemoryObjects(
    transaction: SqlQueryable,
    projectId: string,
    decisionId: string,
    memoryObjectId: string,
  ): Promise<MemoryTargetRow[]> {
    const result = await transaction.query<MemoryTargetRow>(
      `
        WITH related_endpoints AS (
          SELECT
            CASE
              WHEN (source_type = 'decision' AND source_id = $2::uuid)
                OR (source_type = 'memory_object' AND source_id = $3::uuid)
                THEN target_type
              ELSE source_type
            END AS endpoint_type,
            CASE
              WHEN (source_type = 'decision' AND source_id = $2::uuid)
                OR (source_type = 'memory_object' AND source_id = $3::uuid)
                THEN target_id
              ELSE source_id
            END AS endpoint_id
          FROM dirizhor.relationships
          WHERE project_id = $1::uuid
            AND (
              (source_type = 'decision' AND source_id = $2::uuid)
              OR (target_type = 'decision' AND target_id = $2::uuid)
              OR (source_type = 'memory_object' AND source_id = $3::uuid)
              OR (target_type = 'memory_object' AND target_id = $3::uuid)
            )
        ),
        memory_ids AS (
          SELECT endpoint_id AS id FROM related_endpoints WHERE endpoint_type = 'memory_object'
          UNION
          SELECT decision.memory_object_id
          FROM related_endpoints AS endpoint
          JOIN dirizhor.decisions AS decision
            ON endpoint.endpoint_type = 'decision' AND decision.id = endpoint.endpoint_id
          WHERE decision.project_id = $1::uuid
          UNION
          SELECT question.memory_object_id
          FROM related_endpoints AS endpoint
          JOIN dirizhor.open_questions AS question
            ON endpoint.endpoint_type = 'open_question' AND question.id = endpoint.endpoint_id
          WHERE question.project_id = $1::uuid
        )
        SELECT DISTINCT
          memory.id::text AS id,
          memory.type,
          memory.title,
          memory.status,
          memory.current_version_id::text AS "currentVersionId",
          memory.sensitivity_level AS "sensitivityLevel"
        FROM memory_ids
        JOIN dirizhor.memory_objects AS memory ON memory.id = memory_ids.id
        WHERE memory.project_id = $1::uuid AND memory.id <> $3::uuid
        ORDER BY id
      `,
      [projectId, decisionId, memoryObjectId],
    );
    return result.rows;
  }

  private async loadProvenanceRuns(
    transaction: SqlQueryable,
    projectId: string,
    decisionId: string,
    memoryObjectId: string,
  ): Promise<RunRow[]> {
    const result = await transaction.query<RunRow>(
      `
        WITH related_endpoints AS (
          SELECT
            CASE
              WHEN (source_type = 'decision' AND source_id = $2::uuid)
                OR (source_type = 'memory_object' AND source_id = $3::uuid)
                THEN target_type
              ELSE source_type
            END AS endpoint_type,
            CASE
              WHEN (source_type = 'decision' AND source_id = $2::uuid)
                OR (source_type = 'memory_object' AND source_id = $3::uuid)
                THEN target_id
              ELSE source_id
            END AS endpoint_id
          FROM dirizhor.relationships
          WHERE project_id = $1::uuid
            AND (
              (source_type = 'decision' AND source_id = $2::uuid)
              OR (target_type = 'decision' AND target_id = $2::uuid)
              OR (source_type = 'memory_object' AND source_id = $3::uuid)
              OR (target_type = 'memory_object' AND target_id = $3::uuid)
            )
        ),
        run_ids AS (
          SELECT endpoint_id AS id FROM related_endpoints WHERE endpoint_type = 'agent_run'
          UNION
          SELECT run.id
          FROM related_endpoints AS endpoint
          JOIN dirizhor.agent_runs AS run
            ON endpoint.endpoint_type = 'task' AND run.task_id = endpoint.endpoint_id
          WHERE run.project_id = $1::uuid
          UNION
          SELECT result.agent_run_id
          FROM related_endpoints AS endpoint
          JOIN dirizhor.agent_run_results AS result
            ON endpoint.endpoint_type = 'memory_object'
           AND result.saved_memory_object_id = endpoint.endpoint_id
          WHERE result.project_id = $1::uuid
        )
        SELECT DISTINCT
          run.id::text AS id,
          run.task_id::text AS "taskId",
          run.agent_type AS "agentType",
          run.provider,
          run.model,
          run.status,
          run.deployment_class AS "deploymentClass",
          run.context_set_hash AS "contextSetHash",
          result.saved_memory_object_id::text AS "resultMemoryObjectId",
          run.requested_by_user_id::text AS "requestedByUserId",
          run.origin_request_id::text AS "originRequestId",
          run.created_at AS "createdAt",
          run.dispatched_at AS "dispatchedAt",
          run.started_at AS "startedAt",
          run.finished_at AS "finishedAt"
        FROM run_ids
        JOIN dirizhor.agent_runs AS run ON run.id = run_ids.id
        LEFT JOIN dirizhor.agent_run_results AS result ON result.agent_run_id = run.id
        WHERE run.project_id = $1::uuid
        ORDER BY "createdAt", id
      `,
      [projectId, decisionId, memoryObjectId],
    );
    return result.rows;
  }

  private async loadSourceVersions(
    transaction: SqlQueryable,
    runIds: readonly string[],
  ): Promise<SourceVersionRow[]> {
    if (runIds.length === 0) {
      return [];
    }
    const result = await transaction.query<SourceVersionRow>(
      `
        SELECT
          context.agent_run_id::text AS "agentRunId",
          context.position,
          context.memory_object_id::text AS "memoryObjectId",
          memory.title AS "memoryObjectTitle",
          context.document_version_id::text AS "documentVersionId",
          version.version_number AS "versionNumber",
          version.file_name AS "fileName",
          version.file_type AS "fileType",
          version.content_hash AS "contentHash",
          version.size_bytes AS "sizeBytes",
          context.access_reason AS "accessReason",
          context.sensitivity_level AS "frozenSensitivityLevel",
          memory.sensitivity_level AS "currentSensitivityLevel"
        FROM dirizhor.agent_run_contexts AS context
        JOIN dirizhor.memory_objects AS memory
          ON memory.id = context.memory_object_id
         AND memory.project_id = context.project_id
        JOIN dirizhor.document_versions AS version
          ON version.id = context.document_version_id
         AND version.memory_object_id = context.memory_object_id
        WHERE context.agent_run_id = ANY($1::uuid[])
        ORDER BY context.agent_run_id, context.position
      `,
      [runIds],
    );
    return result.rows;
  }

  private async loadProvenanceAudits(
    transaction: SqlQueryable,
    projectId: string,
    decision: Decision,
    memories: readonly MemoryTargetRow[],
    runs: readonly RunRow[],
    sources: readonly SourceVersionRow[],
  ): Promise<AuditRow[]> {
    const memoryIds = [...new Set([
      decision.memory_object_id,
      ...memories.map((memory) => memory.id),
      ...runs.flatMap((run) => run.resultMemoryObjectId === null ? [] : [run.resultMemoryObjectId]),
      ...sources.map((source) => source.memoryObjectId),
    ])];
    const runIds = runs.map((run) => run.id);
    const versionIds = [...new Set(sources.map((source) => source.documentVersionId))];
    const result = await transaction.query<AuditRow>(
      `
        SELECT
          audit.id::text AS id,
          audit.actor_type AS "actorType",
          audit.actor_id::text AS "actorId",
          audit.action,
          audit.target_type AS "targetType",
          audit.target_id::text AS "targetId",
          audit.request_id::text AS "requestId",
          audit.created_at AS "createdAt"
        FROM dirizhor.audit_events AS audit
        WHERE audit.project_id = $1::uuid
          AND audit.action <> 'access.allowed'
          AND audit.target_type IS NOT NULL
          AND audit.target_id IS NOT NULL
          AND (
            (audit.target_type = 'decision' AND audit.target_id = $2::uuid)
            OR (audit.target_type = 'memory_object' AND audit.target_id = ANY($3::uuid[]))
            OR (audit.target_type = 'agent_run' AND audit.target_id = ANY($4::uuid[]))
            OR (audit.target_type = 'document_version' AND audit.target_id = ANY($5::uuid[]))
          )
        ORDER BY audit.created_at, audit.id
      `,
      [projectId, decision.id, memoryIds, runIds, versionIds],
    );
    return result.rows;
  }
}

const relationshipSelect = `
  SELECT
    relationship.id::text AS id,
    relationship.source_type AS "sourceType",
    relationship.source_id::text AS "sourceId",
    relationship.target_type AS "targetType",
    relationship.target_id::text AS "targetId",
    relationship.relation_type AS "relationType",
    relationship.description,
    relationship.created_by_user_id::text AS "createdByUserId",
    relationship.created_at AS "createdAt"
  FROM dirizhor.relationships AS relationship
`;

function decisionFromRow(row: DecisionRow): Decision {
  return {
    id: row.id,
    memory_object_id: row.memoryObjectId,
    project_id: row.projectId,
    topic_id: row.topicId,
    title: row.title,
    decision_text: row.decisionText,
    rationale: row.rationale,
    status: row.status,
    supersedes_decision_id: row.supersedesDecisionId,
    decided_by_user_id: row.decidedByUserId,
    decided_at: nullableTimestamp(row.decidedAt),
    sensitivity_level: row.sensitivityLevel,
    created_at: timestamp(row.createdAt),
    updated_at: timestamp(row.updatedAt),
  };
}

function relationshipFromRow(row: RelationshipRow): DecisionRelationship {
  return {
    id: row.id,
    source_type: row.sourceType,
    source_id: row.sourceId,
    target_type: row.targetType,
    target_id: row.targetId,
    relation_type: row.relationType,
    description: row.description,
    created_by_user_id: row.createdByUserId,
    created_at: timestamp(row.createdAt),
  };
}

function relatedMemoryFromRow(row: MemoryTargetRow): DecisionRelatedMemoryObject {
  return {
    id: row.id,
    type: row.type,
    title: row.title,
    current_version_id: row.currentVersionId,
    sensitivity_level: row.sensitivityLevel,
  };
}

function runFromRow(row: RunRow): DecisionProvenanceAgentRun {
  return {
    id: row.id,
    task_id: row.taskId,
    agent_type: row.agentType,
    provider: row.provider,
    model: row.model,
    status: row.status,
    deployment_class: row.deploymentClass,
    context_set_hash: row.contextSetHash,
    result_memory_object_id: row.resultMemoryObjectId,
    requested_by_user_id: row.requestedByUserId,
    origin_request_id: row.originRequestId,
    created_at: timestamp(row.createdAt),
    dispatched_at: nullableTimestamp(row.dispatchedAt),
    started_at: nullableTimestamp(row.startedAt),
    finished_at: nullableTimestamp(row.finishedAt),
  };
}

function sourceVersionFromRow(row: SourceVersionRow): DecisionSourceVersion {
  return {
    agent_run_id: row.agentRunId,
    position: row.position,
    memory_object_id: row.memoryObjectId,
    memory_object_title: row.memoryObjectTitle,
    document_version_id: row.documentVersionId,
    version_number: row.versionNumber,
    file_name: row.fileName,
    file_type: row.fileType,
    content_hash: row.contentHash,
    size_bytes: safeSize(row.sizeBytes),
    access_reason: row.accessReason,
    frozen_sensitivity_level: row.frozenSensitivityLevel,
    current_sensitivity_level: row.currentSensitivityLevel,
  };
}

function auditFromRow(row: AuditRow): DecisionAuditEvent {
  return {
    id: row.id,
    actor_type: row.actorType,
    actor_id: row.actorId,
    action: row.action,
    target_type: row.targetType,
    target_id: row.targetId,
    request_id: row.requestId,
    created_at: timestamp(row.createdAt),
  };
}

function matchesCreate(
  decision: Decision,
  relationships: readonly RelationshipRow[],
  input: NormalizedDecisionCreate,
): boolean {
  if (
    decision.project_id !== input.project_id ||
    decision.topic_id !== input.topic_id ||
    decision.title !== input.title ||
    decision.decision_text !== input.decision_text ||
    decision.rationale !== input.rationale ||
    decision.status !== input.status ||
    decision.sensitivity_level !== input.sensitivity_level
  ) {
    return false;
  }
  const existing = relationships.map(relationshipKey).sort();
  const expected = input.relationships.map(referenceKey).sort();
  return existing.length === expected.length && existing.every((value, index) => value === expected[index]);
}

function relationshipKey(relationship: RelationshipRow): string {
  return referenceKey({
    target_type: relationship.targetType,
    target_id: relationship.targetId,
    relation_type: relationship.relationType,
    description: relationship.description,
  });
}

function referenceKey(relationship: RelationshipRef): string {
  return JSON.stringify([
    relationship.target_type,
    relationship.target_id,
    relationship.relation_type,
    relationship.description ?? null,
  ]);
}

function relationshipTable(targetType: 'task' | 'agent_run'): string {
  return targetType === 'task' ? 'tasks' : 'agent_runs';
}

function sensitivityPermission(level: SensitivityLevel): string | null {
  if (level === 'confidential') {
    return 'memory_object.read_confidential';
  }
  if (level === 'restricted') {
    return 'memory_object.read_restricted';
  }
  return null;
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

function notFound(resource: string, id: string): DirectorProtocolError {
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
