import { ConcealedAuthorizationDeniedError } from './authorization-audit.js';
import {
  insertAllowedAccessAudit,
  insertAllowAuthorizationDecision,
} from './authorization-decision.js';
import { hashCanonical } from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import type {
  DocumentVersion,
  MemoryObject,
  MemoryObjectStatus,
  MemoryObjectType,
  Project,
  ProjectStatus,
} from './public-protocol.js';
import type {
  GetMemoryObjectQuery,
  GetTaskTimelineQuery,
  ListProjectsQuery,
  MemorySearchMatch,
  MemorySearchPosition,
  MemorySearchSlice,
  PublicQueryRepository,
  ProjectListSlice,
  SearchMemoryObjectsQuery,
  SearchTaskContextQuery,
  TaskTimelinePosition,
  TaskTimelineSlice,
} from './public-query-ports.js';
import type { SqlDatabase, SqlQueryable } from './ports.js';
import type { SensitivityLevel } from './protocol.js';
import type {
  TaskContextCandidate,
  TaskStatus,
  TaskTimelineItem,
  TaskTimelineKind,
} from './task-protocol.js';

interface StatusRow {
  status: string;
}

interface PermissionRow {
  code: string;
}

interface MemoryIdentityRow {
  projectId: string;
  sensitivityLevel: SensitivityLevel;
}

interface TaskIdentityRow {
  projectId: string;
  status: TaskStatus;
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
  status: MemoryObjectStatus;
  sensitivityLevel: SensitivityLevel;
  createdAt: Date | string;
  updatedAt: Date | string;
  archivedAt: Date | string | null;
  documentVersionId: string | null;
  versionNumber: number | null;
  fileName: string | null;
  fileType: string | null;
  contentHash: string | null;
  sizeBytes: number | string | null;
  versionCreatedByUserId: string | null;
  versionCreatedAt: Date | string | null;
  changeSummary: string | null;
}

interface SearchRow {
  id: string;
  type: MemoryObjectType;
  title: string;
  projectId: string;
  topicId: string | null;
  summary: string | null;
  keywords: string[];
  status: MemoryObjectStatus;
  sensitivityLevel: SensitivityLevel;
  updatedAt: Date | string;
  rank: number;
  reason: string;
}

interface TimelineRow {
  kind: TaskTimelineKind;
  occurredAt: Date | string;
  resourceType: string;
  resourceId: string;
  status: string | null;
  summary: string;
}

interface ProjectRow {
  id: string;
  title: string;
  description: string | null;
  status: ProjectStatus;
  ownerUserId: string;
  createdAt: Date | string;
  updatedAt: Date | string;
  archivedAt: Date | string | null;
}

const searchPermissions = [
  'project.read',
  'memory_object.search',
  'memory_object.read',
] as const;

export class PostgresPublicQueryRepository implements PublicQueryRepository {
  constructor(private readonly database: SqlDatabase) {}

  async listProjects(query: ListProjectsQuery): Promise<ProjectListSlice> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, query.userId);
      const result = await transaction.query<ProjectRow>(
        `
          SELECT
            project.id::text AS id,
            project.title,
            project.description,
            project.status,
            project.owner_user_id::text AS "ownerUserId",
            project.created_at AS "createdAt",
            project.updated_at AS "updatedAt",
            project.archived_at AS "archivedAt"
          FROM dirizhor.projects AS project
          WHERE EXISTS (
            SELECT 1
            FROM dirizhor.role_assignments AS assignment
            JOIN dirizhor.role_permissions AS role_permission
              ON role_permission.role_id = assignment.role_id
            JOIN dirizhor.permissions AS permission
              ON permission.id = role_permission.permission_id
            WHERE assignment.principal_type = 'user'
              AND assignment.principal_id = $1::uuid
              AND assignment.scope_type = 'project'
              AND assignment.scope_id = project.id
              AND assignment.revoked_at IS NULL
              AND (assignment.expires_at IS NULL OR assignment.expires_at > clock_timestamp())
              AND permission.code = 'project.read'
          )
            AND (
              $2::timestamptz IS NULL
              OR (project.updated_at, project.id) < ($2::timestamptz, $3::uuid)
            )
          ORDER BY project.updated_at DESC, project.id DESC
          LIMIT $4
        `,
        [
          query.userId,
          query.after?.updatedAt ?? null,
          query.after?.projectId ?? null,
          query.limit + 1,
        ],
      );
      const visibleRows = result.rows.slice(0, query.limit);
      const items = visibleRows.map(projectFromRow);
      const last = result.rows.length > query.limit ? visibleRows.at(-1) : undefined;
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: query.userId,
        action: 'project.read',
        resourceType: 'project_collection',
        resourceId: query.userId,
        projectId: null,
        requestId: query.requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: query.userId,
        authorizedAction: 'project.read',
        resourceType: 'project_collection',
        resourceId: query.userId,
        projectId: null,
        requestId: query.requestId,
        authorizationDecisionId,
        metadata: {
          returned_count: items.length,
          page_limit: query.limit,
          continued: query.after !== null,
        },
      });
      return {
        items,
        nextPosition: last === undefined
          ? null
          : { updatedAt: timestamp(last.updatedAt), projectId: last.id },
      };
    });
  }

  async getMemoryObject(query: GetMemoryObjectQuery): Promise<MemoryObject> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, query.userId);
      const identity = await this.loadMemoryIdentity(transaction, query.memoryObjectId);
      if (identity === undefined) {
        throw notFound('memory_object', query.memoryObjectId);
      }
      const permissions = await this.projectPermissions(
        transaction,
        query.userId,
        identity.projectId,
      );
      this.requirePermissions(permissions, ['project.read', 'memory_object.read'], {
        concealedPermission: 'project.read',
        concealedResource: ['memory_object', query.memoryObjectId],
      });
      this.requireSensitivityPermission(permissions, identity.sensitivityLevel);
      const includeCurrentVersion = permissions.has('document_version.read');
      const memoryObject = await this.loadMemoryObject(
        transaction,
        query.memoryObjectId,
        includeCurrentVersion,
      );
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: query.userId,
        action: 'memory_object.read',
        resourceType: 'memory_object',
        resourceId: query.memoryObjectId,
        projectId: identity.projectId,
        requestId: query.requestId,
      });
      await this.insertReadAudit(
        transaction,
        query,
        identity,
        includeCurrentVersion,
        authorizationDecisionId,
      );
      return memoryObject;
    });
  }

  async searchMemoryObjects(query: SearchMemoryObjectsQuery): Promise<MemorySearchSlice> {
    return this.database.transaction(async (transaction) => {
      const permissions = await this.authorizeProjectSearch(
        transaction,
        query.userId,
        query.projectId,
        ['project', query.projectId],
      );
      const rows = await this.searchRows(
        transaction,
        query.projectId,
        query.normalizedQuery,
        query.terms,
        query.types,
        permissions,
        query.after,
        query.limit + 1,
      );
      const slice = memorySearchSlice(rows, query.limit);
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: query.userId,
        action: 'memory_object.search',
        resourceType: 'project',
        resourceId: query.projectId,
        projectId: query.projectId,
        requestId: query.requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: query.userId,
        authorizedAction: 'memory_object.search',
        resourceType: 'project',
        resourceId: query.projectId,
        projectId: query.projectId,
        requestId: query.requestId,
        authorizationDecisionId,
        metadata: {
          query_hash: searchQueryHash(query.normalizedQuery, query.types),
          returned_count: slice.matches.length,
          page_limit: query.limit,
          continued: query.after !== null,
        },
      });
      return slice;
    });
  }

  async searchTaskContext(
    query: SearchTaskContextQuery,
  ): Promise<TaskContextCandidate[]> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, query.userId);
      const task = await this.loadTaskIdentity(transaction, query.taskId);
      if (task === undefined) {
        throw notFound('task', query.taskId);
      }
      const permissions = await this.authorizeProjectSearch(
        transaction,
        query.userId,
        task.projectId,
        ['task', query.taskId],
        false,
      );
      this.requirePermissions(permissions, ['task.read']);
      const rows = await this.searchRows(
        transaction,
        task.projectId,
        query.normalizedQuery,
        query.terms,
        query.types,
        permissions,
        null,
        query.limit,
      );
      const candidates = rows.map(taskContextCandidate);
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: query.userId,
        action: 'memory_object.search',
        resourceType: 'task',
        resourceId: query.taskId,
        projectId: task.projectId,
        requestId: query.requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: query.userId,
        authorizedAction: 'memory_object.search',
        resourceType: 'task',
        resourceId: query.taskId,
        projectId: task.projectId,
        requestId: query.requestId,
        authorizationDecisionId,
        metadata: {
          query_hash: searchQueryHash(query.normalizedQuery, query.types),
          returned_count: candidates.length,
          page_limit: query.limit,
        },
      });
      return candidates;
    });
  }

  async getTaskTimeline(query: GetTaskTimelineQuery): Promise<TaskTimelineSlice> {
    return this.database.transaction(async (transaction) => {
      await this.requireActiveUser(transaction, query.userId);
      const task = await this.loadTaskIdentity(transaction, query.taskId);
      if (task === undefined) {
        throw notFound('task', query.taskId);
      }
      const permissions = await this.projectPermissions(
        transaction,
        query.userId,
        task.projectId,
      );
      this.requirePermissions(permissions, ['project.read', 'task.read'], {
        concealedPermission: 'project.read',
        concealedResource: ['task', query.taskId],
      });
      const rows = await this.timelineRows(
        transaction,
        query.taskId,
        task.projectId,
        permissions,
        query.after,
        query.limit + 1,
      );
      const slice = timelineSlice(rows, query.limit);
      const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
        principalUserId: query.userId,
        action: 'task.read',
        resourceType: 'task',
        resourceId: query.taskId,
        projectId: task.projectId,
        requestId: query.requestId,
      });
      await insertAllowedAccessAudit(transaction, {
        actorUserId: query.userId,
        authorizedAction: 'task.read',
        resourceType: 'task',
        resourceId: query.taskId,
        projectId: task.projectId,
        requestId: query.requestId,
        authorizationDecisionId,
        metadata: {
          view: 'timeline',
          returned_count: slice.items.length,
          page_limit: query.limit,
          continued: query.after !== null,
        },
      });
      return slice;
    });
  }

  private async authorizeProjectSearch(
    transaction: SqlQueryable,
    userId: string,
    projectId: string,
    concealedResource: readonly ['project' | 'task', string],
    checkUser = true,
  ): Promise<ReadonlySet<string>> {
    if (checkUser) {
      await this.requireActiveUser(transaction, userId);
    }
    const permissions = await this.projectPermissions(transaction, userId, projectId);
    this.requirePermissions(permissions, searchPermissions, {
      concealedPermission: 'project.read',
      concealedResource,
    });
    return permissions;
  }

  private async requireActiveUser(
    transaction: SqlQueryable,
    userId: string,
  ): Promise<void> {
    const result = await transaction.query<StatusRow>(
      `
        SELECT status
        FROM dirizhor.app_users
        WHERE id = $1::uuid
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
  ): Promise<ReadonlySet<string>> {
    const project = await transaction.query<StatusRow>(
      `
        SELECT status
        FROM dirizhor.projects
        WHERE id = $1::uuid
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
      concealedResource: readonly ['project' | 'task' | 'memory_object', string];
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

  private async loadMemoryIdentity(
    transaction: SqlQueryable,
    memoryObjectId: string,
  ): Promise<MemoryIdentityRow | undefined> {
    const result = await transaction.query<MemoryIdentityRow>(
      `
        SELECT
          project_id::text AS "projectId",
          sensitivity_level AS "sensitivityLevel"
        FROM dirizhor.memory_objects
        WHERE id = $1::uuid
      `,
      [memoryObjectId],
    );
    return result.rows[0];
  }

  private async loadTaskIdentity(
    transaction: SqlQueryable,
    taskId: string,
  ): Promise<TaskIdentityRow | undefined> {
    const result = await transaction.query<TaskIdentityRow>(
      `
        SELECT project_id::text AS "projectId", status
        FROM dirizhor.tasks
        WHERE id = $1::uuid
      `,
      [taskId],
    );
    return result.rows[0];
  }

  private async loadMemoryObject(
    transaction: SqlQueryable,
    memoryObjectId: string,
    includeCurrentVersion: boolean,
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
        LEFT JOIN dirizhor.document_versions AS version
          ON version.id = memory.current_version_id
         AND $2::boolean
        WHERE memory.id = $1::uuid
      `,
      [memoryObjectId, includeCurrentVersion],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw notFound('memory_object', memoryObjectId);
    }
    return memoryObject(row, includeCurrentVersion);
  }

  private async insertReadAudit(
    transaction: SqlQueryable,
    query: GetMemoryObjectQuery,
    identity: MemoryIdentityRow,
    includedCurrentVersion: boolean,
    authorizationDecisionId: string,
  ): Promise<void> {
    await transaction.query(
      `
        INSERT INTO dirizhor.audit_events (
          actor_type, actor_id, action, target_type, target_id,
          project_id, metadata, request_id, authorization_decision_id
        )
        VALUES (
          'user', $1::uuid, 'memory_object.read', 'memory_object', $2::uuid,
          $3::uuid, $4::jsonb, $5::uuid, $6::uuid
        )
      `,
      [
        query.userId,
        query.memoryObjectId,
        identity.projectId,
        JSON.stringify({
          sensitivity_level: identity.sensitivityLevel,
          included_current_version: includedCurrentVersion,
        }),
        query.requestId,
        authorizationDecisionId,
      ],
    );
  }

  private async searchRows(
    transaction: SqlQueryable,
    projectId: string,
    normalizedQuery: string,
    terms: readonly string[],
    types: readonly MemoryObjectType[] | null,
    permissions: ReadonlySet<string>,
    after: MemorySearchPosition | null,
    limit: number,
  ): Promise<SearchRow[]> {
    const result = await transaction.query<SearchRow>(
      `
        WITH relationship_memory_edges AS (
          SELECT
            CASE relationship.source_type
              WHEN 'memory_object' THEN relationship.source_id
              WHEN 'decision' THEN source_decision.memory_object_id
              WHEN 'open_question' THEN source_question.memory_object_id
              ELSE NULL
            END AS source_memory_id,
            CASE relationship.target_type
              WHEN 'memory_object' THEN relationship.target_id
              WHEN 'decision' THEN target_decision.memory_object_id
              WHEN 'open_question' THEN target_question.memory_object_id
              ELSE NULL
            END AS target_memory_id
          FROM dirizhor.relationships AS relationship
          LEFT JOIN dirizhor.decisions AS source_decision
            ON relationship.source_type = 'decision'
           AND source_decision.id = relationship.source_id
           AND source_decision.project_id = relationship.project_id
          LEFT JOIN dirizhor.decisions AS target_decision
            ON relationship.target_type = 'decision'
           AND target_decision.id = relationship.target_id
           AND target_decision.project_id = relationship.project_id
          LEFT JOIN dirizhor.open_questions AS source_question
            ON relationship.source_type = 'open_question'
           AND source_question.id = relationship.source_id
           AND source_question.project_id = relationship.project_id
          LEFT JOIN dirizhor.open_questions AS target_question
            ON relationship.target_type = 'open_question'
           AND target_question.id = relationship.target_id
           AND target_question.project_id = relationship.project_id
          WHERE relationship.project_id = $1::uuid
        ),
        ranked AS (
          SELECT
            memory.id::text AS id,
            memory.type,
            memory.title,
            memory.project_id::text AS "projectId",
            memory.topic_id::text AS "topicId",
            memory.summary,
            memory.keywords,
            memory.status,
            memory.sensitivity_level AS "sensitivityLevel",
            memory.updated_at AS "updatedAt",
            CASE
              WHEN lower(memory.title) = $2 THEN 700
              WHEN strpos(lower(memory.title), $2) = 1 THEN 600
              WHEN strpos(lower(memory.title), $2) > 0 THEN 500
              WHEN EXISTS (
                SELECT 1 FROM unnest(memory.keywords) AS keyword
                WHERE lower(keyword) = $2
              ) THEN 450
              WHEN EXISTS (
                SELECT 1 FROM unnest(memory.keywords) AS keyword
                WHERE strpos(lower(keyword), $2) > 0
              ) THEN 400
              WHEN strpos(lower(coalesce(memory.summary, '')), $2) > 0 THEN 350
              WHEN strpos(lower(coalesce(topic.title, '')), $2) > 0 THEN 300
              WHEN strpos(lower(project.title), $2) > 0 THEN 250
              ELSE 100
            END AS rank,
            CASE
              WHEN strpos(lower(memory.title), $2) > 0 THEN 'Matched title'
              WHEN EXISTS (
                SELECT 1 FROM unnest(memory.keywords) AS keyword
                WHERE strpos(lower(keyword), $2) > 0
              ) THEN 'Matched keywords'
              WHEN strpos(lower(coalesce(memory.summary, '')), $2) > 0
                THEN 'Matched summary'
              WHEN strpos(lower(coalesce(topic.title, '')), $2) > 0 THEN 'Matched topic'
              WHEN strpos(lower(project.title), $2) > 0 THEN 'Matched project'
              WHEN NOT EXISTS (
                SELECT 1
                FROM unnest($3::text[]) AS term
                WHERE strpos(
                  lower(concat_ws(
                    ' ',
                    memory.title,
                    coalesce(memory.summary, ''),
                    array_to_string(memory.keywords, ' '),
                    coalesce(topic.title, ''),
                    project.title
                  )),
                  term
                ) = 0
              ) THEN 'Matched card metadata'
              ELSE 'Matched related object'
            END AS reason
          FROM dirizhor.memory_objects AS memory
          JOIN dirizhor.projects AS project ON project.id = memory.project_id
          LEFT JOIN dirizhor.topics AS topic ON topic.id = memory.topic_id
          WHERE memory.project_id = $1::uuid
            AND memory.status = 'active'
            AND ($4::text[] IS NULL OR memory.type = ANY($4::text[]))
            AND (
              memory.sensitivity_level IN ('public', 'internal')
              OR (memory.sensitivity_level = 'confidential' AND $5::boolean)
              OR (memory.sensitivity_level = 'restricted' AND $6::boolean)
            )
            AND NOT EXISTS (
              SELECT 1
              FROM unnest($3::text[]) AS term
              WHERE NOT (
                strpos(
                  lower(concat_ws(
                    ' ',
                    memory.title,
                    coalesce(memory.summary, ''),
                    array_to_string(memory.keywords, ' '),
                    coalesce(topic.title, ''),
                    project.title
                  )),
                  term
                ) > 0
                OR EXISTS (
                  SELECT 1
                  FROM relationship_memory_edges AS edge
                  JOIN dirizhor.memory_objects AS linked
                    ON linked.project_id = memory.project_id
                   AND linked.status = 'active'
                   AND linked.id = CASE
                     WHEN edge.source_memory_id = memory.id THEN edge.target_memory_id
                     ELSE edge.source_memory_id
                   END
                  WHERE (
                      edge.source_memory_id = memory.id
                      OR edge.target_memory_id = memory.id
                   )
                    AND (
                      linked.sensitivity_level IN ('public', 'internal')
                      OR (linked.sensitivity_level = 'confidential' AND $5::boolean)
                      OR (linked.sensitivity_level = 'restricted' AND $6::boolean)
                    )
                    AND strpos(
                      lower(concat_ws(
                        ' ', linked.title, coalesce(linked.summary, ''),
                        array_to_string(linked.keywords, ' ')
                      )),
                      term
                    ) > 0
                )
              )
            )
        )
        SELECT *
        FROM ranked
        WHERE $7::integer IS NULL
           OR (rank, "updatedAt", id::uuid) < ($7::integer, $8::timestamptz, $9::uuid)
        ORDER BY rank DESC, "updatedAt" DESC, id::uuid DESC
        LIMIT $10
      `,
      [
        projectId,
        normalizedQuery,
        terms,
        types,
        permissions.has('memory_object.read_confidential'),
        permissions.has('memory_object.read_restricted'),
        after?.rank ?? null,
        after?.updatedAt ?? null,
        after?.memoryObjectId ?? null,
        limit,
      ],
    );
    return result.rows;
  }

  private async timelineRows(
    transaction: SqlQueryable,
    taskId: string,
    projectId: string,
    permissions: ReadonlySet<string>,
    after: TaskTimelinePosition | null,
    limit: number,
  ): Promise<TimelineRow[]> {
    const result = await transaction.query<TimelineRow>(
      `
        WITH related_runs AS (
          SELECT id, status, created_at
          FROM dirizhor.agent_runs
          WHERE task_id = $1::uuid AND project_id = $2::uuid
        ),
        visible_result_records AS (
          SELECT
            result.id,
            result.saved_at,
            memory.id AS memory_object_id,
            memory.current_version_id,
            memory.title,
            memory.status,
            memory.sensitivity_level,
            memory.created_at
          FROM dirizhor.agent_run_results AS result
          JOIN related_runs AS run ON run.id = result.agent_run_id
          JOIN dirizhor.memory_objects AS memory
            ON memory.id = result.saved_memory_object_id
          WHERE result.saved_memory_object_id IS NOT NULL
            AND (
              memory.sensitivity_level IN ('public', 'internal')
              OR (memory.sensitivity_level = 'confidential' AND $3::boolean)
              OR (memory.sensitivity_level = 'restricted' AND $4::boolean)
            )
        ),
        visible_results AS (
          SELECT DISTINCT ON (memory_object_id)
            memory_object_id,
            current_version_id,
            title,
            status,
            sensitivity_level,
            coalesce(saved_at, created_at) AS occurred_at
          FROM visible_result_records
          ORDER BY memory_object_id, saved_at ASC NULLS LAST
        ),
        core_anchors AS (
          SELECT 'task'::text AS resource_type, $1::uuid AS resource_id
          UNION
          SELECT 'agent_run', id FROM related_runs
          UNION
          SELECT 'memory_object', memory_object_id FROM visible_results
          UNION
          SELECT 'document_version', current_version_id
          FROM visible_results WHERE current_version_id IS NOT NULL
          UNION
          SELECT 'agent_run_result', id FROM visible_result_records
        ),
        visible_decisions AS (
          SELECT DISTINCT
            decision.id,
            decision.memory_object_id,
            memory.current_version_id,
            decision.title,
            decision.status,
            decision.created_at
          FROM dirizhor.relationships AS relationship
          JOIN dirizhor.decisions AS decision
            ON (
              relationship.source_type = 'decision'
              AND relationship.source_id = decision.id
            ) OR (
              relationship.target_type = 'decision'
              AND relationship.target_id = decision.id
            ) OR (
              relationship.source_type = 'memory_object'
              AND relationship.source_id = decision.memory_object_id
            ) OR (
              relationship.target_type = 'memory_object'
              AND relationship.target_id = decision.memory_object_id
            )
          JOIN core_anchors AS anchor
            ON (
              (
                (relationship.source_type = 'decision' AND relationship.source_id = decision.id)
                OR (
                  relationship.source_type = 'memory_object'
                  AND relationship.source_id = decision.memory_object_id
                )
              )
              AND relationship.target_type = anchor.resource_type
              AND relationship.target_id = anchor.resource_id
            ) OR (
              (
                (relationship.target_type = 'decision' AND relationship.target_id = decision.id)
                OR (
                  relationship.target_type = 'memory_object'
                  AND relationship.target_id = decision.memory_object_id
                )
              )
              AND relationship.source_type = anchor.resource_type
              AND relationship.source_id = anchor.resource_id
            )
          JOIN dirizhor.memory_objects AS memory ON memory.id = decision.memory_object_id
          WHERE relationship.project_id = $2::uuid
            AND decision.project_id = $2::uuid
            AND (
              memory.sensitivity_level IN ('public', 'internal')
              OR (memory.sensitivity_level = 'confidential' AND $3::boolean)
              OR (memory.sensitivity_level = 'restricted' AND $4::boolean)
            )
        ),
        resource_anchors AS (
          SELECT resource_type, resource_id FROM core_anchors
          UNION
          SELECT 'decision', id FROM visible_decisions
          UNION
          SELECT 'memory_object', memory_object_id FROM visible_decisions
          UNION
          SELECT 'document_version', current_version_id
          FROM visible_decisions WHERE current_version_id IS NOT NULL
        ),
        related_confirmations AS (
          SELECT confirmation.id
          FROM dirizhor.confirmations AS confirmation
          JOIN resource_anchors AS anchor
            ON anchor.resource_type = confirmation.target_type
           AND anchor.resource_id = confirmation.target_id
          WHERE confirmation.project_id = $2::uuid
        ),
        audit_anchors AS (
          SELECT resource_type, resource_id FROM resource_anchors
          UNION
          SELECT 'confirmation', id FROM related_confirmations
        ),
        timeline AS (
          SELECT
            'audit_event'::text AS kind,
            audit.created_at AS "occurredAt",
            'audit_event'::text AS "resourceType",
            audit.id::text AS "resourceId",
            NULL::text AS status,
            concat('Audit event: ', audit.action) AS summary
          FROM dirizhor.audit_events AS audit
          JOIN audit_anchors AS anchor
            ON anchor.resource_type = audit.target_type
           AND anchor.resource_id = audit.target_id
          WHERE audit.project_id = $2::uuid
            AND audit.action <> 'access.allowed'

          UNION ALL

          SELECT
            'agent_run',
            run.created_at,
            'agent_run',
            run.id::text,
            run.status,
            concat('Agent run is ', run.status)
          FROM related_runs AS run

          UNION ALL

          SELECT
            'ai_result',
            result.occurred_at,
            'memory_object',
            result.memory_object_id::text,
            result.status,
            concat('AI result saved: ', result.title)
          FROM visible_results AS result

          UNION ALL

          SELECT
            'decision',
            decision.created_at,
            'decision',
            decision.id::text,
            decision.status,
            concat('Decision: ', decision.title)
          FROM visible_decisions AS decision
        )
        SELECT kind, "occurredAt", "resourceType", "resourceId", status, summary
        FROM timeline
        WHERE $5::timestamptz IS NULL
           OR ("occurredAt", kind, "resourceId"::uuid)
              < ($5::timestamptz, $6::text, $7::uuid)
        ORDER BY "occurredAt" DESC, kind DESC, "resourceId"::uuid DESC
        LIMIT $8
      `,
      [
        taskId,
        projectId,
        permissions.has('memory_object.read_confidential'),
        permissions.has('memory_object.read_restricted'),
        after?.occurredAt ?? null,
        after?.kind ?? null,
        after?.resourceId ?? null,
        limit,
      ],
    );
    return result.rows;
  }
}

function searchQueryHash(
  normalizedQuery: string,
  types: readonly MemoryObjectType[] | null,
): string {
  return hashCanonical({ version: 1, normalized_query: normalizedQuery, types });
}

function memoryObject(row: MemoryObjectRow, includeCurrentVersion: boolean): MemoryObject {
  const object: MemoryObject = {
    id: row.id,
    type: row.type,
    title: row.title,
    project_id: row.projectId,
    topic_id: row.topicId,
    current_version_id: row.currentVersionId,
    author_user_id: row.authorUserId,
    summary: row.summary,
    keywords: row.keywords,
    status: row.status,
    sensitivity_level: row.sensitivityLevel,
    created_at: timestamp(row.createdAt),
    updated_at: timestamp(row.updatedAt),
    archived_at: row.archivedAt === null ? null : timestamp(row.archivedAt),
  };
  return includeCurrentVersion
    ? { ...object, current_version: documentVersion(row) }
    : object;
}

function documentVersion(row: MemoryObjectRow): DocumentVersion | null {
  if (row.documentVersionId === null) {
    return null;
  }
  if (
    row.versionNumber === null ||
    row.fileName === null ||
    row.fileType === null ||
    row.contentHash === null ||
    row.sizeBytes === null ||
    row.versionCreatedByUserId === null ||
    row.versionCreatedAt === null
  ) {
    throw new Error('Current document version metadata is incomplete.');
  }
  return {
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
}

function projectFromRow(row: ProjectRow): Project {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    status: row.status,
    owner_user_id: row.ownerUserId,
    created_at: timestamp(row.createdAt),
    updated_at: timestamp(row.updatedAt),
    archived_at: row.archivedAt === null ? null : timestamp(row.archivedAt),
  };
}

function memorySearchSlice(rows: readonly SearchRow[], limit: number): MemorySearchSlice {
  const visibleRows = rows.slice(0, limit);
  const matches = visibleRows.map(memorySearchMatch);
  const last = rows.length > limit ? matches.at(-1) : undefined;
  return { matches, nextPosition: last?.position ?? null };
}

function memorySearchMatch(row: SearchRow): MemorySearchMatch {
  const updatedAt = timestamp(row.updatedAt);
  return {
    item: {
      id: row.id,
      type: row.type,
      title: row.title,
      project_id: row.projectId,
      topic_id: row.topicId,
      summary: row.summary,
      keywords: row.keywords,
      status: row.status,
      sensitivity_level: row.sensitivityLevel,
      updated_at: updatedAt,
    },
    reason: row.reason,
    position: { rank: row.rank, updatedAt, memoryObjectId: row.id },
  };
}

function taskContextCandidate(row: SearchRow): TaskContextCandidate {
  return {
    memory_object_id: row.id,
    title: row.title,
    summary: row.summary,
    reason: row.reason,
    sensitivity_level: row.sensitivityLevel,
  };
}

function timelineSlice(rows: readonly TimelineRow[], limit: number): TaskTimelineSlice {
  const visibleRows = rows.slice(0, limit);
  const items = visibleRows.map(taskTimelineItem);
  const last = rows.length > limit ? items.at(-1) : undefined;
  return {
    items,
    nextPosition:
      last === undefined
        ? null
        : {
            occurredAt: last.occurred_at,
            kind: last.kind,
            resourceId: last.resource_id,
          },
  };
}

function taskTimelineItem(row: TimelineRow): TaskTimelineItem {
  return {
    kind: row.kind,
    occurred_at: timestamp(row.occurredAt),
    resource_type: row.resourceType,
    resource_id: row.resourceId,
    status: row.status,
    summary: row.summary,
  };
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

function timestamp(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error('Database returned an invalid timestamp.');
  }
  return date.toISOString();
}

function safeSize(value: number | string): number {
  const size = typeof value === 'string' ? Number(value) : value;
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error('Document size is outside the supported range.');
  }
  return size;
}

function notFound(
  resource: 'project' | 'task' | 'memory_object',
  id: string,
): DirectorProtocolError {
  return new DirectorProtocolError(404, 'not_found', `The ${resource} was not found.`, false, {
    resource,
    id,
  });
}
