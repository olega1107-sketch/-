import { DirectorProtocolError } from './errors.js';
import { insertAllowAuthorizationDecision } from './authorization-decision.js';
import type {
  CreateMemoryObjectWithVersionCommand,
  MemoryIngestRepository,
  MemoryUploadAuthorization,
} from './memory-ports.js';
import type { MemoryObject, UploadMemoryObjectType } from './public-protocol.js';
import type { SensitivityLevel } from './protocol.js';
import type { SqlDatabase, SqlQueryable } from './ports.js';

const requiredPermissions = [
  'project.read',
  'memory_object.create',
  'document_version.create',
] as const;

interface StatusRow {
  status: string;
}

interface PermissionRow {
  code: string;
}

interface MemoryObjectRow {
  id: string;
  type: UploadMemoryObjectType;
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

export class PostgresMemoryIngestRepository implements MemoryIngestRepository {
  constructor(private readonly database: SqlDatabase) {}

  async authorizeUpload(input: MemoryUploadAuthorization): Promise<void> {
    await this.database.transaction((transaction) => this.authorize(transaction, input, false));
  }

  async createMemoryObjectWithVersion(
    command: CreateMemoryObjectWithVersionCommand,
  ): Promise<MemoryObject> {
    try {
      return await this.database.transaction(async (transaction) => {
        await this.authorize(transaction, command, true);
        const authorizationDecisionId = await insertAllowAuthorizationDecision(transaction, {
          principalUserId: command.userId,
          action: 'memory_object.create',
          resourceType: 'project',
          resourceId: command.projectId,
          projectId: command.projectId,
          requestId: command.requestId,
        });
        await transaction.query(
          `
            INSERT INTO dirizhor.memory_objects (
              id,
              type,
              title,
              project_id,
              topic_id,
              author_user_id,
              summary,
              keywords,
              sensitivity_level
            )
            VALUES (
              $1::uuid,
              $2,
              $3,
              $4::uuid,
              $5::uuid,
              $6::uuid,
              $7,
              $8::text[],
              $9
            )
          `,
          [
            command.memoryObjectId,
            command.metadata.type,
            command.metadata.title,
            command.projectId,
            command.topicId,
            command.userId,
            command.metadata.summary,
            command.metadata.keywords,
            command.metadata.sensitivity_level,
          ],
        );
        await transaction.query(
          `
            INSERT INTO dirizhor.document_versions (
              id,
              memory_object_id,
              version_number,
              storage_uri,
              file_name,
              file_type,
              content_hash,
              size_bytes,
              created_by_user_id
            )
            VALUES ($1::uuid, $2::uuid, 1, $3, $4, $5, $6, $7, $8::uuid)
          `,
          [
            command.documentVersionId,
            command.memoryObjectId,
            command.storageUri,
            command.fileName,
            command.fileType,
            command.contentHash,
            command.sizeBytes,
            command.userId,
          ],
        );
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
              request_id,
              authorization_decision_id
            )
            VALUES
              (
                'user',
                $1::uuid,
                'memory_object.created',
                'memory_object',
                $2::uuid,
                $3::uuid,
                $4::jsonb,
                $5::uuid,
                $8::uuid
              ),
              (
                'user',
                $1::uuid,
                'document_version.created',
                'document_version',
                $6::uuid,
                $3::uuid,
                $7::jsonb,
                $5::uuid,
                $8::uuid
              )
          `,
          [
            command.userId,
            command.memoryObjectId,
            command.projectId,
            JSON.stringify({
              type: command.metadata.type,
              topic_id: command.topicId,
              sensitivity_level: command.metadata.sensitivity_level,
            }),
            command.requestId,
            command.documentVersionId,
            JSON.stringify({
              memory_object_id: command.memoryObjectId,
              version_number: 1,
              file_name: command.fileName,
              file_type: command.fileType,
              content_hash: command.contentHash,
              size_bytes: command.sizeBytes,
            }),
            authorizationDecisionId,
          ],
        );
        return this.loadCreated(transaction, command.memoryObjectId);
      });
    } catch (error) {
      if (sqlState(error) === '23505') {
        throw new DirectorProtocolError(
          409,
          'conflict',
          'The memory object or document version already exists.',
        );
      }
      throw error;
    }
  }

  private async authorize(
    transaction: SqlQueryable,
    input: MemoryUploadAuthorization,
    lock: boolean,
  ): Promise<void> {
    const lockClause = lock ? ' FOR SHARE' : '';
    const user = await transaction.query<StatusRow>(
      `
        SELECT status
        FROM dirizhor.app_users
        WHERE id = $1::uuid
        ${lockClause}
      `,
      [input.userId],
    );
    if (user.rows[0]?.status !== 'active') {
      throw new DirectorProtocolError(401, 'unauthorized', 'Authenticated user is not active.');
    }

    const project = await transaction.query<StatusRow>(
      `
        SELECT status
        FROM dirizhor.projects
        WHERE id = $1::uuid
        ${lockClause}
      `,
      [input.projectId],
    );
    if (project.rows[0]?.status !== 'active') {
      throw notFound('project', input.projectId);
    }

    const permissions = await transaction.query<PermissionRow>(
      `
        SELECT permission.code
        FROM dirizhor.role_assignments AS assignment
        JOIN dirizhor.roles AS role
          ON role.id = assignment.role_id
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
          AND permission.code = ANY($3::text[])
        ${lock ? 'FOR SHARE OF assignment, role, role_permission, permission' : ''}
      `,
      [input.userId, input.projectId, requiredPermissions],
    );
    const granted = new Set(permissions.rows.map((row) => row.code));
    const missing = requiredPermissions.filter((permission) => !granted.has(permission));
    if (missing.length > 0) {
      throw new DirectorProtocolError(
        403,
        'access_denied',
        'The user lacks required project permissions.',
        false,
        { missing_permissions: missing },
      );
    }

    if (input.topicId !== null) {
      const topic = await transaction.query<{ id: string }>(
        `
          SELECT id::text AS id
          FROM dirizhor.topics
          WHERE id = $1::uuid
            AND project_id = $2::uuid
          ${lockClause}
        `,
        [input.topicId, input.projectId],
      );
      if (topic.rowCount !== 1) {
        throw notFound('topic', input.topicId);
      }
    }
  }

  private async loadCreated(
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
      throw new Error('Committed memory object could not be loaded.');
    }
    const sizeBytes = safeSize(row.sizeBytes);
    return {
      id: row.id,
      type: row.type,
      title: row.title,
      project_id: row.projectId,
      topic_id: row.topicId,
      current_version_id: row.currentVersionId,
      current_version: {
        id: row.documentVersionId,
        memory_object_id: row.id,
        version_number: row.versionNumber,
        file_name: row.fileName,
        file_type: row.fileType,
        content_hash: row.contentHash,
        size_bytes: sizeBytes,
        created_by_user_id: row.versionCreatedByUserId,
        created_at: timestamp(row.versionCreatedAt),
        change_summary: row.changeSummary,
      },
      author_user_id: row.authorUserId,
      summary: row.summary,
      keywords: row.keywords,
      status: row.status,
      sensitivity_level: row.sensitivityLevel,
      created_at: timestamp(row.createdAt),
      updated_at: timestamp(row.updatedAt),
      archived_at: row.archivedAt === null ? null : timestamp(row.archivedAt),
    };
  }
}

function notFound(resource: 'project' | 'topic', id: string): DirectorProtocolError {
  return new DirectorProtocolError(404, 'not_found', `The ${resource} was not found.`, false, {
    resource,
    id,
  });
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

function sqlState(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return undefined;
  }
  return typeof error.code === 'string' ? error.code : undefined;
}
