import { hashCanonical } from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import type {
  MemoryObject,
  MemoryObjectPage,
  MemoryObjectSearchQuery,
  MemoryObjectType,
  ProjectListQuery,
  ProjectPage,
} from './public-protocol.js';
import type {
  MemorySearchPosition,
  ProjectListPosition,
  PublicQueryRepository,
  TaskTimelinePosition,
} from './public-query-ports.js';
import { decodeQueryCursor, encodeQueryCursor } from './query-cursor.js';
import type {
  TaskContextSearchRequest,
  TaskContextSearchResponse,
  TaskTimelinePage,
  TaskTimelineQuery,
} from './task-protocol.js';

export interface PublicQueryServiceOptions {
  repository: PublicQueryRepository;
}

export class PublicQueryService {
  private readonly repository: PublicQueryRepository;

  constructor(options: PublicQueryServiceOptions) {
    this.repository = options.repository;
  }

  async listProjects(
    userId: string,
    requestId: string,
    input: ProjectListQuery,
  ): Promise<ProjectPage> {
    const scope = hashCanonical({ version: 1, kind: 'project_list', userId });
    const after = input.cursor === undefined
      ? null
      : decodeQueryCursor(input.cursor, scope, isProjectListPosition);
    const result = await this.repository.listProjects({
      userId,
      requestId,
      limit: normalizedLimit(input.limit, 50),
      after,
    });
    return {
      items: result.items,
      next_cursor: result.nextPosition === null
        ? null
        : encodeQueryCursor(scope, result.nextPosition),
    };
  }

  async getMemoryObject(
    userId: string,
    requestId: string,
    memoryObjectId: string,
  ): Promise<MemoryObject> {
    return this.repository.getMemoryObject({ userId, requestId, memoryObjectId });
  }

  async searchMemoryObjects(
    userId: string,
    requestId: string,
    input: MemoryObjectSearchQuery,
  ): Promise<MemoryObjectPage> {
    const search = normalizeSearch(input.q);
    const types = input.type === undefined ? null : [input.type];
    const scope = memorySearchScope(userId, input.project_id, search.query, types);
    const after =
      input.cursor === undefined
        ? null
        : decodeQueryCursor(input.cursor, scope, isMemorySearchPosition);
    const result = await this.repository.searchMemoryObjects({
      userId,
      requestId,
      projectId: input.project_id,
      normalizedQuery: search.query,
      terms: search.terms,
      types,
      limit: normalizedLimit(input.limit, 50),
      after,
    });
    return {
      items: result.matches.map((match) => match.item),
      next_cursor:
        result.nextPosition === null
          ? null
          : encodeQueryCursor(scope, result.nextPosition),
    };
  }

  async searchTaskContext(
    userId: string,
    requestId: string,
    taskId: string,
    input: TaskContextSearchRequest,
  ): Promise<TaskContextSearchResponse> {
    const search = normalizeSearch(input.query);
    const types = normalizeTypes(input.types);
    const candidates = await this.repository.searchTaskContext({
      userId,
      requestId,
      taskId,
      normalizedQuery: search.query,
      terms: search.terms,
      types,
      limit: normalizedLimit(input.limit, 20),
    });
    return { task_id: taskId, candidates };
  }

  async getTaskTimeline(
    userId: string,
    requestId: string,
    taskId: string,
    input: TaskTimelineQuery,
  ): Promise<TaskTimelinePage> {
    const scope = timelineScope(userId, taskId);
    const after =
      input.cursor === undefined
        ? null
        : decodeQueryCursor(input.cursor, scope, isTaskTimelinePosition);
    const result = await this.repository.getTaskTimeline({
      userId,
      requestId,
      taskId,
      limit: normalizedLimit(input.limit, 50),
      after,
    });
    return {
      items: result.items,
      next_cursor:
        result.nextPosition === null
          ? null
          : encodeQueryCursor(scope, result.nextPosition),
    };
  }
}

function normalizeSearch(value: string): { query: string; terms: string[] } {
  const query = value.normalize('NFKC').trim().replace(/\s+/g, ' ').toLocaleLowerCase('ru');
  if (query.length === 0) {
    throw validationError('Search query must not be blank.');
  }
  const split = query.split(/[\s\p{P}\p{S}]+/u).filter((term) => term.length > 0);
  return { query, terms: split.length === 0 ? [query] : [...new Set(split)] };
}

function normalizeTypes(
  values: readonly MemoryObjectType[] | undefined,
): MemoryObjectType[] | null {
  if (values === undefined || values.length === 0) {
    return null;
  }
  return [...new Set(values)];
}

function normalizedLimit(value: number | undefined, fallback: number): number {
  const limit = value ?? fallback;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw validationError('Pagination limit must be an integer from 1 through 100.');
  }
  return limit;
}

function memorySearchScope(
  userId: string,
  projectId: string,
  query: string,
  types: readonly MemoryObjectType[] | null,
): string {
  return hashCanonical({ version: 1, kind: 'memory_search', userId, projectId, query, types });
}

function timelineScope(userId: string, taskId: string): string {
  return hashCanonical({ version: 1, kind: 'task_timeline', userId, taskId });
}

function isMemorySearchPosition(value: unknown): value is MemorySearchPosition {
  if (!isRecord(value, ['rank', 'updatedAt', 'memoryObjectId'])) {
    return false;
  }
  return (
    Number.isSafeInteger(value.rank) &&
    typeof value.rank === 'number' &&
    value.rank >= 0 &&
    isTimestamp(value.updatedAt) &&
    isUuid(value.memoryObjectId)
  );
}

function isProjectListPosition(value: unknown): value is ProjectListPosition {
  if (!isRecord(value, ['updatedAt', 'projectId'])) {
    return false;
  }
  return isTimestamp(value.updatedAt) && isUuid(value.projectId);
}

function isTaskTimelinePosition(value: unknown): value is TaskTimelinePosition {
  if (!isRecord(value, ['occurredAt', 'kind', 'resourceId'])) {
    return false;
  }
  return (
    isTimestamp(value.occurredAt) &&
    ['audit_event', 'agent_run', 'ai_result', 'decision'].includes(String(value.kind)) &&
    isUuid(value.resourceId)
  );
}

function isRecord(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => key in value)
  );
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

function isUuid(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
  );
}

function validationError(message: string): DirectorProtocolError {
  return new DirectorProtocolError(400, 'validation_error', message);
}
