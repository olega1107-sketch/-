import type {
  MemoryObject,
  MemoryObjectSummary,
  MemoryObjectType,
  Project,
  ProjectStatus,
} from './public-protocol.js';
import type {
  TaskContextCandidate,
  TaskTimelineItem,
  TaskTimelineKind,
} from './task-protocol.js';

export interface MemorySearchPosition {
  rank: number;
  updatedAt: string;
  memoryObjectId: string;
}

export interface TaskTimelinePosition {
  occurredAt: string;
  kind: TaskTimelineKind;
  resourceId: string;
}

export interface ProjectListPosition {
  updatedAt: string;
  projectId: string;
}

export interface ListProjectsQuery {
  userId: string;
  requestId: string;
  limit: number;
  after: ProjectListPosition | null;
}

export interface ProjectRowView extends Project {
  status: ProjectStatus;
}

export interface ProjectListSlice {
  items: ProjectRowView[];
  nextPosition: ProjectListPosition | null;
}

export interface GetMemoryObjectQuery {
  userId: string;
  requestId: string;
  memoryObjectId: string;
}

export interface SearchMemoryObjectsQuery {
  userId: string;
  requestId: string;
  projectId: string;
  normalizedQuery: string;
  terms: readonly string[];
  types: readonly MemoryObjectType[] | null;
  limit: number;
  after: MemorySearchPosition | null;
}

export interface SearchTaskContextQuery {
  userId: string;
  requestId: string;
  taskId: string;
  normalizedQuery: string;
  terms: readonly string[];
  types: readonly MemoryObjectType[] | null;
  limit: number;
}

export interface GetTaskTimelineQuery {
  userId: string;
  requestId: string;
  taskId: string;
  limit: number;
  after: TaskTimelinePosition | null;
}

export interface MemorySearchMatch {
  item: MemoryObjectSummary;
  reason: string;
  position: MemorySearchPosition;
}

export interface MemorySearchSlice {
  matches: MemorySearchMatch[];
  nextPosition: MemorySearchPosition | null;
}

export interface TaskTimelineSlice {
  items: TaskTimelineItem[];
  nextPosition: TaskTimelinePosition | null;
}

export interface PublicQueryRepository {
  listProjects(query: ListProjectsQuery): Promise<ProjectListSlice>;
  getMemoryObject(query: GetMemoryObjectQuery): Promise<MemoryObject>;
  searchMemoryObjects(query: SearchMemoryObjectsQuery): Promise<MemorySearchSlice>;
  searchTaskContext(query: SearchTaskContextQuery): Promise<TaskContextCandidate[]>;
  getTaskTimeline(query: GetTaskTimelineQuery): Promise<TaskTimelineSlice>;
}
