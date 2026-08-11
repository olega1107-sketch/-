import { Type, type Static } from '@sinclair/typebox';

import { MemoryObjectTypeSchema } from './public-protocol.js';
import {
  DeploymentClassSchema,
  SensitivityLevelSchema,
  TimestampSchema,
  UuidSchema,
  type SensitivityLevel,
} from './protocol.js';

export const TaskStatusSchema = Type.Union([
  Type.Literal('created'),
  Type.Literal('planning'),
  Type.Literal('awaiting_context'),
  Type.Literal('awaiting_user_confirmation'),
  Type.Literal('running_agent'),
  Type.Literal('reviewing'),
  Type.Literal('completed'),
  Type.Literal('failed'),
  Type.Literal('cancelled'),
]);
export type TaskStatus = Static<typeof TaskStatusSchema>;

export const TaskCreateSchema = Type.Object(
  {
    project_id: UuidSchema,
    title: Type.String({ minLength: 1 }),
    user_request: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type TaskCreate = Static<typeof TaskCreateSchema>;

export const TaskSchema = Type.Object(
  {
    id: UuidSchema,
    project_id: UuidSchema,
    created_by_user_id: UuidSchema,
    title: Type.String({ minLength: 1 }),
    user_request: Type.String({ minLength: 1 }),
    status: TaskStatusSchema,
    result_memory_object_id: Type.Union([Type.Null(), UuidSchema]),
    created_at: TimestampSchema,
    updated_at: TimestampSchema,
    completed_at: Type.Union([Type.Null(), TimestampSchema]),
  },
  { additionalProperties: false },
);
export type Task = Static<typeof TaskSchema>;

export const TaskIdParamsSchema = Type.Object(
  { task_id: UuidSchema },
  { additionalProperties: false },
);

export const TaskContextSearchRequestSchema = Type.Object(
  {
    query: Type.String({ minLength: 1 }),
    types: Type.Optional(Type.Array(MemoryObjectTypeSchema, { uniqueItems: true })),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, default: 20 })),
  },
  { additionalProperties: false },
);
export type TaskContextSearchRequest = Static<typeof TaskContextSearchRequestSchema>;

export const TaskContextCandidateSchema = Type.Object(
  {
    memory_object_id: UuidSchema,
    title: Type.String({ minLength: 1 }),
    summary: Type.Union([Type.Null(), Type.String()]),
    reason: Type.String({ minLength: 1 }),
    sensitivity_level: SensitivityLevelSchema,
  },
  { additionalProperties: false },
);
export type TaskContextCandidate = Static<typeof TaskContextCandidateSchema>;

export const TaskContextSearchResponseSchema = Type.Object(
  {
    task_id: UuidSchema,
    candidates: Type.Array(TaskContextCandidateSchema),
  },
  { additionalProperties: false },
);
export type TaskContextSearchResponse = Static<typeof TaskContextSearchResponseSchema>;

export const TaskTimelineKindSchema = Type.Union([
  Type.Literal('audit_event'),
  Type.Literal('agent_run'),
  Type.Literal('ai_result'),
  Type.Literal('decision'),
]);
export type TaskTimelineKind = Static<typeof TaskTimelineKindSchema>;

export const TaskTimelineQuerySchema = Type.Object(
  {
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, default: 50 })),
    cursor: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type TaskTimelineQuery = Static<typeof TaskTimelineQuerySchema>;

export const TaskTimelineItemSchema = Type.Object(
  {
    kind: TaskTimelineKindSchema,
    occurred_at: TimestampSchema,
    resource_type: Type.String({ minLength: 1 }),
    resource_id: UuidSchema,
    status: Type.Union([Type.Null(), Type.String()]),
    summary: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type TaskTimelineItem = Static<typeof TaskTimelineItemSchema>;

export const TaskTimelinePageSchema = Type.Object(
  {
    items: Type.Array(TaskTimelineItemSchema),
    next_cursor: Type.Union([Type.Null(), Type.String({ minLength: 1 })]),
  },
  { additionalProperties: false },
);
export type TaskTimelinePage = Static<typeof TaskTimelinePageSchema>;

export const AgentRunContextInputSchema = Type.Object(
  {
    memory_object_id: UuidSchema,
    document_version_id: UuidSchema,
    access_reason: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type AgentRunContextInput = Static<typeof AgentRunContextInputSchema>;

export const AgentRunCreateSchema = Type.Object(
  {
    agent_type: Type.String({ minLength: 1 }),
    purpose: Type.String({ minLength: 1 }),
    instructions: Type.String({ minLength: 1 }),
    context: Type.Array(AgentRunContextInputSchema, { minItems: 1, uniqueItems: true }),
  },
  { additionalProperties: false },
);
export type AgentRunCreate = Static<typeof AgentRunCreateSchema>;

export const AgentRunStatusSchema = Type.Union([
  Type.Literal('queued'),
  Type.Literal('running'),
  Type.Literal('completed'),
  Type.Literal('failed'),
  Type.Literal('cancelled'),
  Type.Literal('awaiting_user_confirmation'),
]);
export type AgentRunStatus = Static<typeof AgentRunStatusSchema>;

export const AgentRunSchema = Type.Object(
  {
    id: UuidSchema,
    task_id: UuidSchema,
    project_id: UuidSchema,
    agent_type: Type.String({ minLength: 1 }),
    provider: Type.String({ minLength: 1 }),
    model: Type.Union([Type.Null(), Type.String()]),
    purpose: Type.String({ minLength: 1 }),
    status: AgentRunStatusSchema,
    requested_by_user_id: UuidSchema,
    provider_data_profile_version: Type.Union([Type.Null(), Type.String()]),
    deployment_class: DeploymentClassSchema,
    context_set_hash: Type.Union([
      Type.Null(),
      Type.String({ pattern: '^sha256:[0-9a-f]{64}$' }),
    ]),
    origin_request_id: UuidSchema,
    request_fingerprint: Type.Union([
      Type.Null(),
      Type.String({ pattern: '^sha256:[0-9a-f]{64}$' }),
    ]),
    dispatched_at: Type.Union([Type.Null(), TimestampSchema]),
    deadline_at: Type.Union([Type.Null(), TimestampSchema]),
    created_at: TimestampSchema,
    started_at: Type.Union([Type.Null(), TimestampSchema]),
    finished_at: Type.Union([Type.Null(), TimestampSchema]),
    error_message: Type.Union([Type.Null(), Type.String()]),
  },
  { additionalProperties: false },
);
export type AgentRun = Static<typeof AgentRunSchema>;

export interface FrozenContextDescriptor extends AgentRunContextInput {
  position: number;
  fileName: string;
  mediaType: string;
  sizeBytes: number;
  contentHash: string;
  sensitivityLevel: SensitivityLevel;
}
