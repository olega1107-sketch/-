import { Type, type Static } from '@sinclair/typebox';

import {
  NullableStringSchema,
  SensitivityLevelSchema,
  TimestampSchema,
  UuidSchema,
} from './protocol.js';

export const UploadMemoryObjectTypeSchema = Type.Union([
  Type.Literal('document'),
  Type.Literal('protocol'),
  Type.Literal('research_result'),
]);
export type UploadMemoryObjectType = Static<typeof UploadMemoryObjectTypeSchema>;

export const MemoryObjectTypeSchema = Type.Union([
  Type.Literal('document'),
  Type.Literal('protocol'),
  Type.Literal('decision'),
  Type.Literal('research_result'),
  Type.Literal('open_question'),
  Type.Literal('ai_result'),
  Type.Literal('note'),
]);
export type MemoryObjectType = Static<typeof MemoryObjectTypeSchema>;

export const MemoryObjectStatusSchema = Type.Union([
  Type.Literal('active'),
  Type.Literal('archived'),
]);
export type MemoryObjectStatus = Static<typeof MemoryObjectStatusSchema>;

export const ProjectStatusSchema = Type.Union([
  Type.Literal('active'),
  Type.Literal('archived'),
]);
export type ProjectStatus = Static<typeof ProjectStatusSchema>;

export const ProjectSchema = Type.Object(
  {
    id: UuidSchema,
    title: Type.String({ minLength: 1 }),
    description: NullableStringSchema,
    status: ProjectStatusSchema,
    owner_user_id: UuidSchema,
    created_at: TimestampSchema,
    updated_at: TimestampSchema,
    archived_at: Type.Union([Type.Null(), TimestampSchema]),
  },
  { additionalProperties: false },
);
export type Project = Static<typeof ProjectSchema>;

export const ProjectListQuerySchema = Type.Object(
  {
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, default: 50 })),
    cursor: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type ProjectListQuery = Static<typeof ProjectListQuerySchema>;

export const ProjectPageSchema = Type.Object(
  {
    items: Type.Array(ProjectSchema),
    next_cursor: Type.Union([Type.Null(), Type.String({ minLength: 1 })]),
  },
  { additionalProperties: false },
);
export type ProjectPage = Static<typeof ProjectPageSchema>;

export const PublicRequestHeadersSchema = Type.Object(
  {
    'x-request-id': UuidSchema,
    authorization: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: true },
);

export const MemoryUploadMetadataSchema = Type.Object(
  {
    project_id: UuidSchema,
    topic_id: Type.Union([Type.Null(), UuidSchema]),
    type: UploadMemoryObjectTypeSchema,
    title: Type.String({ minLength: 1 }),
    summary: NullableStringSchema,
    keywords: Type.Array(Type.String({ minLength: 1 }), { uniqueItems: true }),
    sensitivity_level: SensitivityLevelSchema,
  },
  { additionalProperties: false },
);
export type MemoryUploadMetadata = Static<typeof MemoryUploadMetadataSchema>;

export const DocumentVersionSchema = Type.Object(
  {
    id: UuidSchema,
    memory_object_id: UuidSchema,
    version_number: Type.Integer({ minimum: 1 }),
    file_name: Type.String({ minLength: 1 }),
    file_type: Type.String({ minLength: 1 }),
    content_hash: Type.String({ pattern: '^sha256:[0-9a-f]{64}$' }),
    size_bytes: Type.Integer({ minimum: 0 }),
    created_by_user_id: UuidSchema,
    created_at: TimestampSchema,
    change_summary: NullableStringSchema,
  },
  { additionalProperties: false },
);
export type DocumentVersion = Static<typeof DocumentVersionSchema>;

export const MemoryObjectSchema = Type.Object(
  {
    id: UuidSchema,
    type: MemoryObjectTypeSchema,
    title: Type.String({ minLength: 1 }),
    project_id: UuidSchema,
    topic_id: Type.Union([Type.Null(), UuidSchema]),
    current_version_id: Type.Union([Type.Null(), UuidSchema]),
    current_version: Type.Optional(Type.Union([Type.Null(), DocumentVersionSchema])),
    author_user_id: UuidSchema,
    summary: NullableStringSchema,
    keywords: Type.Array(Type.String()),
    status: MemoryObjectStatusSchema,
    sensitivity_level: SensitivityLevelSchema,
    created_at: TimestampSchema,
    updated_at: TimestampSchema,
    archived_at: Type.Union([Type.Null(), TimestampSchema]),
  },
  { additionalProperties: false },
);
export type MemoryObject = Static<typeof MemoryObjectSchema>;

export const MemoryObjectIdParamsSchema = Type.Object(
  { memory_object_id: UuidSchema },
  { additionalProperties: false },
);

export const MemoryObjectSearchQuerySchema = Type.Object(
  {
    project_id: UuidSchema,
    q: Type.String({ minLength: 1 }),
    type: Type.Optional(MemoryObjectTypeSchema),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, default: 50 })),
    cursor: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type MemoryObjectSearchQuery = Static<typeof MemoryObjectSearchQuerySchema>;

export const MemoryObjectSummarySchema = Type.Object(
  {
    id: UuidSchema,
    type: MemoryObjectTypeSchema,
    title: Type.String({ minLength: 1 }),
    project_id: UuidSchema,
    topic_id: Type.Union([Type.Null(), UuidSchema]),
    summary: NullableStringSchema,
    keywords: Type.Array(Type.String()),
    status: MemoryObjectStatusSchema,
    sensitivity_level: SensitivityLevelSchema,
    updated_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type MemoryObjectSummary = Static<typeof MemoryObjectSummarySchema>;

export const MemoryObjectPageSchema = Type.Object(
  {
    items: Type.Array(MemoryObjectSummarySchema),
    next_cursor: Type.Union([Type.Null(), Type.String({ minLength: 1 })]),
  },
  { additionalProperties: false },
);
export type MemoryObjectPage = Static<typeof MemoryObjectPageSchema>;

export const PublicErrorResponseSchema = Type.Object(
  {
    error: Type.Object(
      {
        code: Type.String({ minLength: 1 }),
        message: Type.String({ minLength: 1 }),
        details: Type.Record(Type.String(), Type.Unknown()),
        request_id: UuidSchema,
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
