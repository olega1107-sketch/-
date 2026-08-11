import { Type, type Static } from '@sinclair/typebox';

import {
  NullableStringSchema,
  SensitivityLevelSchema,
  Sha256Schema,
  TimestampSchema,
  UuidSchema,
} from './protocol.js';

export const RelationshipEndpointTypeSchema = Type.Union([
  Type.Literal('memory_object'),
  Type.Literal('decision'),
  Type.Literal('open_question'),
  Type.Literal('task'),
  Type.Literal('agent_run'),
]);
export type RelationshipEndpointType = Static<typeof RelationshipEndpointTypeSchema>;

export const RelationshipTypeSchema = Type.Union([
  Type.Literal('references'),
  Type.Literal('depends_on'),
  Type.Literal('contradicts'),
  Type.Literal('supersedes'),
  Type.Literal('explains'),
  Type.Literal('implements'),
  Type.Literal('belongs_to'),
  Type.Literal('derived_from'),
]);
export type RelationshipType = Static<typeof RelationshipTypeSchema>;

export const RelationshipRefSchema = Type.Object(
  {
    target_type: RelationshipEndpointTypeSchema,
    target_id: UuidSchema,
    relation_type: RelationshipTypeSchema,
    description: Type.Optional(NullableStringSchema),
  },
  { additionalProperties: false },
);
export type RelationshipRef = Static<typeof RelationshipRefSchema>;

export const AgentResultSaveRequestSchema = Type.Object(
  {
    title: Type.String({ minLength: 1 }),
    summary: Type.Optional(NullableStringSchema),
    topic_id: Type.Optional(Type.Union([Type.Null(), UuidSchema])),
    keywords: Type.Optional(
      Type.Array(Type.String({ minLength: 1 }), { uniqueItems: true, default: [] }),
    ),
    relationships: Type.Optional(
      Type.Array(RelationshipRefSchema, { uniqueItems: true, default: [] }),
    ),
  },
  { additionalProperties: false },
);
export type AgentResultSaveRequest = Static<typeof AgentResultSaveRequestSchema>;

export const AgentRunResultSchema = Type.Object(
  {
    id: UuidSchema,
    agent_run_id: UuidSchema,
    project_id: UuidSchema,
    content: Type.String(),
    content_type: Type.String({ minLength: 1 }),
    content_hash: Sha256Schema,
    sensitivity_level: SensitivityLevelSchema,
    output_summary: NullableStringSchema,
    created_at: TimestampSchema,
    expires_at: Type.Union([Type.Null(), TimestampSchema]),
    saved_memory_object_id: Type.Union([Type.Null(), UuidSchema]),
    saved_at: Type.Union([Type.Null(), TimestampSchema]),
  },
  { additionalProperties: false },
);
export type AgentRunResult = Static<typeof AgentRunResultSchema>;

export const AiResultSaveConfirmationPayloadSchema = Type.Object(
  {
    version: Type.Literal(1),
    operation: Type.Literal('ai_result_save'),
    result: Type.Object(
      {
        id: UuidSchema,
        agent_run_id: UuidSchema,
        task_id: UuidSchema,
        project_id: UuidSchema,
        output_storage_uri: Type.String({ minLength: 1 }),
        content_hash: Sha256Schema,
        size_bytes: Type.Integer({ minimum: 0 }),
        content_type: Type.String({ minLength: 1 }),
        sensitivity_level: SensitivityLevelSchema,
      },
      { additionalProperties: false },
    ),
    save_sensitivity_level: SensitivityLevelSchema,
    requested_by_user_id: UuidSchema,
    input: Type.Object(
      {
        title: Type.String({ minLength: 1 }),
        summary: NullableStringSchema,
        topic_id: Type.Union([Type.Null(), UuidSchema]),
        keywords: Type.Array(Type.String({ minLength: 1 }), { uniqueItems: true }),
        relationships: Type.Array(RelationshipRefSchema, { uniqueItems: true }),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
export type AiResultSaveConfirmationPayload = Static<
  typeof AiResultSaveConfirmationPayloadSchema
>;
