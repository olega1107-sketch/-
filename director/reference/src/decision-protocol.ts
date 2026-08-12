import { Type, type Static } from '@sinclair/typebox';

import {
  RelationshipEndpointTypeSchema,
  RelationshipRefSchema,
  RelationshipTypeSchema,
} from './agent-result-protocol.js';
import { MemoryObjectTypeSchema } from './public-protocol.js';
import {
  DeploymentClassSchema,
  NullableStringSchema,
  SensitivityLevelSchema,
  Sha256Schema,
  TimestampSchema,
  UuidSchema,
} from './protocol.js';
import { AgentRunStatusSchema } from './task-protocol.js';

export const DecisionStatusSchema = Type.Union([
  Type.Literal('draft'),
  Type.Literal('proposed'),
  Type.Literal('approved'),
  Type.Literal('rejected'),
  Type.Literal('superseded'),
]);
export type DecisionStatus = Static<typeof DecisionStatusSchema>;

export const PilotDecisionCreateStatusSchema = Type.Union([
  Type.Literal('draft'),
  Type.Literal('proposed'),
]);
export type PilotDecisionCreateStatus = Static<typeof PilotDecisionCreateStatusSchema>;

export const DecisionCreateSchema = Type.Object(
  {
    project_id: UuidSchema,
    topic_id: Type.Optional(Type.Union([Type.Null(), UuidSchema])),
    title: Type.String({ minLength: 1 }),
    decision_text: Type.String({ minLength: 1 }),
    rationale: Type.Optional(NullableStringSchema),
    status: Type.Optional(PilotDecisionCreateStatusSchema),
    sensitivity_level: Type.Optional(SensitivityLevelSchema),
    relationships: Type.Optional(
      Type.Array(RelationshipRefSchema, { uniqueItems: true, maxItems: 100 }),
    ),
  },
  { additionalProperties: false },
);
export type DecisionCreate = Static<typeof DecisionCreateSchema>;

export const DecisionSchema = Type.Object(
  {
    id: UuidSchema,
    memory_object_id: UuidSchema,
    project_id: UuidSchema,
    topic_id: Type.Union([Type.Null(), UuidSchema]),
    title: Type.String({ minLength: 1 }),
    decision_text: Type.String({ minLength: 1 }),
    rationale: NullableStringSchema,
    status: DecisionStatusSchema,
    supersedes_decision_id: Type.Union([Type.Null(), UuidSchema]),
    decided_by_user_id: Type.Union([Type.Null(), UuidSchema]),
    decided_at: Type.Union([Type.Null(), TimestampSchema]),
    sensitivity_level: SensitivityLevelSchema,
    created_at: TimestampSchema,
    updated_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type Decision = Static<typeof DecisionSchema>;

export const DecisionIdParamsSchema = Type.Object(
  { decision_id: UuidSchema },
  { additionalProperties: false },
);

export const DecisionRelationshipSchema = Type.Object(
  {
    id: UuidSchema,
    source_type: RelationshipEndpointTypeSchema,
    source_id: UuidSchema,
    target_type: RelationshipEndpointTypeSchema,
    target_id: UuidSchema,
    relation_type: RelationshipTypeSchema,
    description: NullableStringSchema,
    created_by_user_id: UuidSchema,
    created_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type DecisionRelationship = Static<typeof DecisionRelationshipSchema>;

export const DecisionRelatedMemoryObjectSchema = Type.Object(
  {
    id: UuidSchema,
    type: MemoryObjectTypeSchema,
    title: Type.String({ minLength: 1 }),
    current_version_id: Type.Union([Type.Null(), UuidSchema]),
    sensitivity_level: SensitivityLevelSchema,
  },
  { additionalProperties: false },
);
export type DecisionRelatedMemoryObject = Static<
  typeof DecisionRelatedMemoryObjectSchema
>;

export const DecisionProvenanceAgentRunSchema = Type.Object(
  {
    id: UuidSchema,
    task_id: UuidSchema,
    agent_type: Type.String({ minLength: 1 }),
    provider: Type.String({ minLength: 1 }),
    model: NullableStringSchema,
    status: AgentRunStatusSchema,
    deployment_class: DeploymentClassSchema,
    context_set_hash: Type.Union([Type.Null(), Sha256Schema]),
    result_memory_object_id: Type.Union([Type.Null(), UuidSchema]),
    requested_by_user_id: UuidSchema,
    origin_request_id: UuidSchema,
    created_at: TimestampSchema,
    dispatched_at: Type.Union([Type.Null(), TimestampSchema]),
    started_at: Type.Union([Type.Null(), TimestampSchema]),
    finished_at: Type.Union([Type.Null(), TimestampSchema]),
  },
  { additionalProperties: false },
);
export type DecisionProvenanceAgentRun = Static<
  typeof DecisionProvenanceAgentRunSchema
>;

export const DecisionSourceVersionSchema = Type.Object(
  {
    agent_run_id: UuidSchema,
    position: Type.Integer({ minimum: 1 }),
    memory_object_id: UuidSchema,
    memory_object_title: Type.String({ minLength: 1 }),
    document_version_id: UuidSchema,
    version_number: Type.Integer({ minimum: 1 }),
    file_name: Type.String({ minLength: 1 }),
    file_type: Type.String({ minLength: 1 }),
    content_hash: Sha256Schema,
    size_bytes: Type.Integer({ minimum: 0 }),
    access_reason: Type.String({ minLength: 1 }),
    frozen_sensitivity_level: SensitivityLevelSchema,
    current_sensitivity_level: SensitivityLevelSchema,
  },
  { additionalProperties: false },
);
export type DecisionSourceVersion = Static<typeof DecisionSourceVersionSchema>;

export const DecisionAuditEventSchema = Type.Object(
  {
    id: UuidSchema,
    actor_type: Type.String({ minLength: 1 }),
    actor_id: Type.Union([Type.Null(), UuidSchema]),
    action: Type.String({ minLength: 1 }),
    target_type: Type.String({ minLength: 1 }),
    target_id: UuidSchema,
    request_id: UuidSchema,
    created_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type DecisionAuditEvent = Static<typeof DecisionAuditEventSchema>;

export const DecisionProvenanceSchema = Type.Object(
  {
    decision: DecisionSchema,
    provenance_complete: Type.Literal(true),
    relationships: Type.Array(DecisionRelationshipSchema),
    related_memory_objects: Type.Array(DecisionRelatedMemoryObjectSchema),
    agent_runs: Type.Array(DecisionProvenanceAgentRunSchema),
    source_versions: Type.Array(DecisionSourceVersionSchema),
    audit_events: Type.Array(DecisionAuditEventSchema),
  },
  { additionalProperties: false },
);
export type DecisionProvenance = Static<typeof DecisionProvenanceSchema>;
