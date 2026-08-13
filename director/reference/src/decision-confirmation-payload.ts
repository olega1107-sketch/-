import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

import { RelationshipRefSchema } from './agent-result-protocol.js';
import { hashCanonical } from './canonical.js';
import { SensitivityLevelSchema, UuidSchema } from './protocol.js';

const FrozenDecisionSchema = Type.Object(
  {
    id: UuidSchema,
    memory_object_id: UuidSchema,
    project_id: UuidSchema,
    topic_id: Type.Union([Type.Null(), UuidSchema]),
    title: Type.String({ minLength: 1 }),
    decision_text: Type.String({ minLength: 1 }),
    rationale: Type.Union([Type.Null(), Type.String()]),
    sensitivity_level: SensitivityLevelSchema,
    relationships: Type.Array(RelationshipRefSchema, { maxItems: 101 }),
  },
  { additionalProperties: false },
);
export type FrozenDecision = Static<typeof FrozenDecisionSchema>;

export const DecisionConfirmationPayloadSchema = Type.Object(
  {
    version: Type.Literal(1),
    operation: Type.Union([
      Type.Literal('decision_approve'),
      Type.Literal('decision_supersede'),
    ]),
    requested_by_user_id: UuidSchema,
    target_decision_id: UuidSchema,
    decision: FrozenDecisionSchema,
  },
  { additionalProperties: false },
);
export type DecisionConfirmationPayload = Static<
  typeof DecisionConfirmationPayloadSchema
>;

export function buildDecisionConfirmationPayload(input: {
  operation: DecisionConfirmationPayload['operation'];
  requestedByUserId: string;
  targetDecisionId: string;
  decision: FrozenDecision;
}): DecisionConfirmationPayload {
  return {
    version: 1,
    operation: input.operation,
    requested_by_user_id: input.requestedByUserId,
    target_decision_id: input.targetDecisionId,
    decision: {
      ...input.decision,
      relationships: sortedRelationships(input.decision.relationships),
    },
  };
}

export function computeDecisionConfirmationPayloadHash(
  payload: DecisionConfirmationPayload,
): string {
  return hashCanonical(payload);
}

export function validatedDecisionConfirmationPayload(
  value: unknown,
): DecisionConfirmationPayload | undefined {
  return Value.Check(DecisionConfirmationPayloadSchema, value)
    ? (value as DecisionConfirmationPayload)
    : undefined;
}

function sortedRelationships(
  relationships: FrozenDecision['relationships'],
): FrozenDecision['relationships'] {
  return [...relationships].sort((left, right) =>
    relationshipKey(left).localeCompare(relationshipKey(right)),
  );
}

function relationshipKey(relationship: FrozenDecision['relationships'][number]): string {
  return JSON.stringify([
    relationship.target_type,
    relationship.target_id,
    relationship.relation_type,
    relationship.description ?? null,
  ]);
}
