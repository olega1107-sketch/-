import { Type, type Static } from '@sinclair/typebox';

import { Sha256Schema, TimestampSchema, UuidSchema } from './protocol.js';

export const ConfirmationOperationSchema = Type.Union([
  Type.Literal('agent_context_share'),
  Type.Literal('bulk_context_share'),
  Type.Literal('ai_result_save'),
  Type.Literal('decision_approve'),
  Type.Literal('decision_supersede'),
  Type.Literal('sensitivity_lower'),
  Type.Literal('break_glass_project_recovery'),
]);
export type ConfirmationOperation = Static<typeof ConfirmationOperationSchema>;

export const ConfirmationStatusSchema = Type.Union([
  Type.Literal('pending'),
  Type.Literal('approved'),
  Type.Literal('rejected'),
  Type.Literal('expired'),
  Type.Literal('consumed'),
  Type.Literal('revoked'),
]);
export type ConfirmationStatus = Static<typeof ConfirmationStatusSchema>;

export const ConfirmationSchema = Type.Object(
  {
    id: UuidSchema,
    operation: ConfirmationOperationSchema,
    target_type: Type.String({ minLength: 1 }),
    target_id: UuidSchema,
    project_id: UuidSchema,
    requested_by_user_id: UuidSchema,
    decided_by_user_id: Type.Union([Type.Null(), UuidSchema]),
    authorization_decision_id: UuidSchema,
    request_id: UuidSchema,
    status: ConfirmationStatusSchema,
    payload_hash: Sha256Schema,
    summary: Type.String({ minLength: 1 }),
    created_at: TimestampSchema,
    expires_at: TimestampSchema,
    decided_at: Type.Union([Type.Null(), TimestampSchema]),
    consumed_at: Type.Union([Type.Null(), TimestampSchema]),
  },
  { additionalProperties: false },
);
export type Confirmation = Static<typeof ConfirmationSchema>;

export const ConfirmationListQuerySchema = Type.Object(
  {
    project_id: UuidSchema,
    status: Type.Optional(ConfirmationStatusSchema),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, default: 50 })),
    cursor: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type ConfirmationListQuery = Static<typeof ConfirmationListQuerySchema>;

export const ConfirmationPageSchema = Type.Object(
  {
    items: Type.Array(ConfirmationSchema),
    next_cursor: Type.Union([Type.Null(), Type.String({ minLength: 1 })]),
  },
  { additionalProperties: false },
);
export type ConfirmationPage = Static<typeof ConfirmationPageSchema>;

export const ConfirmationIdParamsSchema = Type.Object(
  { confirmation_id: UuidSchema },
  { additionalProperties: false },
);

export const RequiresConfirmationDetailsSchema = Type.Object(
  {
    confirmation_id: UuidSchema,
    target_type: Type.String({ minLength: 1 }),
    target_id: UuidSchema,
    payload_hash: Sha256Schema,
    expires_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type RequiresConfirmationDetails = Static<typeof RequiresConfirmationDetailsSchema>;
