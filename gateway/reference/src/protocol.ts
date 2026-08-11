import { Type, type Static } from '@sinclair/typebox';

const UUID_PATTERN =
  '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$';
const SHA256_PATTERN = '^sha256:[0-9a-f]{64}$';

export const UuidSchema = Type.String({ pattern: UUID_PATTERN });
export const TimestampSchema = Type.String({ minLength: 1 });
export const Sha256Schema = Type.String({ pattern: SHA256_PATTERN });
export const ProtocolVersionSchema = Type.Literal('1.0');
export const SensitivityLevelSchema = Type.Union([
  Type.Literal('public'),
  Type.Literal('internal'),
  Type.Literal('confidential'),
  Type.Literal('restricted'),
]);
export const DeploymentClassSchema = Type.Union([
  Type.Literal('internal'),
  Type.Literal('external'),
]);
// AJV evaluates unions in order; null must come first to prevent null -> "" coercion.
export const NullableStringSchema = Type.Union([Type.Null(), Type.String()]);

export const AgentExecutionRequestSchema = Type.Object(
  {
    protocol_version: ProtocolVersionSchema,
    project_id: UuidSchema,
    task_id: UuidSchema,
    origin_request_id: UuidSchema,
    request_fingerprint: Sha256Schema,
    agent_type: Type.String({ minLength: 1 }),
    provider: Type.String({ minLength: 1 }),
    model: Type.Optional(NullableStringSchema),
    purpose: Type.String({ minLength: 1 }),
    instructions: Type.String({ minLength: 1 }),
    deployment_class: DeploymentClassSchema,
    provider_data_profile_version: Type.Optional(NullableStringSchema),
    context_set_hash: Sha256Schema,
    context_item_count: Type.Integer({ minimum: 1 }),
    max_context_sensitivity: SensitivityLevelSchema,
    dispatched_at: TimestampSchema,
    deadline_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type AgentExecutionRequest = Static<typeof AgentExecutionRequestSchema>;

export const CancellationReasonCodeSchema = Type.Union([
  Type.Literal('user_requested'),
  Type.Literal('task_cancelled'),
  Type.Literal('authorization_revoked'),
  Type.Literal('deadline_exceeded'),
  Type.Literal('service_shutdown'),
]);
export type CancellationReasonCode = Static<typeof CancellationReasonCodeSchema>;

export const AgentCancellationRequestSchema = Type.Object(
  {
    protocol_version: ProtocolVersionSchema,
    reason_code: CancellationReasonCodeSchema,
    reason: Type.Optional(Type.Union([Type.Null(), Type.String({ maxLength: 500 })])),
    requested_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type AgentCancellationRequest = Static<typeof AgentCancellationRequestSchema>;

export const ContextBundleRedeemRequestSchema = Type.Object(
  {
    protocol_version: ProtocolVersionSchema,
    request_fingerprint: Sha256Schema,
    expected_context_set_hash: Sha256Schema,
  },
  { additionalProperties: false },
);
export type ContextBundleRedeemRequest = Static<typeof ContextBundleRedeemRequestSchema>;

export const ContextItemSchema = Type.Object(
  {
    position: Type.Integer({ minimum: 1 }),
    memory_object_id: UuidSchema,
    document_version_id: UuidSchema,
    file_name: Type.String({ minLength: 1 }),
    media_type: Type.String({ minLength: 1 }),
    size_bytes: Type.Integer({ minimum: 0 }),
    content_encoding: Type.Union([Type.Literal('utf-8'), Type.Literal('base64')]),
    content: Type.String(),
    content_hash: Sha256Schema,
    sensitivity_level: SensitivityLevelSchema,
    access_reason: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type ContextItem = Static<typeof ContextItemSchema>;

export const ContextBundleSchema = Type.Object(
  {
    protocol_version: ProtocolVersionSchema,
    agent_run_id: UuidSchema,
    project_id: UuidSchema,
    request_fingerprint: Sha256Schema,
    context_set_hash: Sha256Schema,
    item_count: Type.Integer({ minimum: 1 }),
    max_sensitivity_level: SensitivityLevelSchema,
    items: Type.Array(ContextItemSchema, { minItems: 1 }),
    assembled_at: TimestampSchema,
    expires_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type ContextBundle = Static<typeof ContextBundleSchema>;

export const AgentRunIdParamsSchema = Type.Object(
  { agent_run_id: UuidSchema },
  { additionalProperties: false },
);
export type AgentRunIdParams = Static<typeof AgentRunIdParamsSchema>;

export const ExecuteHeadersSchema = Type.Object(
  {
    'x-request-id': Type.Optional(UuidSchema),
    'idempotency-key': UuidSchema,
    'x-agent-capability': Type.String({ minLength: 1 }),
    authorization: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: true },
);
export type ExecuteHeaders = Static<typeof ExecuteHeadersSchema>;

export const CancelHeadersSchema = Type.Object(
  {
    'x-request-id': Type.Optional(UuidSchema),
    'idempotency-key': UuidSchema,
    authorization: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: true },
);
export type CancelHeaders = Static<typeof CancelHeadersSchema>;

export const AgentExecutionReceiptSchema = Type.Object(
  {
    protocol_version: ProtocolVersionSchema,
    agent_run_id: UuidSchema,
    request_fingerprint: Sha256Schema,
    gateway_state: Type.Union([
      Type.Literal('accepted'),
      Type.Literal('already_accepted'),
      Type.Literal('started'),
      Type.Literal('terminal'),
    ]),
    accepted_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type AgentExecutionReceipt = Static<typeof AgentExecutionReceiptSchema>;

export const AgentCancellationReceiptSchema = Type.Object(
  {
    protocol_version: ProtocolVersionSchema,
    agent_run_id: UuidSchema,
    gateway_state: Type.Union([
      Type.Literal('accepted'),
      Type.Literal('already_cancelled'),
      Type.Literal('terminal'),
    ]),
    accepted_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type AgentCancellationReceipt = Static<typeof AgentCancellationReceiptSchema>;

export const ProtocolErrorResponseSchema = Type.Object(
  {
    error: Type.Object(
      {
        code: Type.String({ minLength: 1 }),
        message: Type.String({ minLength: 1 }),
        retryable: Type.Boolean(),
        details: Type.Record(Type.String(), Type.Unknown()),
      },
      { additionalProperties: false },
    ),
    request_id: UuidSchema,
  },
  { additionalProperties: false },
);
export type ProtocolErrorResponse = Static<typeof ProtocolErrorResponseSchema>;

export type SensitivityLevel = Static<typeof SensitivityLevelSchema>;
export type FinishReason = 'stop' | 'length' | 'content_filter' | 'other';
export type FailurePhase = 'admission' | 'context' | 'provider' | 'normalization' | 'delivery';
export type GatewayFailureCode =
  | 'capability_invalid'
  | 'capability_expired'
  | 'capability_used'
  | 'context_hash_mismatch'
  | 'context_too_large'
  | 'unsupported_agent'
  | 'unsupported_provider'
  | 'policy_violation'
  | 'provider_rate_limited'
  | 'provider_timeout'
  | 'provider_unavailable'
  | 'provider_rejected'
  | 'provider_outcome_unknown'
  | 'unsupported_tool_call'
  | 'output_too_large'
  | 'normalization_failed'
  | 'internal_error';

export interface GatewayEventBase {
  protocol_version: '1.0';
  event_id: string;
  event_type:
    | 'agent_run.started'
    | 'agent_run.completed'
    | 'agent_run.failed'
    | 'agent_run.cancelled';
  event_hash: string;
  agent_run_id: string;
  project_id: string;
  origin_request_id: string;
  request_fingerprint: string;
  occurred_at: string;
}

export interface AgentRunStartedEvent extends GatewayEventBase {
  event_type: 'agent_run.started';
  provider: string;
  model: string | null;
  adapter_version: string;
  context_set_hash: string;
}

export interface ProviderUsage {
  input_tokens?: number;
  output_tokens?: number;
}

export interface GatewayResult {
  content: string;
  content_type: 'text/plain' | 'text/markdown' | 'application/json';
  content_hash: string;
  size_bytes: number;
  output_summary?: string | null;
  sensitivity_level: SensitivityLevel;
  finish_reason: FinishReason;
  usage?: ProviderUsage;
}

export interface AgentRunCompletedEvent extends GatewayEventBase {
  event_type: 'agent_run.completed';
  provider: string;
  model: string | null;
  adapter_version: string;
  provider_request_id: string | null;
  result: GatewayResult;
}

export interface GatewayFailure {
  code: GatewayFailureCode;
  phase: FailurePhase;
  message: string;
  retryable: boolean;
  provider_status?: number | null;
  retry_after_seconds?: number | null;
}

export interface AgentRunFailedEvent extends GatewayEventBase {
  event_type: 'agent_run.failed';
  provider: string | null;
  model: string | null;
  adapter_version: string | null;
  provider_request_id: string | null;
  failure: GatewayFailure;
}

export interface AgentRunCancelledEvent extends GatewayEventBase {
  event_type: 'agent_run.cancelled';
  reason_code: CancellationReasonCode;
  provider_request_id: string | null;
}

export type GatewayEvent =
  | AgentRunStartedEvent
  | AgentRunCompletedEvent
  | AgentRunFailedEvent
  | AgentRunCancelledEvent;
