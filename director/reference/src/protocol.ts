import { Type, type Static } from '@sinclair/typebox';

const UUID_PATTERN =
  '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$';
const SHA256_PATTERN = '^sha256:[0-9a-f]{64}$';

export const UuidSchema = Type.String({ pattern: UUID_PATTERN });
export const TimestampSchema = Type.String({ minLength: 1 });
export const Sha256Schema = Type.String({ pattern: SHA256_PATTERN });
export const ProtocolVersionSchema = Type.Literal('1.0');
export const NullableStringSchema = Type.Union([Type.Null(), Type.String()]);
export const SensitivityLevelSchema = Type.Union([
  Type.Literal('public'),
  Type.Literal('internal'),
  Type.Literal('confidential'),
  Type.Literal('restricted'),
]);
export type SensitivityLevel = Static<typeof SensitivityLevelSchema>;

export const DeploymentClassSchema = Type.Union([
  Type.Literal('internal'),
  Type.Literal('external'),
]);
export type DeploymentClass = Static<typeof DeploymentClassSchema>;

export const AgentExecutionRequestSchema = Type.Object(
  {
    protocol_version: ProtocolVersionSchema,
    project_id: UuidSchema,
    task_id: UuidSchema,
    origin_request_id: UuidSchema,
    request_fingerprint: Sha256Schema,
    agent_type: Type.String({ minLength: 1 }),
    provider: Type.String({ minLength: 1 }),
    model: NullableStringSchema,
    purpose: Type.String({ minLength: 1 }),
    instructions: Type.String({ minLength: 1 }),
    deployment_class: DeploymentClassSchema,
    provider_data_profile_version: NullableStringSchema,
    context_set_hash: Sha256Schema,
    context_item_count: Type.Integer({ minimum: 1 }),
    max_context_sensitivity: SensitivityLevelSchema,
    dispatched_at: TimestampSchema,
    deadline_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type AgentExecutionRequest = Static<typeof AgentExecutionRequestSchema>;

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

export const AgentRunIdParamsSchema = Type.Object(
  { agent_run_id: UuidSchema },
  { additionalProperties: false },
);

export const RedeemHeadersSchema = Type.Object(
  {
    'x-request-id': Type.Optional(UuidSchema),
    'x-agent-capability': Type.String({ minLength: 1 }),
    authorization: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: true },
);

export const EventHeadersSchema = Type.Object(
  {
    'x-request-id': Type.Optional(UuidSchema),
    authorization: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: true },
);

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

const eventBaseProperties = {
  protocol_version: ProtocolVersionSchema,
  event_id: UuidSchema,
  event_hash: Sha256Schema,
  agent_run_id: UuidSchema,
  project_id: UuidSchema,
  origin_request_id: UuidSchema,
  request_fingerprint: Sha256Schema,
  occurred_at: TimestampSchema,
};

export const AgentRunStartedEventSchema = Type.Object(
  {
    ...eventBaseProperties,
    event_type: Type.Literal('agent_run.started'),
    provider: Type.String({ minLength: 1 }),
    model: Type.Optional(NullableStringSchema),
    adapter_version: Type.String({ minLength: 1 }),
    context_set_hash: Sha256Schema,
  },
  { additionalProperties: false },
);
export type AgentRunStartedEvent = Static<typeof AgentRunStartedEventSchema>;

export const ProviderUsageSchema = Type.Object(
  {
    input_tokens: Type.Optional(Type.Integer({ minimum: 0 })),
    output_tokens: Type.Optional(Type.Integer({ minimum: 0 })),
  },
  { additionalProperties: false },
);

export const GatewayResultSchema = Type.Object(
  {
    content: Type.String(),
    content_type: Type.Union([
      Type.Literal('text/plain'),
      Type.Literal('text/markdown'),
      Type.Literal('application/json'),
    ]),
    content_hash: Sha256Schema,
    size_bytes: Type.Integer({ minimum: 0 }),
    output_summary: Type.Optional(NullableStringSchema),
    sensitivity_level: SensitivityLevelSchema,
    finish_reason: Type.Union([
      Type.Literal('stop'),
      Type.Literal('length'),
      Type.Literal('content_filter'),
      Type.Literal('other'),
    ]),
    usage: Type.Optional(ProviderUsageSchema),
  },
  { additionalProperties: false },
);
export type GatewayResult = Static<typeof GatewayResultSchema>;

export const AgentRunCompletedEventSchema = Type.Object(
  {
    ...eventBaseProperties,
    event_type: Type.Literal('agent_run.completed'),
    provider: Type.String({ minLength: 1 }),
    model: Type.Optional(NullableStringSchema),
    adapter_version: Type.String({ minLength: 1 }),
    provider_request_id: NullableStringSchema,
    result: GatewayResultSchema,
  },
  { additionalProperties: false },
);
export type AgentRunCompletedEvent = Static<typeof AgentRunCompletedEventSchema>;

export const GatewayFailureCodeSchema = Type.Union([
  Type.Literal('capability_invalid'),
  Type.Literal('capability_expired'),
  Type.Literal('capability_used'),
  Type.Literal('context_hash_mismatch'),
  Type.Literal('context_too_large'),
  Type.Literal('unsupported_agent'),
  Type.Literal('unsupported_provider'),
  Type.Literal('policy_violation'),
  Type.Literal('provider_rate_limited'),
  Type.Literal('provider_timeout'),
  Type.Literal('provider_unavailable'),
  Type.Literal('provider_rejected'),
  Type.Literal('provider_outcome_unknown'),
  Type.Literal('unsupported_tool_call'),
  Type.Literal('output_too_large'),
  Type.Literal('normalization_failed'),
  Type.Literal('internal_error'),
]);

export const GatewayFailureSchema = Type.Object(
  {
    code: GatewayFailureCodeSchema,
    phase: Type.Union([
      Type.Literal('admission'),
      Type.Literal('context'),
      Type.Literal('provider'),
      Type.Literal('normalization'),
      Type.Literal('delivery'),
    ]),
    message: Type.String({ minLength: 1 }),
    retryable: Type.Boolean(),
    provider_status: Type.Optional(Type.Union([Type.Null(), Type.Integer({ minimum: 100, maximum: 599 })])),
    retry_after_seconds: Type.Optional(Type.Union([Type.Null(), Type.Integer({ minimum: 1 })])),
  },
  { additionalProperties: false },
);

export const AgentRunFailedEventSchema = Type.Object(
  {
    ...eventBaseProperties,
    event_type: Type.Literal('agent_run.failed'),
    provider: Type.Optional(NullableStringSchema),
    model: Type.Optional(NullableStringSchema),
    adapter_version: NullableStringSchema,
    provider_request_id: NullableStringSchema,
    failure: GatewayFailureSchema,
  },
  { additionalProperties: false },
);
export type AgentRunFailedEvent = Static<typeof AgentRunFailedEventSchema>;

export const CancellationReasonCodeSchema = Type.Union([
  Type.Literal('user_requested'),
  Type.Literal('task_cancelled'),
  Type.Literal('authorization_revoked'),
  Type.Literal('deadline_exceeded'),
  Type.Literal('service_shutdown'),
]);

export const AgentRunCancelledEventSchema = Type.Object(
  {
    ...eventBaseProperties,
    event_type: Type.Literal('agent_run.cancelled'),
    reason_code: CancellationReasonCodeSchema,
    provider_request_id: NullableStringSchema,
  },
  { additionalProperties: false },
);
export type AgentRunCancelledEvent = Static<typeof AgentRunCancelledEventSchema>;

export const GatewayEventSchema = Type.Union([
  AgentRunStartedEventSchema,
  AgentRunCompletedEventSchema,
  AgentRunFailedEventSchema,
  AgentRunCancelledEventSchema,
]);
export type GatewayEvent = Static<typeof GatewayEventSchema>;

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
