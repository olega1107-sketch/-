import type {
  AgentCancellationRequest,
  AgentExecutionRequest,
  ContextBundle,
  ContextBundleRedeemRequest,
  FinishReason,
  GatewayEvent,
  ProviderUsage,
} from './protocol.js';

export type ExecutionPhase =
  | 'accepted'
  | 'started_event_pending'
  | 'running'
  | 'provider_calling'
  | 'terminal_event_pending'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface AcceptedCancellation {
  request: AgentCancellationRequest;
  acceptedAt: string;
}

export interface ExecutionRecord {
  version: 1;
  agentRunId: string;
  requestFingerprint: string;
  acceptedAt: string;
  phase: ExecutionPhase;
  eventIds: string[];
  adapterVersion?: string;
  request?: AgentExecutionRequest;
  context?: ContextBundle;
  pendingEvent?: GatewayEvent;
  cancellation?: AcceptedCancellation;
  providerRequestId?: string | null;
  startedAt?: string;
  terminalEventType?: 'agent_run.completed' | 'agent_run.failed' | 'agent_run.cancelled';
  terminalAt?: string;
}

export interface ExecutionStore {
  load(agentRunId: string): Promise<ExecutionRecord | undefined>;
  save(record: ExecutionRecord): Promise<void>;
  listPending(): Promise<ExecutionRecord[]>;
}

export interface DirectorClient {
  redeemContextBundle(
    agentRunId: string,
    capability: string,
    request: ContextBundleRedeemRequest,
    requestId: string,
  ): Promise<ContextBundle>;
  recordEvent(agentRunId: string, event: GatewayEvent, requestId: string): Promise<void>;
}

export interface ProviderInvocation {
  agentRunId: string;
  projectId: string;
  originRequestId: string;
  agentType: string;
  provider: string;
  model: string | null;
  purpose: string;
  instructions: string;
  providerDataProfileVersion: string | null;
  context: ContextBundle;
  deadlineAt: string;
}

export interface ProviderResult {
  content: string;
  contentType: 'text/plain' | 'text/markdown' | 'application/json';
  finishReason: FinishReason;
  providerRequestId: string | null;
  usage?: ProviderUsage;
  outputSummary?: string | null;
}

export interface ProviderAdapter {
  readonly provider: string;
  readonly adapterVersion: string;
  supports(request: AgentExecutionRequest): boolean;
  execute(invocation: ProviderInvocation, signal: AbortSignal): Promise<ProviderResult>;
}

export interface ServiceAuthInput {
  authorization?: string;
  socket: unknown;
}

export interface ServiceAuthenticator {
  authenticate(input: ServiceAuthInput): Promise<void> | void;
}

export interface Clock {
  now(): Date;
}

export interface IdGenerator {
  next(): string;
}

export const systemClock: Clock = { now: () => new Date() };
