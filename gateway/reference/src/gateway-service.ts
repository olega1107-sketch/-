import { randomUUID } from 'node:crypto';

import {
  computeEventHash,
  computeRequestFingerprint,
  sha256Text,
  verifyContextBundle,
} from './canonical.js';
import { DirectorClientError, GatewayProtocolError, ProviderAdapterError } from './errors.js';
import { KeyedLock } from './keyed-lock.js';
import {
  systemClock,
  type Clock,
  type DirectorClient,
  type ExecutionRecord,
  type ExecutionStore,
  type IdGenerator,
  type ProviderAdapter,
  type ProviderInvocation,
  type ProviderResult,
} from './ports.js';
import type {
  AgentCancellationReceipt,
  AgentCancellationRequest,
  AgentExecutionReceipt,
  AgentExecutionRequest,
  AgentRunCancelledEvent,
  AgentRunCompletedEvent,
  AgentRunFailedEvent,
  AgentRunStartedEvent,
  CancellationReasonCode,
  GatewayEvent,
  GatewayFailure,
} from './protocol.js';

export interface ExecuteCommand {
  agentRunId: string;
  idempotencyKey: string;
  capability: string;
  requestId: string;
  request: AgentExecutionRequest;
}

export interface CancelCommand {
  agentRunId: string;
  idempotencyKey: string;
  requestId: string;
  request: AgentCancellationRequest;
}

export interface GatewayServiceOptions {
  store: ExecutionStore;
  director: DirectorClient;
  adapters: readonly ProviderAdapter[];
  clock?: Clock;
  idGenerator?: IdGenerator;
  autoProcess?: boolean;
  maxResultBytes?: number;
  backgroundRetryDelayMs?: number;
  maxBackgroundRetryDelayMs?: number;
  maxBackgroundDeliveryAttempts?: number;
  onBackgroundError?: (error: unknown, agentRunId: string) => void;
}

export interface GatewayQueueSnapshot {
  pending: number;
  oldestSeconds: number;
}

const terminalPhases = new Set(['completed', 'failed', 'cancelled']);

export class GatewayService {
  private readonly lock = new KeyedLock();
  private readonly adapters = new Map<string, ProviderAdapter>();
  private readonly activeWork = new Map<string, Promise<void>>();
  private readonly abortControllers = new Map<string, AbortController>();
  private readonly retryAttempts = new Map<string, number>();
  private readonly store: ExecutionStore;
  private readonly director: DirectorClient;
  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;
  private readonly autoProcess: boolean;
  private readonly maxResultBytes: number;
  private readonly backgroundRetryDelayMs: number;
  private readonly maxBackgroundRetryDelayMs: number;
  private readonly maxBackgroundDeliveryAttempts: number;
  private readonly onBackgroundError: (error: unknown, agentRunId: string) => void;

  constructor(options: GatewayServiceOptions) {
    this.store = options.store;
    this.director = options.director;
    this.clock = options.clock ?? systemClock;
    this.idGenerator = options.idGenerator ?? { next: () => randomUUID() };
    this.autoProcess = options.autoProcess ?? true;
    this.maxResultBytes = options.maxResultBytes ?? 4 * 1024 * 1024;
    this.backgroundRetryDelayMs = options.backgroundRetryDelayMs ?? 1_000;
    this.maxBackgroundRetryDelayMs = options.maxBackgroundRetryDelayMs ?? 30_000;
    this.maxBackgroundDeliveryAttempts = options.maxBackgroundDeliveryAttempts ?? 5;
    this.onBackgroundError = options.onBackgroundError ?? (() => undefined);

    for (const adapter of options.adapters) {
      if (this.adapters.has(adapter.provider)) {
        throw new Error(`Duplicate provider adapter: ${adapter.provider}`);
      }
      this.adapters.set(adapter.provider, adapter);
    }
  }

  async execute(command: ExecuteCommand): Promise<AgentExecutionReceipt> {
    this.validateIdempotencyKey(command.agentRunId, command.idempotencyKey);
    this.validateExecutionRequest(command.agentRunId, command.request);

    const result = await this.lock.runExclusive(command.agentRunId, async () => {
      const existing = await this.store.load(command.agentRunId);
      if (existing !== undefined) {
        if (existing.requestFingerprint !== command.request.request_fingerprint) {
          throw new GatewayProtocolError(
            409,
            'idempotency_conflict',
            'The agent run was already accepted with a different fingerprint.',
          );
        }
        return {
          receipt: this.executionReceipt(existing, true),
          shouldProcess: !terminalPhases.has(existing.phase),
        };
      }

      this.validateNewExecution(command.request);
      const adapter = this.requireAdapter(command.request.provider);

      const bundle = await this.director.redeemContextBundle(
        command.agentRunId,
        command.capability,
        {
          protocol_version: '1.0',
          request_fingerprint: command.request.request_fingerprint,
          expected_context_set_hash: command.request.context_set_hash,
        },
        command.requestId,
      );
      verifyContextBundle(command.agentRunId, command.request, bundle, this.clock.now());

      const acceptedAt = this.clock.now().toISOString();
      const record: ExecutionRecord = {
        version: 1,
        agentRunId: command.agentRunId,
        requestFingerprint: command.request.request_fingerprint,
        acceptedAt,
        phase: 'accepted',
        eventIds: [],
        adapterVersion: adapter.adapterVersion,
        request: command.request,
        context: bundle,
      };
      await this.store.save(record);
      return { receipt: this.executionReceipt(record, false), shouldProcess: true };
    });

    if (this.autoProcess && result.shouldProcess) {
      this.enqueue(command.agentRunId);
    }
    return result.receipt;
  }

  async cancel(command: CancelCommand): Promise<AgentCancellationReceipt> {
    this.validateIdempotencyKey(command.agentRunId, command.idempotencyKey);
    this.validateTimestamp(command.request.requested_at, 'requested_at');

    const result = await this.lock.runExclusive(command.agentRunId, async () => {
      const record = await this.store.load(command.agentRunId);
      if (record === undefined) {
        throw new GatewayProtocolError(404, 'not_found', 'The agent run is not accepted.');
      }
      if (terminalPhases.has(record.phase)) {
        return { receipt: this.cancellationReceipt(record, 'terminal'), shouldProcess: false };
      }
      if (record.cancellation !== undefined) {
        return {
          receipt: this.cancellationReceipt(record, 'already_cancelled'),
          shouldProcess: true,
        };
      }

      const acceptedAt = this.clock.now().toISOString();
      record.cancellation = { request: command.request, acceptedAt };
      await this.store.save(record);
      return { receipt: this.cancellationReceipt(record, 'accepted'), shouldProcess: true };
    });

    this.abortControllers.get(command.agentRunId)?.abort(command.request.reason_code);
    if (this.autoProcess && result.shouldProcess) {
      this.enqueue(command.agentRunId);
    }
    return result.receipt;
  }

  async drain(agentRunId: string): Promise<void> {
    const current = this.activeWork.get(agentRunId);
    if (current !== undefined) {
      return current;
    }

    const work = this.run(agentRunId).finally(() => {
      if (this.activeWork.get(agentRunId) === work) {
        this.activeWork.delete(agentRunId);
      }
    });
    this.activeWork.set(agentRunId, work);
    return work;
  }

  async resumePending(): Promise<void> {
    const records = await this.store.listPending();
    if (this.autoProcess) {
      for (const record of records) {
        this.schedule(record.agentRunId);
      }
      return;
    }
    await Promise.all(records.map((record) => this.drain(record.agentRunId)));
  }

  async inspectQueue(): Promise<GatewayQueueSnapshot> {
    const pending = await this.store.listPending();
    const now = this.clock.now().getTime();
    const oldestSeconds = pending.reduce((oldest, record) => {
      const acceptedAt = Date.parse(record.acceptedAt);
      if (!Number.isFinite(acceptedAt)) return oldest;
      return Math.max(oldest, (now - acceptedAt) / 1_000);
    }, 0);
    return { pending: pending.length, oldestSeconds: Math.max(0, oldestSeconds) };
  }

  private async run(agentRunId: string): Promise<void> {
    while (true) {
      const record = await this.store.load(agentRunId);
      if (record === undefined || terminalPhases.has(record.phase)) {
        return;
      }

      switch (record.phase) {
        case 'accepted':
          await this.stageInitialEvent(record);
          break;
        case 'started_event_pending':
          await this.deliverStartedEvent(record);
          break;
        case 'running':
          await this.beginProviderOrCancel(record);
          break;
        case 'provider_calling':
          await this.stageUnknownProviderOutcome(record);
          break;
        case 'terminal_event_pending':
          await this.deliverTerminalEvent(record);
          break;
        default:
          return;
      }
    }
  }

  private async stageInitialEvent(snapshot: ExecutionRecord): Promise<void> {
    await this.lock.runExclusive(snapshot.agentRunId, async () => {
      const record = await this.requireRecord(snapshot.agentRunId);
      if (record.phase !== 'accepted') {
        return;
      }
      if (record.cancellation !== undefined || this.deadlineReached(record)) {
        this.ensureDeadlineCancellation(record);
        this.stageCancelledEvent(record);
      } else {
        const request = this.requireRequest(record);
        const adapter = this.requireAdapter(request.provider);
        const event = this.sealEvent<AgentRunStartedEvent>({
          protocol_version: '1.0',
          event_id: this.idGenerator.next(),
          event_type: 'agent_run.started',
          agent_run_id: record.agentRunId,
          project_id: request.project_id,
          origin_request_id: request.origin_request_id,
          request_fingerprint: record.requestFingerprint,
          occurred_at: this.clock.now().toISOString(),
          provider: request.provider,
          model: request.model ?? null,
          adapter_version: record.adapterVersion ?? adapter.adapterVersion,
          context_set_hash: request.context_set_hash,
        });
        record.phase = 'started_event_pending';
        record.pendingEvent = event;
        record.eventIds.push(event.event_id);
      }
      await this.store.save(record);
    });
  }

  private async deliverStartedEvent(snapshot: ExecutionRecord): Promise<void> {
    const event = this.requirePendingEvent(snapshot, 'agent_run.started');
    await this.director.recordEvent(snapshot.agentRunId, event, event.event_id);
    await this.lock.runExclusive(snapshot.agentRunId, async () => {
      const record = await this.requireRecord(snapshot.agentRunId);
      if (
        record.phase === 'started_event_pending' &&
        record.pendingEvent?.event_id === event.event_id
      ) {
        record.phase = 'running';
        record.startedAt = event.occurred_at;
        delete record.pendingEvent;
        await this.store.save(record);
      }
    });
  }

  private async beginProviderOrCancel(snapshot: ExecutionRecord): Promise<void> {
    const prepared = await this.lock.runExclusive(snapshot.agentRunId, async () => {
      const record = await this.requireRecord(snapshot.agentRunId);
      if (record.phase !== 'running') {
        return undefined;
      }
      if (record.cancellation !== undefined || this.deadlineReached(record)) {
        this.ensureDeadlineCancellation(record);
        this.stageCancelledEvent(record);
        await this.store.save(record);
        return undefined;
      }

      const request = this.requireRequest(record);
      const context = this.requireContext(record);
      const adapter = this.requireAdapter(request.provider);
      record.phase = 'provider_calling';
      await this.store.save(record);
      const invocation: ProviderInvocation = {
        agentRunId: record.agentRunId,
        projectId: request.project_id,
        originRequestId: request.origin_request_id,
        agentType: request.agent_type,
        provider: request.provider,
        model: request.model ?? null,
        purpose: request.purpose,
        instructions: request.instructions,
        providerDataProfileVersion: request.provider_data_profile_version ?? null,
        context,
        deadlineAt: request.deadline_at,
      };
      return { adapter, invocation };
    });

    if (prepared === undefined) {
      return;
    }
    await this.invokeProvider(snapshot.agentRunId, prepared.adapter, prepared.invocation);
  }

  private async invokeProvider(
    agentRunId: string,
    adapter: ProviderAdapter,
    invocation: ProviderInvocation,
  ): Promise<void> {
    const controller = new AbortController();
    this.abortControllers.set(agentRunId, controller);
    const remainingMs = Math.max(0, Date.parse(invocation.deadlineAt) - this.clock.now().getTime());
    const deadlineTimer = setTimeout(() => controller.abort('deadline_exceeded'), remainingMs);

    let result: ProviderResult | undefined;
    let failure: ProviderAdapterError | undefined;
    try {
      result = await adapter.execute(invocation, controller.signal);
    } catch (error) {
      failure = this.normalizeProviderError(error, controller.signal);
    } finally {
      clearTimeout(deadlineTimer);
      if (this.abortControllers.get(agentRunId) === controller) {
        this.abortControllers.delete(agentRunId);
      }
    }

    await this.lock.runExclusive(agentRunId, async () => {
      const record = await this.requireRecord(agentRunId);
      if (record.phase !== 'provider_calling') {
        return;
      }
      if (record.cancellation !== undefined || this.deadlineReached(record)) {
        this.ensureDeadlineCancellation(record);
        this.stageCancelledEvent(record);
      } else if (failure !== undefined) {
        if (failure.providerRequestId !== undefined) {
          record.providerRequestId = failure.providerRequestId;
        }
        this.stageFailedEvent(record, this.failureFromAdapter(failure), adapter.adapterVersion);
      } else if (result !== undefined) {
        record.providerRequestId = result.providerRequestId;
        this.stageCompletedEvent(record, result, adapter);
      } else {
        this.stageFailedEvent(
          record,
          {
            code: 'internal_error',
            phase: 'provider',
            message: 'Provider adapter returned no result.',
            retryable: false,
          },
          adapter.adapterVersion,
        );
      }
      await this.store.save(record);
    });
  }

  private async stageUnknownProviderOutcome(snapshot: ExecutionRecord): Promise<void> {
    await this.lock.runExclusive(snapshot.agentRunId, async () => {
      const record = await this.requireRecord(snapshot.agentRunId);
      if (record.phase !== 'provider_calling') {
        return;
      }
      if (record.cancellation !== undefined || this.deadlineReached(record)) {
        this.ensureDeadlineCancellation(record);
        this.stageCancelledEvent(record);
      } else {
        const request = this.requireRequest(record);
        this.stageFailedEvent(
          record,
          {
            code: 'provider_outcome_unknown',
            phase: 'provider',
            message: 'Provider outcome is unknown after gateway recovery.',
            retryable: false,
          },
          record.adapterVersion ?? this.adapters.get(request.provider)?.adapterVersion ?? null,
        );
      }
      await this.store.save(record);
    });
  }

  private async deliverTerminalEvent(snapshot: ExecutionRecord): Promise<void> {
    const event = snapshot.pendingEvent;
    if (event === undefined || !isTerminalEvent(event)) {
      throw new Error('Terminal execution record does not contain a terminal event.');
    }
    await this.director.recordEvent(snapshot.agentRunId, event, event.event_id);
    await this.lock.runExclusive(snapshot.agentRunId, async () => {
      const record = await this.requireRecord(snapshot.agentRunId);
      if (
        record.phase !== 'terminal_event_pending' ||
        record.pendingEvent?.event_id !== event.event_id
      ) {
        return;
      }
      record.phase = terminalPhase(event);
      record.terminalEventType = event.event_type;
      record.terminalAt = this.clock.now().toISOString();
      delete record.request;
      delete record.context;
      delete record.pendingEvent;
      await this.store.save(record);
    });
  }

  private stageCompletedEvent(
    record: ExecutionRecord,
    result: ProviderResult,
    adapter: ProviderAdapter,
  ): void {
    const request = this.requireRequest(record);
    const context = this.requireContext(record);
    const sizeBytes = Buffer.byteLength(result.content, 'utf8');
    if (sizeBytes > this.maxResultBytes) {
      this.stageFailedEvent(
        record,
        {
          code: 'output_too_large',
          phase: 'normalization',
          message: 'Provider output exceeds the gateway result limit.',
          retryable: false,
        },
        adapter.adapterVersion,
      );
      return;
    }

    const eventBody = {
      protocol_version: '1.0' as const,
      event_id: this.idGenerator.next(),
      event_type: 'agent_run.completed' as const,
      agent_run_id: record.agentRunId,
      project_id: request.project_id,
      origin_request_id: request.origin_request_id,
      request_fingerprint: record.requestFingerprint,
      occurred_at: this.clock.now().toISOString(),
      provider: request.provider,
      model: request.model ?? null,
      adapter_version: adapter.adapterVersion,
      provider_request_id: result.providerRequestId,
      result: {
        content: result.content,
        content_type: result.contentType,
        content_hash: sha256Text(result.content),
        size_bytes: sizeBytes,
        sensitivity_level: context.max_sensitivity_level,
        finish_reason: result.finishReason,
        ...(result.usage === undefined ? {} : { usage: result.usage }),
        ...(result.outputSummary === undefined
          ? {}
          : { output_summary: result.outputSummary }),
      },
    };
    this.stageTerminalEvent(record, this.sealEvent<AgentRunCompletedEvent>(eventBody));
  }

  private stageFailedEvent(
    record: ExecutionRecord,
    failure: GatewayFailure,
    adapterVersion: string | null,
  ): void {
    const request = this.requireRequest(record);
    const event = this.sealEvent<AgentRunFailedEvent>({
      protocol_version: '1.0',
      event_id: this.idGenerator.next(),
      event_type: 'agent_run.failed',
      agent_run_id: record.agentRunId,
      project_id: request.project_id,
      origin_request_id: request.origin_request_id,
      request_fingerprint: record.requestFingerprint,
      occurred_at: this.clock.now().toISOString(),
      provider: request.provider ?? null,
      model: request.model ?? null,
      adapter_version: adapterVersion,
      provider_request_id: record.providerRequestId ?? null,
      failure,
    });
    this.stageTerminalEvent(record, event);
  }

  private stageCancelledEvent(record: ExecutionRecord): void {
    const request = this.requireRequest(record);
    const reason = record.cancellation?.request.reason_code ?? 'deadline_exceeded';
    const event = this.sealEvent<AgentRunCancelledEvent>({
      protocol_version: '1.0',
      event_id: this.idGenerator.next(),
      event_type: 'agent_run.cancelled',
      agent_run_id: record.agentRunId,
      project_id: request.project_id,
      origin_request_id: request.origin_request_id,
      request_fingerprint: record.requestFingerprint,
      occurred_at: this.clock.now().toISOString(),
      reason_code: reason,
      provider_request_id: record.providerRequestId ?? null,
    });
    this.stageTerminalEvent(record, event);
  }

  private stageTerminalEvent(record: ExecutionRecord, event: GatewayEvent): void {
    record.phase = 'terminal_event_pending';
    record.pendingEvent = event;
    record.eventIds.push(event.event_id);
  }

  private ensureDeadlineCancellation(record: ExecutionRecord): void {
    if (record.cancellation !== undefined) {
      return;
    }
    const acceptedAt = this.clock.now().toISOString();
    record.cancellation = {
      acceptedAt,
      request: {
        protocol_version: '1.0',
        reason_code: 'deadline_exceeded',
        reason: null,
        requested_at: acceptedAt,
      },
    };
  }

  private normalizeProviderError(error: unknown, signal: AbortSignal): ProviderAdapterError {
    if (error instanceof ProviderAdapterError) {
      return error;
    }
    if (signal.aborted) {
      return new ProviderAdapterError('Provider request was cancelled.', {
        code: 'provider_timeout',
        retryable: false,
      });
    }
    return new ProviderAdapterError('Provider adapter failed.', {
      code: 'internal_error',
      retryable: false,
    });
  }

  private failureFromAdapter(error: ProviderAdapterError): GatewayFailure {
    return {
      code: error.code,
      phase: error.phase,
      message: error.message,
      retryable: error.retryable,
      ...(error.providerStatus === undefined
        ? {}
        : { provider_status: error.providerStatus }),
      ...(error.retryAfterSeconds === undefined
        ? {}
        : { retry_after_seconds: error.retryAfterSeconds }),
    };
  }

  private sealEvent<T extends GatewayEvent>(event: Omit<T, 'event_hash'>): T {
    return { ...event, event_hash: computeEventHash(event) } as T;
  }

  private validateExecutionRequest(agentRunId: string, request: AgentExecutionRequest): void {
    if (computeRequestFingerprint(agentRunId, request) !== request.request_fingerprint) {
      throw new GatewayProtocolError(
        400,
        'validation_error',
        'The request fingerprint does not match the canonical execution envelope.',
      );
    }
    this.validateTimestamp(request.dispatched_at, 'dispatched_at');
    this.validateTimestamp(request.deadline_at, 'deadline_at');
  }

  private validateNewExecution(request: AgentExecutionRequest): void {
    if (Date.parse(request.deadline_at) <= this.clock.now().getTime()) {
      throw new GatewayProtocolError(409, 'invalid_state', 'The execution deadline has passed.');
    }
    if (
      request.deployment_class === 'external' &&
      (request.provider_data_profile_version ?? '').length === 0
    ) {
      throw new GatewayProtocolError(
        422,
        'policy_violation',
        'External execution requires a provider data profile version.',
      );
    }
    if (
      request.deployment_class === 'internal' &&
      (request.provider_data_profile_version ?? null) !== null
    ) {
      throw new GatewayProtocolError(
        422,
        'policy_violation',
        'Internal execution cannot set a provider data profile version.',
      );
    }
    const adapter = this.adapters.get(request.provider);
    if (adapter === undefined || !adapter.supports(request)) {
      throw new GatewayProtocolError(
        422,
        'unsupported_provider',
        'The requested provider or model is not supported.',
      );
    }
  }

  private validateTimestamp(value: string, field: string): Date {
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds)) {
      throw new GatewayProtocolError(
        400,
        'validation_error',
        `The ${field} timestamp is invalid.`,
      );
    }
    return new Date(milliseconds);
  }

  private validateIdempotencyKey(agentRunId: string, idempotencyKey: string): void {
    if (agentRunId !== idempotencyKey) {
      throw new GatewayProtocolError(
        400,
        'validation_error',
        'Idempotency-Key must equal agent_run_id.',
      );
    }
  }

  private deadlineReached(record: ExecutionRecord): boolean {
    const request = this.requireRequest(record);
    return Date.parse(request.deadline_at) <= this.clock.now().getTime();
  }

  private executionReceipt(record: ExecutionRecord, duplicate: boolean): AgentExecutionReceipt {
    let gatewayState: AgentExecutionReceipt['gateway_state'];
    if (terminalPhases.has(record.phase)) {
      gatewayState = 'terminal';
    } else if (record.startedAt !== undefined) {
      gatewayState = 'started';
    } else {
      gatewayState = duplicate ? 'already_accepted' : 'accepted';
    }
    return {
      protocol_version: '1.0',
      agent_run_id: record.agentRunId,
      request_fingerprint: record.requestFingerprint,
      gateway_state: gatewayState,
      accepted_at: record.acceptedAt,
    };
  }

  private cancellationReceipt(
    record: ExecutionRecord,
    state: AgentCancellationReceipt['gateway_state'],
  ): AgentCancellationReceipt {
    return {
      protocol_version: '1.0',
      agent_run_id: record.agentRunId,
      gateway_state: state,
      accepted_at: record.cancellation?.acceptedAt ?? record.terminalAt ?? record.acceptedAt,
    };
  }

  private async requireRecord(agentRunId: string): Promise<ExecutionRecord> {
    const record = await this.store.load(agentRunId);
    if (record === undefined) {
      throw new Error('Execution record disappeared during processing.');
    }
    return record;
  }

  private requireRequest(record: ExecutionRecord): AgentExecutionRequest {
    if (record.request === undefined) {
      throw new Error('Pending execution record has no request.');
    }
    return record.request;
  }

  private requireContext(record: ExecutionRecord) {
    if (record.context === undefined) {
      throw new Error('Pending execution record has no context.');
    }
    return record.context;
  }

  private requireAdapter(provider: string): ProviderAdapter {
    const adapter = this.adapters.get(provider);
    if (adapter === undefined) {
      throw new Error(`Accepted execution has no provider adapter: ${provider}`);
    }
    return adapter;
  }

  private requirePendingEvent(
    record: ExecutionRecord,
    eventType: 'agent_run.started',
  ): AgentRunStartedEvent {
    if (record.pendingEvent?.event_type !== eventType) {
      throw new Error('Execution record does not contain the expected pending event.');
    }
    return record.pendingEvent;
  }

  private schedule(agentRunId: string): void {
    void this.drain(agentRunId)
      .then(() => {
        this.retryAttempts.delete(agentRunId);
      })
      .catch((error: unknown) => {
        const attempts = (this.retryAttempts.get(agentRunId) ?? 0) + 1;
        this.retryAttempts.set(agentRunId, attempts);
        if (
          error instanceof DirectorClientError &&
          error.retryable &&
          attempts < this.maxBackgroundDeliveryAttempts
        ) {
          const exponential = Math.min(
            this.backgroundRetryDelayMs * 2 ** (attempts - 1),
            this.maxBackgroundRetryDelayMs,
          );
          const jittered = Math.max(1, Math.round(exponential * (0.5 + Math.random())));
          setTimeout(() => this.schedule(agentRunId), jittered).unref();
          return;
        }
        this.onBackgroundError(error, agentRunId);
      });
  }

  private enqueue(agentRunId: string): void {
    setImmediate(() => this.schedule(agentRunId)).unref();
  }
}

function terminalPhase(
  event: AgentRunCompletedEvent | AgentRunFailedEvent | AgentRunCancelledEvent,
): 'completed' | 'failed' | 'cancelled' {
  switch (event.event_type) {
    case 'agent_run.completed':
      return 'completed';
    case 'agent_run.failed':
      return 'failed';
    case 'agent_run.cancelled':
      return 'cancelled';
  }
}

function isTerminalEvent(
  event: GatewayEvent,
): event is AgentRunCompletedEvent | AgentRunFailedEvent | AgentRunCancelledEvent {
  return event.event_type !== 'agent_run.started';
}

export function isCancellationReason(value: unknown): value is CancellationReasonCode {
  return [
    'user_requested',
    'task_cancelled',
    'authorization_revoked',
    'deadline_exceeded',
    'service_shutdown',
  ].includes(String(value));
}
