import { computeContextSetHash, computeRequestFingerprint, sha256Bytes } from '../src/canonical.js';
import type {
  Clock,
  DirectorClient,
  ExecutionRecord,
  ExecutionStore,
  IdGenerator,
} from '../src/ports.js';
import type {
  AgentExecutionRequest,
  ContextBundle,
  ContextItem,
  ContextBundleRedeemRequest,
  GatewayEvent,
} from '../src/protocol.js';

export const ids = {
  run: '10000000-0000-4000-8000-000000000001',
  project: '10000000-0000-4000-8000-000000000002',
  task: '10000000-0000-4000-8000-000000000003',
  request: '10000000-0000-4000-8000-000000000004',
  memory: '10000000-0000-4000-8000-000000000005',
  version: '10000000-0000-4000-8000-000000000006',
  callerRequest: '10000000-0000-4000-8000-000000000007',
};

export class TestClock implements Clock {
  constructor(private current: Date = new Date('2026-08-10T10:00:00.000Z')) {}

  now(): Date {
    return new Date(this.current);
  }

  set(value: string): void {
    this.current = new Date(value);
  }
}

export class SequentialIds implements IdGenerator {
  private value = 100;

  next(): string {
    const suffix = String(this.value++).padStart(12, '0');
    return `20000000-0000-4000-8000-${suffix}`;
  }
}

export class MemoryExecutionStore implements ExecutionStore {
  readonly records = new Map<string, ExecutionRecord>();

  async load(agentRunId: string): Promise<ExecutionRecord | undefined> {
    const record = this.records.get(agentRunId);
    return record === undefined ? undefined : structuredClone(record);
  }

  async save(record: ExecutionRecord): Promise<void> {
    this.records.set(record.agentRunId, structuredClone(record));
  }

  async listPending(): Promise<ExecutionRecord[]> {
    return [...this.records.values()]
      .filter((record) => !['completed', 'failed', 'cancelled'].includes(record.phase))
      .map((record) => structuredClone(record));
  }
}

export class FakeDirector implements DirectorClient {
  readonly redeemCalls: Array<{
    agentRunId: string;
    capability: string;
    request: ContextBundleRedeemRequest;
    requestId: string;
  }> = [];
  readonly eventAttempts: GatewayEvent[] = [];
  readonly events: GatewayEvent[] = [];
  eventHandler?: (event: GatewayEvent, attempt: number) => Promise<void>;

  constructor(public bundle: ContextBundle) {}

  async redeemContextBundle(
    agentRunId: string,
    capability: string,
    request: ContextBundleRedeemRequest,
    requestId: string,
  ): Promise<ContextBundle> {
    this.redeemCalls.push({ agentRunId, capability, request, requestId });
    return structuredClone(this.bundle);
  }

  async recordEvent(_agentRunId: string, event: GatewayEvent): Promise<void> {
    const copy = structuredClone(event);
    this.eventAttempts.push(copy);
    if (this.eventHandler !== undefined) {
      await this.eventHandler(copy, this.eventAttempts.length);
    }
    this.events.push(copy);
  }
}

export interface ExecutionFixture {
  agentRunId: string;
  request: AgentExecutionRequest;
  bundle: ContextBundle;
}

export function executionFixture(options?: {
  provider?: string;
  model?: string | null;
  content?: string;
  deadlineAt?: string;
  deploymentClass?: 'internal' | 'external';
  providerDataProfileVersion?: string | null;
}): ExecutionFixture {
  const content = options?.content ?? '# Architecture\nUse immutable context.';
  const contentBytes = Buffer.from(content, 'utf8');
  const item: ContextItem = {
    position: 1,
    memory_object_id: ids.memory,
    document_version_id: ids.version,
    file_name: 'architecture.md',
    media_type: 'text/markdown',
    size_bytes: contentBytes.byteLength,
    content_encoding: 'utf-8',
    content,
    content_hash: sha256Bytes(contentBytes),
    sensitivity_level: 'internal',
    access_reason: 'Primary architecture context',
  };
  const bundle: ContextBundle = {
    protocol_version: '1.0',
    agent_run_id: ids.run,
    project_id: ids.project,
    request_fingerprint: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    context_set_hash: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    item_count: 1,
    max_sensitivity_level: 'internal',
    items: [item],
    assembled_at: '2026-08-10T09:59:00.000Z',
    expires_at: '2026-08-10T12:00:00.000Z',
  };
  bundle.context_set_hash = computeContextSetHash(bundle);

  const request: AgentExecutionRequest = {
    protocol_version: '1.0',
    project_id: ids.project,
    task_id: ids.task,
    origin_request_id: ids.request,
    request_fingerprint: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    agent_type: 'architect',
    provider: options?.provider ?? 'fixture',
    model: options?.model ?? null,
    purpose: 'Review the architecture',
    instructions: 'Return only the final recommendation.',
    deployment_class: options?.deploymentClass ?? 'internal',
    provider_data_profile_version: options?.providerDataProfileVersion ?? null,
    context_set_hash: bundle.context_set_hash,
    context_item_count: 1,
    max_context_sensitivity: 'internal',
    dispatched_at: '2026-08-10T10:00:00.000Z',
    deadline_at: options?.deadlineAt ?? '2026-08-10T11:00:00.000Z',
  };
  request.request_fingerprint = computeRequestFingerprint(ids.run, request);
  bundle.request_fingerprint = request.request_fingerprint;
  return { agentRunId: ids.run, request, bundle };
}

export function executeCommand(fixture: ExecutionFixture) {
  return {
    agentRunId: fixture.agentRunId,
    idempotencyKey: fixture.agentRunId,
    capability: 'capability-secret',
    requestId: ids.callerRequest,
    request: fixture.request,
  };
}
