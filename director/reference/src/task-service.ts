import { randomUUID } from 'node:crypto';

import { sha256Text } from './canonical.js';
import type { AgentRouteResolver } from './agent-routing.js';
import { DirectorProtocolError } from './errors.js';
import type { IdGenerator } from './memory-ports.js';
import { systemClock, type Clock } from './ports.js';
import type {
  AgentGatewayClient,
  CapabilityTokenIssuer,
  TaskRepository,
} from './task-ports.js';
import type { AgentRun, AgentRunCreate, Task, TaskCreate } from './task-protocol.js';

export interface TaskServiceOptions {
  repository: TaskRepository;
  gateway: AgentGatewayClient;
  capabilityTokens: CapabilityTokenIssuer;
  routeResolver: AgentRouteResolver;
  clock?: Clock;
  idGenerator?: IdGenerator;
  runDeadlineMs?: number;
  capabilityTtlMs?: number;
  confirmationTtlMs?: number;
}

const randomIds: IdGenerator = { next: () => randomUUID() };

export class TaskService {
  private readonly repository: TaskRepository;
  private readonly gateway: AgentGatewayClient;
  private readonly capabilityTokens: CapabilityTokenIssuer;
  private readonly routeResolver: AgentRouteResolver;
  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;
  private readonly runDeadlineMs: number;
  private readonly capabilityTtlMs: number;
  private readonly confirmationTtlMs: number;

  constructor(options: TaskServiceOptions) {
    this.repository = options.repository;
    this.gateway = options.gateway;
    this.capabilityTokens = options.capabilityTokens;
    this.routeResolver = options.routeResolver;
    this.clock = options.clock ?? systemClock;
    this.idGenerator = options.idGenerator ?? randomIds;
    this.runDeadlineMs = positiveDuration(options.runDeadlineMs ?? 10 * 60 * 1_000);
    this.capabilityTtlMs = positiveDuration(options.capabilityTtlMs ?? 5 * 60 * 1_000);
    this.confirmationTtlMs = positiveDuration(options.confirmationTtlMs ?? 15 * 60 * 1_000);
  }

  async createTask(userId: string, requestId: string, input: TaskCreate): Promise<Task> {
    return this.repository.createTask({
      taskId: this.idGenerator.next(),
      userId,
      requestId,
      input: {
        project_id: input.project_id,
        title: requiredText(input.title, 'Task title'),
        user_request: requiredText(input.user_request, 'Task request'),
      },
    });
  }

  async getTask(userId: string, requestId: string, taskId: string): Promise<Task> {
    return this.repository.getTask(userId, requestId, taskId);
  }

  async getAgentRun(userId: string, requestId: string, agentRunId: string): Promise<AgentRun> {
    return this.repository.getAgentRun(userId, requestId, agentRunId);
  }

  async createAgentRun(
    userId: string,
    taskId: string,
    requestId: string,
    input: AgentRunCreate,
  ): Promise<AgentRun> {
    const normalized = normalizeAgentRun(input);
    const now = this.clock.now();
    const deadlineAt = new Date(now.getTime() + this.runDeadlineMs);
    const capabilityExpiresAt = new Date(
      Math.min(deadlineAt.getTime(), now.getTime() + this.capabilityTtlMs),
    );
    const confirmationExpiresAt = new Date(now.getTime() + this.confirmationTtlMs);
    const agentRunId = this.idGenerator.next();
    const capabilityId = this.idGenerator.next();
    const initialCapability = this.capabilityTokens.issue(capabilityId);
    const route = await this.routeResolver.resolve(normalized.agent_type);
    const prepared = await this.repository.prepareAgentRun({
      agentRunId,
      capabilityId,
      capabilityTokenHash: sha256Text(initialCapability),
      userId,
      taskId,
      requestId,
      input: normalized,
      route,
      dispatchedAt: now.toISOString(),
      deadlineAt: deadlineAt.toISOString(),
      capabilityExpiresAt: capabilityExpiresAt.toISOString(),
      confirmationExpiresAt: confirmationExpiresAt.toISOString(),
    });
    if (prepared.outcome === 'requires_confirmation') {
      throw new DirectorProtocolError(
        428,
        'requires_confirmation',
        'The agent execution requires user confirmation.',
        false,
        {
          confirmation_id: prepared.confirmation.id,
          target_type: prepared.confirmation.target_type,
          target_id: prepared.confirmation.target_id,
          payload_hash: prepared.confirmation.payload_hash,
          expires_at: prepared.confirmation.expires_at,
        },
      );
    }
    await this.gateway.dispatch({
      agentRunId: prepared.run.id,
      capability: this.capabilityTokens.issue(prepared.capabilityId),
      requestId,
      request: prepared.executionRequest,
    });
    return prepared.run;
  }
}

function normalizeAgentRun(input: AgentRunCreate): AgentRunCreate {
  const seenVersions = new Set<string>();
  const context = input.context.map((item) => {
    if (seenVersions.has(item.document_version_id)) {
      throw validationError('Agent context cannot contain the same document version twice.');
    }
    seenVersions.add(item.document_version_id);
    return {
      memory_object_id: item.memory_object_id,
      document_version_id: item.document_version_id,
      access_reason: requiredText(item.access_reason, 'Context access reason'),
    };
  });
  if (context.length === 0) {
    throw validationError('Agent context must not be empty.');
  }
  return {
    agent_type: requiredText(input.agent_type, 'Agent type'),
    purpose: requiredText(input.purpose, 'Agent purpose'),
    instructions: requiredText(input.instructions, 'Agent instructions'),
    context,
  };
}

function requiredText(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw validationError(`${label} must not be blank.`);
  }
  return normalized;
}

function positiveDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error('Task service durations must be positive safe integers.');
  }
  return value;
}

function validationError(message: string): DirectorProtocolError {
  return new DirectorProtocolError(400, 'validation_error', message);
}
