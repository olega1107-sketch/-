import { randomUUID } from 'node:crypto';

import { hashCanonical, sha256Text } from './canonical.js';
import type {
  ConfirmationListPosition,
  ConfirmationRepository,
} from './confirmation-ports.js';
import type {
  Confirmation,
  ConfirmationListQuery,
  ConfirmationPage,
} from './confirmation-protocol.js';
import { DirectorProtocolError } from './errors.js';
import type { IdGenerator } from './memory-ports.js';
import { systemClock, type Clock } from './ports.js';
import { decodeQueryCursor, encodeQueryCursor } from './query-cursor.js';
import type { AgentGatewayClient, CapabilityTokenIssuer } from './task-ports.js';

export interface ConfirmationServiceOptions {
  repository: ConfirmationRepository;
  gateway: AgentGatewayClient;
  capabilityTokens: CapabilityTokenIssuer;
  clock?: Clock;
  idGenerator?: IdGenerator;
  runDeadlineMs?: number;
  capabilityTtlMs?: number;
}

const randomIds: IdGenerator = { next: () => randomUUID() };

export class ConfirmationService {
  private readonly repository: ConfirmationRepository;
  private readonly gateway: AgentGatewayClient;
  private readonly capabilityTokens: CapabilityTokenIssuer;
  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;
  private readonly runDeadlineMs: number;
  private readonly capabilityTtlMs: number;

  constructor(options: ConfirmationServiceOptions) {
    this.repository = options.repository;
    this.gateway = options.gateway;
    this.capabilityTokens = options.capabilityTokens;
    this.clock = options.clock ?? systemClock;
    this.idGenerator = options.idGenerator ?? randomIds;
    this.runDeadlineMs = positiveDuration(options.runDeadlineMs ?? 10 * 60 * 1_000);
    this.capabilityTtlMs = positiveDuration(options.capabilityTtlMs ?? 5 * 60 * 1_000);
  }

  async listConfirmations(
    userId: string,
    requestId: string,
    input: ConfirmationListQuery,
  ): Promise<ConfirmationPage> {
    const status = input.status ?? 'pending';
    const scope = hashCanonical({
      version: 1,
      kind: 'confirmation_list',
      userId,
      projectId: input.project_id,
      status,
    });
    const after = input.cursor === undefined
      ? null
      : decodeQueryCursor(input.cursor, scope, isConfirmationListPosition);
    const result = await this.repository.listConfirmations({
      userId,
      requestId,
      projectId: input.project_id,
      status,
      limit: normalizedLimit(input.limit),
      after,
    });
    return {
      items: result.items,
      next_cursor: result.nextPosition === null
        ? null
        : encodeQueryCursor(scope, result.nextPosition),
    };
  }

  async getConfirmation(
    userId: string,
    requestId: string,
    confirmationId: string,
  ): Promise<Confirmation> {
    return this.repository.getConfirmation(userId, requestId, confirmationId);
  }

  async approveConfirmation(
    userId: string,
    confirmationId: string,
    requestId: string,
  ): Promise<Confirmation> {
    const now = this.clock.now();
    const deadlineAt = new Date(now.getTime() + this.runDeadlineMs);
    const capabilityExpiresAt = new Date(
      Math.min(deadlineAt.getTime(), now.getTime() + this.capabilityTtlMs),
    );
    const capabilityId = this.idGenerator.next();
    const capability = this.capabilityTokens.issue(capabilityId);
    const approved = await this.repository.approveConfirmation({
      userId,
      confirmationId,
      requestId,
      capabilityId,
      capabilityTokenHash: sha256Text(capability),
      dispatchedAt: now.toISOString(),
      deadlineAt: deadlineAt.toISOString(),
      capabilityExpiresAt: capabilityExpiresAt.toISOString(),
    });
    if (approved.dispatch !== null) {
      await this.gateway.dispatch({
        agentRunId: approved.dispatch.agentRunId,
        capability: this.capabilityTokens.issue(approved.dispatch.capabilityId),
        requestId,
        request: approved.dispatch.executionRequest,
      });
    }
    return approved.confirmation;
  }

  async rejectConfirmation(
    userId: string,
    confirmationId: string,
    requestId: string,
  ): Promise<Confirmation> {
    return this.repository.rejectConfirmation(
      userId,
      confirmationId,
      requestId,
      this.clock.now().toISOString(),
    );
  }
}

function positiveDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error('Confirmation service durations must be positive safe integers.');
  }
  return value;
}

function normalizedLimit(value: number | undefined): number {
  const limit = value ?? 50;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new DirectorProtocolError(
      400,
      'validation_error',
      'Pagination limit must be an integer from 1 through 100.',
    );
  }
  return limit;
}

function isConfirmationListPosition(value: unknown): value is ConfirmationListPosition {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const position = value as Record<string, unknown>;
  return (
    Object.keys(position).length === 2 &&
    typeof position.createdAt === 'string' &&
    !Number.isNaN(Date.parse(position.createdAt)) &&
    typeof position.confirmationId === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      position.confirmationId,
    )
  );
}
