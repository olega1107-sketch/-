import { randomUUID } from 'node:crypto';

import type { RelationshipRef } from './agent-result-protocol.js';
import type { Confirmation } from './confirmation-protocol.js';
import type {
  DecisionRepository,
  NormalizedDecisionCreate,
  NormalizedDecisionSupersede,
} from './decision-ports.js';
import type {
  Decision,
  DecisionCreate,
  DecisionProvenance,
  DecisionSupersedeRequest,
  DecisionSupersedeResponse,
} from './decision-protocol.js';
import { DirectorProtocolError } from './errors.js';
import type { IdGenerator } from './memory-ports.js';
import { systemClock, type Clock } from './ports.js';

export interface DecisionServiceOptions {
  repository: DecisionRepository;
  idGenerator?: IdGenerator;
  clock?: Clock;
  confirmationTtlMs?: number;
}

const randomIds: IdGenerator = { next: () => randomUUID() };

export class DecisionService {
  private readonly repository: DecisionRepository;
  private readonly idGenerator: IdGenerator;
  private readonly clock: Clock;
  private readonly confirmationTtlMs: number;

  constructor(options: DecisionServiceOptions) {
    this.repository = options.repository;
    this.idGenerator = options.idGenerator ?? randomIds;
    this.clock = options.clock ?? systemClock;
    this.confirmationTtlMs = positiveDuration(options.confirmationTtlMs ?? 15 * 60 * 1_000);
  }

  async requestDecisionApproval(
    userId: string,
    requestId: string,
    decisionId: string,
  ): Promise<Decision> {
    const requestedAt = this.clock.now();
    const prepared = await this.repository.prepareDecisionApproval({
      userId,
      requestId,
      decisionId,
      requestedAt: requestedAt.toISOString(),
      confirmationExpiresAt: new Date(
        requestedAt.getTime() + this.confirmationTtlMs,
      ).toISOString(),
    });
    if (prepared.outcome === 'approved') {
      return prepared.decision;
    }
    throw requiresConfirmation(
      prepared.confirmation,
      'Approving the decision requires user confirmation.',
    );
  }

  async supersedeDecision(
    userId: string,
    requestId: string,
    decisionId: string,
    input: DecisionSupersedeRequest,
  ): Promise<DecisionSupersedeResponse> {
    const requestedAt = this.clock.now();
    const prepared = await this.repository.prepareDecisionSupersede({
      userId,
      requestId,
      decisionId,
      newDecisionId: this.idGenerator.next(),
      newMemoryObjectId: this.idGenerator.next(),
      requestedAt: requestedAt.toISOString(),
      confirmationExpiresAt: new Date(
        requestedAt.getTime() + this.confirmationTtlMs,
      ).toISOString(),
      input: normalizeSupersede(input),
    });
    if (prepared.outcome === 'superseded') {
      return prepared.result;
    }
    throw requiresConfirmation(
      prepared.confirmation,
      'Superseding the decision requires user confirmation.',
    );
  }

  async createDecision(
    userId: string,
    requestId: string,
    input: DecisionCreate,
  ): Promise<Decision> {
    return this.repository.createDecision({
      decisionId: this.idGenerator.next(),
      memoryObjectId: this.idGenerator.next(),
      userId,
      requestId,
      input: normalizeDecision(input),
    });
  }

  async getDecision(userId: string, requestId: string, decisionId: string): Promise<Decision> {
    return this.repository.getDecision(userId, requestId, decisionId);
  }

  async getDecisionProvenance(
    userId: string,
    requestId: string,
    decisionId: string,
  ): Promise<DecisionProvenance> {
    return this.repository.getDecisionProvenance(userId, requestId, decisionId);
  }
}

function normalizeDecision(input: DecisionCreate): NormalizedDecisionCreate {
  return {
    project_id: input.project_id,
    topic_id: input.topic_id ?? null,
    title: requiredText(input.title, 'Decision title'),
    decision_text: requiredText(input.decision_text, 'Decision text'),
    rationale: nullableText(input.rationale ?? null),
    status: input.status ?? 'draft',
    sensitivity_level: input.sensitivity_level ?? 'internal',
    relationships: normalizedRelationships(input.relationships ?? []),
  };
}

function normalizeSupersede(input: DecisionSupersedeRequest): NormalizedDecisionSupersede {
  return {
    title: requiredText(input.title, 'Decision title'),
    decision_text: requiredText(input.decision_text, 'Decision text'),
    rationale: nullableText(input.rationale ?? null),
    sensitivity_level: input.sensitivity_level ?? 'internal',
    relationships: normalizedRelationships(input.relationships ?? []),
  };
}

function normalizedRelationships(relationships: readonly RelationshipRef[]): RelationshipRef[] {
  const normalized = relationships.map(normalizeRelationship);
  const keys = normalized.map(
    (relationship) =>
      `${relationship.target_type}:${relationship.target_id}:${relationship.relation_type}`,
  );
  if (new Set(keys).size !== keys.length) {
    throw validationError('Relationships must be unique after normalization.');
  }
  return normalized;
}

function normalizeRelationship(relationship: RelationshipRef): RelationshipRef {
  return {
    target_type: relationship.target_type,
    target_id: relationship.target_id,
    relation_type: relationship.relation_type,
    description: nullableText(relationship.description ?? null),
  };
}

function requiredText(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw validationError(`${label} must not be blank.`);
  }
  return normalized;
}

function nullableText(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  const normalized = value.trim();
  return normalized.length === 0 ? null : normalized;
}

function validationError(message: string): DirectorProtocolError {
  return new DirectorProtocolError(400, 'validation_error', message);
}

function requiresConfirmation(
  confirmation: Confirmation,
  message: string,
): DirectorProtocolError {
  return new DirectorProtocolError(428, 'requires_confirmation', message, false, {
    confirmation_id: confirmation.id,
    target_type: confirmation.target_type,
    target_id: confirmation.target_id,
    payload_hash: confirmation.payload_hash,
    expires_at: confirmation.expires_at,
  });
}

function positiveDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error('Decision confirmation TTL must be a positive safe integer.');
  }
  return value;
}
