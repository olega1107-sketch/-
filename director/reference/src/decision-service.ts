import { randomUUID } from 'node:crypto';

import type { RelationshipRef } from './agent-result-protocol.js';
import type { DecisionRepository, NormalizedDecisionCreate } from './decision-ports.js';
import type {
  Decision,
  DecisionCreate,
  DecisionProvenance,
} from './decision-protocol.js';
import { DirectorProtocolError } from './errors.js';
import type { IdGenerator } from './memory-ports.js';

export interface DecisionServiceOptions {
  repository: DecisionRepository;
  idGenerator?: IdGenerator;
}

const randomIds: IdGenerator = { next: () => randomUUID() };

export class DecisionService {
  private readonly repository: DecisionRepository;
  private readonly idGenerator: IdGenerator;

  constructor(options: DecisionServiceOptions) {
    this.repository = options.repository;
    this.idGenerator = options.idGenerator ?? randomIds;
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
  const relationships = (input.relationships ?? []).map(normalizeRelationship);
  const keys = relationships.map(
    (relationship) =>
      `${relationship.target_type}:${relationship.target_id}:${relationship.relation_type}`,
  );
  if (new Set(keys).size !== keys.length) {
    throw validationError('Relationships must be unique after normalization.');
  }
  return {
    project_id: input.project_id,
    topic_id: input.topic_id ?? null,
    title: requiredText(input.title, 'Decision title'),
    decision_text: requiredText(input.decision_text, 'Decision text'),
    rationale: nullableText(input.rationale ?? null),
    status: input.status ?? 'draft',
    sensitivity_level: input.sensitivity_level ?? 'internal',
    relationships,
  };
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
