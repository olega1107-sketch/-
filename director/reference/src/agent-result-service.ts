import { sha256Bytes } from './canonical.js';
import type { AgentResultRepository } from './agent-result-ports.js';
import type {
  AgentResultSaveRequest,
  AgentRunResult,
  RelationshipRef,
} from './agent-result-protocol.js';
import { DirectorProtocolError } from './errors.js';
import type { MemoryObject } from './public-protocol.js';
import { systemClock, type Clock, type DocumentStore } from './ports.js';

export interface AgentResultServiceOptions {
  repository: AgentResultRepository;
  documentStore: DocumentStore;
  clock?: Clock;
  confirmationTtlMs?: number;
}

export class AgentResultService {
  private readonly repository: AgentResultRepository;
  private readonly documentStore: DocumentStore;
  private readonly clock: Clock;
  private readonly confirmationTtlMs: number;

  constructor(options: AgentResultServiceOptions) {
    this.repository = options.repository;
    this.documentStore = options.documentStore;
    this.clock = options.clock ?? systemClock;
    this.confirmationTtlMs = positiveDuration(options.confirmationTtlMs ?? 15 * 60 * 1_000);
  }

  async getAgentRunResult(
    userId: string,
    requestId: string,
    agentRunId: string,
  ): Promise<AgentRunResult> {
    const result = await this.repository.getAgentRunResult(
      userId,
      requestId,
      agentRunId,
      this.clock.now().toISOString(),
    );
    let bytes: Uint8Array;
    try {
      bytes = (await this.documentStore.readImmutable(result.outputStorageUri)).bytes;
    } catch {
      throw resultIntegrityError('The stored agent result is unavailable.');
    }
    if (bytes.byteLength !== result.sizeBytes || sha256Bytes(bytes) !== result.contentHash) {
      throw resultIntegrityError('The stored agent result failed integrity validation.');
    }
    const content = decodeCanonicalUtf8(bytes);
    return {
      id: result.id,
      agent_run_id: result.agentRunId,
      project_id: result.projectId,
      content,
      content_type: result.contentType,
      content_hash: result.contentHash,
      sensitivity_level: result.sensitivityLevel,
      output_summary: result.outputSummary,
      created_at: result.createdAt,
      expires_at: result.expiresAt,
      saved_memory_object_id: result.savedMemoryObjectId,
      saved_at: result.savedAt,
    };
  }

  async saveAgentRunResult(
    userId: string,
    agentRunId: string,
    requestId: string,
    input: AgentResultSaveRequest,
  ): Promise<MemoryObject> {
    const requestedAt = this.clock.now();
    const prepared = await this.repository.prepareAgentResultSave({
      userId,
      agentRunId,
      requestId,
      input: normalizeSaveRequest(input),
      requestedAt: requestedAt.toISOString(),
      confirmationExpiresAt: new Date(
        requestedAt.getTime() + this.confirmationTtlMs,
      ).toISOString(),
    });
    if (prepared.outcome === 'saved') {
      return prepared.memoryObject;
    }
    throw new DirectorProtocolError(
      428,
      'requires_confirmation',
      'Saving the AI result requires user confirmation.',
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
}

function normalizeSaveRequest(input: AgentResultSaveRequest): Required<AgentResultSaveRequest> {
  const keywords = (input.keywords ?? []).map((keyword) => requiredText(keyword, 'Keyword'));
  if (new Set(keywords).size !== keywords.length) {
    throw validationError('Keywords must be unique after normalization.');
  }
  const relationships = (input.relationships ?? []).map(normalizeRelationship);
  const relationshipKeys = relationships.map(
    (relationship) =>
      `${relationship.target_type}:${relationship.target_id}:${relationship.relation_type}`,
  );
  if (new Set(relationshipKeys).size !== relationshipKeys.length) {
    throw validationError('Relationships must be unique after normalization.');
  }
  return {
    title: requiredText(input.title, 'AI result title'),
    summary: nullableText(input.summary ?? null),
    topic_id: input.topic_id ?? null,
    keywords,
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

function decodeCanonicalUtf8(bytes: Uint8Array): string {
  try {
    const content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!Buffer.from(content, 'utf8').equals(Buffer.from(bytes))) {
      throw new Error('Non-canonical UTF-8.');
    }
    return content;
  } catch {
    throw resultIntegrityError('The stored agent result is not canonical UTF-8.');
  }
}

function validationError(message: string): DirectorProtocolError {
  return new DirectorProtocolError(400, 'validation_error', message);
}

function resultIntegrityError(message: string): DirectorProtocolError {
  return new DirectorProtocolError(500, 'internal_error', message);
}

function positiveDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error('Agent result confirmation TTL must be a positive safe integer.');
  }
  return value;
}
