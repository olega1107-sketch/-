import {
  computeContextSetHash,
  computeEventHash,
  isTextMediaType,
  maximumSensitivity,
  sha256Bytes,
  sha256Text,
} from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import {
  systemClock,
  type Clock,
  type ContextGrant,
  type DirectorRepository,
  type DocumentStore,
} from './ports.js';
import type {
  ContextBundle,
  ContextBundleRedeemRequest,
  ContextItem,
  GatewayEvent,
} from './protocol.js';

export interface DirectorServiceOptions {
  repository: DirectorRepository;
  documentStore: DocumentStore;
  clock?: Clock;
  maxContextBytes?: number;
  maxResultBytes?: number;
  resultTtlMs?: number;
}

export class DirectorService {
  private readonly repository: DirectorRepository;
  private readonly documentStore: DocumentStore;
  private readonly clock: Clock;
  private readonly maxContextBytes: number;
  private readonly maxResultBytes: number;
  private readonly resultTtlMs: number;

  constructor(options: DirectorServiceOptions) {
    this.repository = options.repository;
    this.documentStore = options.documentStore;
    this.clock = options.clock ?? systemClock;
    this.maxContextBytes = options.maxContextBytes ?? 32 * 1024 * 1024;
    this.maxResultBytes = options.maxResultBytes ?? 4 * 1024 * 1024;
    this.resultTtlMs = options.resultTtlMs ?? 24 * 60 * 60 * 1_000;
  }

  async redeemContextBundle(
    agentRunId: string,
    capability: string,
    request: ContextBundleRedeemRequest,
    requestId: string,
  ): Promise<ContextBundle> {
    const inspectionTime = this.clock.now();
    const grantRequest = {
      tokenHash: sha256Text(capability),
      agentRunId,
      requestFingerprint: request.request_fingerprint,
      contextSetHash: request.expected_context_set_hash,
      requestId,
      now: inspectionTime.toISOString(),
    };
    const inspected = await this.repository.inspectContextGrant(grantRequest);
    const items = await this.readContextItems(inspected);
    const assembledAt = this.clock.now();
    const bundle = this.createBundle(inspected, items, assembledAt);
    if (computeContextSetHash(bundle) !== request.expected_context_set_hash) {
      throw new DirectorProtocolError(
        422,
        'context_hash_mismatch',
        'Frozen context manifest hash does not match.',
      );
    }

    const consumed = await this.repository.consumeContextGrant(
      { ...grantRequest, now: assembledAt.toISOString() },
      inspected.capabilityId,
    );
    if (grantSignature(consumed) !== grantSignature(inspected)) {
      throw new DirectorProtocolError(
        409,
        'invalid_state',
        'Frozen context changed during capability redemption.',
      );
    }
    return bundle;
  }

  async recordGatewayEvent(agentRunId: string, event: GatewayEvent): Promise<void> {
    if (event.agent_run_id !== agentRunId) {
      throw new DirectorProtocolError(
        400,
        'validation_error',
        'Path agent_run_id does not match the event.',
      );
    }
    if (!Number.isFinite(Date.parse(event.occurred_at))) {
      throw new DirectorProtocolError(400, 'validation_error', 'Event timestamp is invalid.');
    }
    if (computeEventHash(event) !== event.event_hash) {
      throw new DirectorProtocolError(
        400,
        'validation_error',
        'Event hash does not match the canonical event.',
      );
    }

    const preflight = await this.repository.preflightGatewayEvent(event);
    if (preflight === 'duplicate') {
      return;
    }
    if (preflight === 'conflict') {
      await this.rejectConflictingEvent(event);
    }

    const stagedResult =
      event.event_type === 'agent_run.completed'
        ? await this.stageCompletedResult(event)
        : undefined;
    const outcome = await this.repository.applyGatewayEvent(event, stagedResult);
    if (outcome === 'conflict') {
      throw new DirectorProtocolError(
        409,
        'idempotency_conflict',
        'Event ID was already used with a different hash.',
      );
    }
  }

  private async rejectConflictingEvent(event: GatewayEvent): Promise<never> {
    const outcome = await this.repository.applyGatewayEvent(event, undefined);
    if (outcome !== 'conflict') {
      throw new DirectorProtocolError(
        409,
        'invalid_state',
        'Gateway event state changed during conflict handling.',
      );
    }
    throw new DirectorProtocolError(
      409,
      'idempotency_conflict',
      'Event ID was already used with a different hash.',
    );
  }

  private async readContextItems(grant: ContextGrant): Promise<ContextItem[]> {
    let totalBytes = 0;
    const items: ContextItem[] = [];
    for (const descriptor of grant.contexts) {
      let bytes: Uint8Array;
      try {
        bytes = (await this.documentStore.readImmutable(descriptor.storageUri)).bytes;
      } catch {
        throw new DirectorProtocolError(
          503,
          'unavailable',
          'Document Store could not read a frozen context version.',
          true,
        );
      }
      totalBytes += bytes.byteLength;
      if (totalBytes > this.maxContextBytes) {
        throw new DirectorProtocolError(413, 'payload_too_large', 'Context bundle is too large.');
      }
      if (
        bytes.byteLength !== descriptor.sizeBytes ||
        sha256Bytes(bytes) !== descriptor.contentHash
      ) {
        throw new DirectorProtocolError(
          422,
          'context_hash_mismatch',
          'Document bytes do not match the immutable version metadata.',
          false,
          { position: descriptor.position },
        );
      }

      const encoded = encodeContent(bytes, descriptor.mediaType, descriptor.position);
      items.push({
        position: descriptor.position,
        memory_object_id: descriptor.memoryObjectId,
        document_version_id: descriptor.documentVersionId,
        file_name: descriptor.fileName,
        media_type: descriptor.mediaType,
        size_bytes: descriptor.sizeBytes,
        content_encoding: encoded.encoding,
        content: encoded.content,
        content_hash: descriptor.contentHash,
        sensitivity_level: descriptor.sensitivityLevel,
        access_reason: descriptor.accessReason,
      });
    }
    return items;
  }

  private createBundle(
    grant: ContextGrant,
    items: ContextItem[],
    assembledAt: Date,
  ): ContextBundle {
    return {
      protocol_version: '1.0',
      agent_run_id: grant.agentRunId,
      project_id: grant.projectId,
      request_fingerprint: grant.requestFingerprint,
      context_set_hash: grant.contextSetHash,
      item_count: items.length,
      max_sensitivity_level: maximumSensitivity(
        items.map((item) => item.sensitivity_level),
      ),
      items,
      assembled_at: assembledAt.toISOString(),
      expires_at: new Date(grant.expiresAt).toISOString(),
    };
  }

  private async stageCompletedResult(event: GatewayEvent & { event_type: 'agent_run.completed' }) {
    const bytes = Buffer.from(event.result.content, 'utf8');
    if (bytes.toString('utf8') !== event.result.content) {
      throw new DirectorProtocolError(
        422,
        'validation_error',
        'Gateway result is not canonical UTF-8.',
      );
    }
    if (bytes.byteLength > this.maxResultBytes) {
      throw new DirectorProtocolError(413, 'payload_too_large', 'Gateway result is too large.');
    }
    if (
      bytes.byteLength !== event.result.size_bytes ||
      sha256Bytes(bytes) !== event.result.content_hash
    ) {
      throw new DirectorProtocolError(
        422,
        'validation_error',
        'Gateway result content hash or size does not match.',
      );
    }

    const deterministicKey = `agent-results/${event.agent_run_id}/${event.result.content_hash}`;
    try {
      const staged = await this.documentStore.stageAgentResult(
        deterministicKey,
        bytes,
        event.result.content_type,
        event.result.content_hash,
      );
      return {
        storageUri: staged.storageUri,
        expiresAt: new Date(this.clock.now().getTime() + this.resultTtlMs).toISOString(),
      };
    } catch {
      throw new DirectorProtocolError(
        503,
        'unavailable',
        'Document Store could not stage the gateway result.',
        true,
      );
    }
  }
}

function encodeContent(
  bytes: Uint8Array,
  mediaType: string,
  position: number,
): { encoding: 'utf-8' | 'base64'; content: string } {
  if (!isTextMediaType(mediaType)) {
    return { encoding: 'base64', content: Buffer.from(bytes).toString('base64') };
  }
  try {
    const content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!Buffer.from(content, 'utf8').equals(Buffer.from(bytes))) {
      throw new Error('Non-canonical UTF-8.');
    }
    return { encoding: 'utf-8', content };
  } catch {
    throw new DirectorProtocolError(
      422,
      'context_hash_mismatch',
      'Text context is not valid UTF-8.',
      false,
      { position },
    );
  }
}

function grantSignature(grant: ContextGrant): string {
  return JSON.stringify({
    capabilityId: grant.capabilityId,
    servicePrincipalId: grant.servicePrincipalId,
    agentRunId: grant.agentRunId,
    projectId: grant.projectId,
    requestFingerprint: grant.requestFingerprint,
    contextSetHash: grant.contextSetHash,
    expiresAt: grant.expiresAt,
    contexts: grant.contexts,
  });
}
