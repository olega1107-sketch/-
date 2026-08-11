import { createHash } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';

import { GatewayProtocolError } from './errors.js';
import type {
  AgentExecutionRequest,
  ContextBundle,
  ContextItem,
  SensitivityLevel,
} from './protocol.js';

export function sha256Bytes(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function sha256Text(value: string): string {
  return sha256Bytes(Buffer.from(value, 'utf8'));
}

export function hashCanonical(value: unknown): string {
  return sha256Text(canonicalize(value));
}

export function computeRequestFingerprint(
  agentRunId: string,
  request: AgentExecutionRequest,
): string {
  const envelope: Partial<AgentExecutionRequest> = { ...request };
  delete envelope.request_fingerprint;
  return hashCanonical({ agent_run_id: agentRunId, ...envelope });
}

export function computeContextSetHash(bundle: ContextBundle): string {
  return hashCanonical({
    version: 1,
    agent_run_id: bundle.agent_run_id,
    project_id: bundle.project_id,
    items: [...bundle.items]
      .sort((left, right) => left.position - right.position)
      .map((item) => ({
        position: item.position,
        memory_object_id: item.memory_object_id,
        document_version_id: item.document_version_id,
        file_name: item.file_name,
        media_type: item.media_type,
        size_bytes: item.size_bytes,
        content_hash: item.content_hash,
        sensitivity_level: item.sensitivity_level,
        access_reason: item.access_reason,
      })),
  });
}

export function computeEventHash(event: unknown): string {
  return hashCanonical(event);
}

export function contextItemBytes(item: ContextItem): Buffer {
  if (item.content_encoding === 'utf-8') {
    const bytes = Buffer.from(item.content, 'utf8');
    if (bytes.toString('utf8') !== item.content) {
      throw contextMismatch('Context text is not canonical UTF-8.', item.position);
    }
    return bytes;
  }

  if (
    item.content.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      item.content,
    )
  ) {
    throw contextMismatch('Context item has invalid base64.', item.position);
  }

  const bytes = Buffer.from(item.content, 'base64');
  if (bytes.toString('base64') !== item.content) {
    throw contextMismatch('Context item has non-canonical base64.', item.position);
  }
  return bytes;
}

const sensitivityRank: Record<SensitivityLevel, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
};

export function verifyContextBundle(
  agentRunId: string,
  request: AgentExecutionRequest,
  bundle: ContextBundle,
  now: Date,
): void {
  if (
    bundle.agent_run_id !== agentRunId ||
    bundle.project_id !== request.project_id ||
    bundle.request_fingerprint !== request.request_fingerprint
  ) {
    throw contextMismatch('Context bundle identity does not match the execution request.');
  }
  if (
    bundle.item_count !== bundle.items.length ||
    bundle.item_count !== request.context_item_count
  ) {
    throw contextMismatch('Context bundle item count does not match the execution request.');
  }
  const assembledAt = Date.parse(bundle.assembled_at);
  const expiresAt = Date.parse(bundle.expires_at);
  if (!Number.isFinite(assembledAt) || !Number.isFinite(expiresAt)) {
    throw contextMismatch('Context bundle timestamps are invalid.');
  }
  if (expiresAt <= now.getTime()) {
    throw new GatewayProtocolError(410, 'capability_expired', 'Context bundle has expired.');
  }

  let maximum: SensitivityLevel = 'public';
  for (const [index, item] of bundle.items.entries()) {
    if (item.position !== index + 1) {
      throw contextMismatch('Context positions must be continuous and ordered.', item.position);
    }
    const bytes = contextItemBytes(item);
    if (bytes.byteLength !== item.size_bytes || sha256Bytes(bytes) !== item.content_hash) {
      throw contextMismatch('Context content hash or size does not match.', item.position);
    }
    if (sensitivityRank[item.sensitivity_level] > sensitivityRank[maximum]) {
      maximum = item.sensitivity_level;
    }
  }

  if (
    maximum !== bundle.max_sensitivity_level ||
    maximum !== request.max_context_sensitivity
  ) {
    throw contextMismatch('Context sensitivity does not match the frozen request.');
  }
  if (
    bundle.context_set_hash !== request.context_set_hash ||
    computeContextSetHash(bundle) !== request.context_set_hash
  ) {
    throw contextMismatch('Context manifest hash does not match.');
  }
}

function contextMismatch(message: string, position?: number): GatewayProtocolError {
  const details = position === undefined ? {} : { position };
  return new GatewayProtocolError(422, 'context_hash_mismatch', message, false, details);
}
