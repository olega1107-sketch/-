import { createHash } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';

import type {
  AgentExecutionRequest,
  ContextBundle,
  GatewayEvent,
  SensitivityLevel,
} from './protocol.js';
import type { FrozenContextDescriptor } from './task-protocol.js';

export function sha256Bytes(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function sha256Text(value: string): string {
  return sha256Bytes(Buffer.from(value, 'utf8'));
}

export function hashCanonical(value: unknown): string {
  return sha256Text(canonicalize(value));
}

export function computeEventHash(event: GatewayEvent): string {
  const body: Partial<GatewayEvent> = { ...event };
  delete body.event_hash;
  return hashCanonical(body);
}

export function computeRequestFingerprint(
  agentRunId: string,
  request: AgentExecutionRequest,
): string {
  const envelope: Partial<AgentExecutionRequest> = { ...request };
  delete envelope.request_fingerprint;
  return hashCanonical({ agent_run_id: agentRunId, ...envelope });
}

export function computeFrozenContextSetHash(
  agentRunId: string,
  projectId: string,
  items: readonly FrozenContextDescriptor[],
): string {
  return hashCanonical({
    version: 1,
    agent_run_id: agentRunId,
    project_id: projectId,
    items: [...items]
      .sort((left, right) => left.position - right.position)
      .map((item) => ({
        position: item.position,
        memory_object_id: item.memory_object_id,
        document_version_id: item.document_version_id,
        file_name: item.fileName,
        media_type: item.mediaType,
        size_bytes: item.sizeBytes,
        content_hash: item.contentHash,
        sensitivity_level: item.sensitivityLevel,
        access_reason: item.access_reason,
      })),
  });
}

export function computeContextSetHash(bundle: ContextBundle): string {
  return computeFrozenContextSetHash(
    bundle.agent_run_id,
    bundle.project_id,
    bundle.items.map((item) => ({
      position: item.position,
      memory_object_id: item.memory_object_id,
      document_version_id: item.document_version_id,
      access_reason: item.access_reason,
      fileName: item.file_name,
      mediaType: item.media_type,
      sizeBytes: item.size_bytes,
      contentHash: item.content_hash,
      sensitivityLevel: item.sensitivity_level,
    })),
  );
}

const sensitivityRanks: Record<SensitivityLevel, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
};

export function sensitivityRank(value: SensitivityLevel): number {
  return sensitivityRanks[value];
}

export function maximumSensitivity(values: readonly SensitivityLevel[]): SensitivityLevel {
  if (values.length === 0) {
    throw new Error('Cannot determine sensitivity for an empty context.');
  }
  return values.reduce((maximum, value) =>
    sensitivityRank(value) > sensitivityRank(maximum) ? value : maximum,
  );
}

export function isTextMediaType(mediaType: string): boolean {
  return (
    mediaType.startsWith('text/') ||
    ['application/json', 'application/xml', 'application/yaml', 'application/x-yaml'].includes(
      mediaType,
    )
  );
}
