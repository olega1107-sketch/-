import { hashCanonical, maximumSensitivity } from './canonical.js';
import type { AgentConfirmationReason } from './agent-policy.js';
import type { DeploymentClass } from './protocol.js';
import type { AgentRunCreate, FrozenContextDescriptor } from './task-protocol.js';

export interface AgentRunConfirmationSource {
  agentRunId: string;
  taskId: string;
  projectId: string;
  requestedByUserId: string;
  originRequestId: string;
  provider: string;
  model: string | null;
  deploymentClass: DeploymentClass;
  providerDataProfileVersion: string | null;
  input: AgentRunCreate;
  contextSetHash: string;
  context: readonly FrozenContextDescriptor[];
  confirmationReasons: readonly AgentConfirmationReason[];
}

export function buildAgentRunConfirmationPayload(source: AgentRunConfirmationSource) {
  return {
    version: 1,
    agent_run_id: source.agentRunId,
    task_id: source.taskId,
    project_id: source.projectId,
    requested_by_user_id: source.requestedByUserId,
    origin_request_id: source.originRequestId,
    agent_type: source.input.agent_type,
    provider: source.provider,
    model: source.model,
    purpose: source.input.purpose,
    instructions: source.input.instructions,
    deployment_class: source.deploymentClass,
    provider_data_profile_version: source.providerDataProfileVersion,
    context_set_hash: source.contextSetHash,
    context_item_count: source.context.length,
    max_context_sensitivity: maximumSensitivity(
      source.context.map((item) => item.sensitivityLevel),
    ),
    confirmation_reasons: [...source.confirmationReasons],
    context: [...source.context]
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
  };
}

export function computeAgentRunConfirmationPayloadHash(
  source: AgentRunConfirmationSource,
): string {
  return hashCanonical(buildAgentRunConfirmationPayload(source));
}
