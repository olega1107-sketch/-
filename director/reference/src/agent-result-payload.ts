import { hashCanonical } from './canonical.js';
import type {
  AgentResultSaveRequest,
  AiResultSaveConfirmationPayload,
} from './agent-result-protocol.js';
import type { AgentResultRecord } from './agent-result-ports.js';
import type { SensitivityLevel } from './protocol.js';

export interface AiResultSavePayloadSource {
  result: AgentResultRecord;
  saveSensitivityLevel: SensitivityLevel;
  requestedByUserId: string;
  input: Required<AgentResultSaveRequest>;
}

export function buildAiResultSaveConfirmationPayload(
  source: AiResultSavePayloadSource,
): AiResultSaveConfirmationPayload {
  return {
    version: 1,
    operation: 'ai_result_save',
    result: {
      id: source.result.id,
      agent_run_id: source.result.agentRunId,
      task_id: source.result.taskId,
      project_id: source.result.projectId,
      output_storage_uri: source.result.outputStorageUri,
      content_hash: source.result.contentHash,
      size_bytes: source.result.sizeBytes,
      content_type: source.result.contentType,
      sensitivity_level: source.result.sensitivityLevel,
    },
    save_sensitivity_level: source.saveSensitivityLevel,
    requested_by_user_id: source.requestedByUserId,
    input: source.input,
  };
}

export function computeAiResultSaveConfirmationPayloadHash(
  source: AiResultSavePayloadSource,
): string {
  return hashCanonical(buildAiResultSaveConfirmationPayload(source));
}
