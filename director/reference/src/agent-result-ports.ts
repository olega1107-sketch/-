import type { AgentResultSaveRequest } from './agent-result-protocol.js';
import type { Confirmation } from './confirmation-protocol.js';
import type { MemoryObject } from './public-protocol.js';
import type { SensitivityLevel } from './protocol.js';

export interface AgentResultRecord {
  id: string;
  agentRunId: string;
  taskId: string;
  projectId: string;
  outputStorageUri: string;
  contentHash: string;
  sizeBytes: number;
  contentType: string;
  outputSummary: string | null;
  sensitivityLevel: SensitivityLevel;
  createdAt: string;
  expiresAt: string | null;
  savedMemoryObjectId: string | null;
  savedAt: string | null;
}

export interface PrepareAgentResultSaveCommand {
  userId: string;
  agentRunId: string;
  requestId: string;
  input: Required<AgentResultSaveRequest>;
  requestedAt: string;
  confirmationExpiresAt: string;
}

export type PreparedAgentResultSave =
  | { outcome: 'requires_confirmation'; confirmation: Confirmation }
  | { outcome: 'saved'; memoryObject: MemoryObject };

export interface AgentResultRepository {
  getAgentRunResult(
    userId: string,
    requestId: string,
    agentRunId: string,
    requestedAt: string,
  ): Promise<AgentResultRecord>;
  prepareAgentResultSave(
    command: PrepareAgentResultSaveCommand,
  ): Promise<PreparedAgentResultSave>;
}
