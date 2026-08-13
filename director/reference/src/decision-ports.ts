import type { RelationshipRef } from './agent-result-protocol.js';
import type {
  Decision,
  DecisionCreate,
  DecisionProvenance,
  DecisionSupersedeRequest,
  DecisionSupersedeResponse,
  PilotDecisionCreateStatus,
} from './decision-protocol.js';
import type { Confirmation } from './confirmation-protocol.js';
import type { SensitivityLevel } from './protocol.js';

export interface NormalizedDecisionCreate {
  project_id: string;
  topic_id: string | null;
  title: string;
  decision_text: string;
  rationale: string | null;
  status: PilotDecisionCreateStatus;
  sensitivity_level: SensitivityLevel;
  relationships: RelationshipRef[];
}

export interface CreateDecisionCommand {
  decisionId: string;
  memoryObjectId: string;
  userId: string;
  requestId: string;
  input: NormalizedDecisionCreate;
}

export interface NormalizedDecisionSupersede {
  title: string;
  decision_text: string;
  rationale: string | null;
  sensitivity_level: SensitivityLevel;
  relationships: RelationshipRef[];
}

export interface PrepareDecisionApprovalCommand {
  userId: string;
  requestId: string;
  decisionId: string;
  requestedAt: string;
  confirmationExpiresAt: string;
}

export interface PrepareDecisionSupersedeCommand {
  userId: string;
  requestId: string;
  decisionId: string;
  newDecisionId: string;
  newMemoryObjectId: string;
  requestedAt: string;
  confirmationExpiresAt: string;
  input: NormalizedDecisionSupersede;
}

export type PreparedDecisionApproval =
  | { outcome: 'approved'; decision: Decision }
  | { outcome: 'requires_confirmation'; confirmation: Confirmation };

export type PreparedDecisionSupersede =
  | { outcome: 'superseded'; result: DecisionSupersedeResponse }
  | { outcome: 'requires_confirmation'; confirmation: Confirmation };

export interface DecisionRepository {
  createDecision(command: CreateDecisionCommand): Promise<Decision>;
  prepareDecisionApproval(
    command: PrepareDecisionApprovalCommand,
  ): Promise<PreparedDecisionApproval>;
  prepareDecisionSupersede(
    command: PrepareDecisionSupersedeCommand,
  ): Promise<PreparedDecisionSupersede>;
  getDecision(userId: string, requestId: string, decisionId: string): Promise<Decision>;
  getDecisionProvenance(
    userId: string,
    requestId: string,
    decisionId: string,
  ): Promise<DecisionProvenance>;
}

export type { DecisionCreate, DecisionSupersedeRequest };
