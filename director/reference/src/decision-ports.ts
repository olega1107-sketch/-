import type { RelationshipRef } from './agent-result-protocol.js';
import type {
  Decision,
  DecisionCreate,
  DecisionProvenance,
  PilotDecisionCreateStatus,
} from './decision-protocol.js';
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

export interface DecisionRepository {
  createDecision(command: CreateDecisionCommand): Promise<Decision>;
  getDecision(userId: string, requestId: string, decisionId: string): Promise<Decision>;
  getDecisionProvenance(
    userId: string,
    requestId: string,
    decisionId: string,
  ): Promise<DecisionProvenance>;
}

export type { DecisionCreate };
