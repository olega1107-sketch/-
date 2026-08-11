import type { Confirmation, ConfirmationStatus } from './confirmation-protocol.js';
import type { AgentExecutionRequest } from './protocol.js';

export interface ApproveConfirmationCommand {
  userId: string;
  confirmationId: string;
  requestId: string;
  capabilityId: string;
  capabilityTokenHash: string;
  dispatchedAt: string;
  deadlineAt: string;
  capabilityExpiresAt: string;
}

export interface ConfirmationDispatch {
  agentRunId: string;
  capabilityId: string;
  executionRequest: AgentExecutionRequest;
}

export interface ApprovedConfirmation {
  confirmation: Confirmation;
  dispatch: ConfirmationDispatch | null;
}

export interface ConfirmationListPosition {
  createdAt: string;
  confirmationId: string;
}

export interface ListConfirmationsQuery {
  userId: string;
  requestId: string;
  projectId: string;
  status: ConfirmationStatus;
  limit: number;
  after: ConfirmationListPosition | null;
}

export interface ConfirmationListSlice {
  items: Confirmation[];
  nextPosition: ConfirmationListPosition | null;
}

export interface ConfirmationRepository {
  listConfirmations(query: ListConfirmationsQuery): Promise<ConfirmationListSlice>;
  getConfirmation(userId: string, requestId: string, confirmationId: string): Promise<Confirmation>;
  approveConfirmation(command: ApproveConfirmationCommand): Promise<ApprovedConfirmation>;
  rejectConfirmation(
    userId: string,
    confirmationId: string,
    requestId: string,
    decidedAt: string,
  ): Promise<Confirmation>;
}
