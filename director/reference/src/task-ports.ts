import type { Confirmation } from './confirmation-protocol.js';
import type { AgentRoute } from './agent-routing.js';
import type { AgentExecutionRequest } from './protocol.js';
import type {
  AgentRun,
  AgentRunCreate,
  Task,
  TaskCreate,
} from './task-protocol.js';

export interface CapabilityTokenIssuer {
  issue(capabilityId: string): string;
}

export interface AgentGatewayDispatch {
  agentRunId: string;
  capability: string;
  requestId: string;
  request: AgentExecutionRequest;
}

export interface AgentGatewayClient {
  dispatch(input: AgentGatewayDispatch): Promise<void>;
}

export interface CreateTaskCommand {
  taskId: string;
  userId: string;
  requestId: string;
  input: TaskCreate;
}

export interface PrepareAgentRunCommand {
  agentRunId: string;
  capabilityId: string;
  capabilityTokenHash: string;
  userId: string;
  taskId: string;
  requestId: string;
  input: AgentRunCreate;
  route: AgentRoute | null;
  dispatchedAt: string;
  deadlineAt: string;
  capabilityExpiresAt: string;
  confirmationExpiresAt: string;
}

export interface DispatchableAgentRun {
  outcome: 'dispatch';
  run: AgentRun;
  capabilityId: string;
  executionRequest: AgentExecutionRequest;
}

export interface ConfirmationRequiredAgentRun {
  outcome: 'requires_confirmation';
  run: AgentRun;
  confirmation: Confirmation;
}

export type PreparedAgentRun = DispatchableAgentRun | ConfirmationRequiredAgentRun;

export interface TaskRepository {
  createTask(command: CreateTaskCommand): Promise<Task>;
  getTask(userId: string, requestId: string, taskId: string): Promise<Task>;
  getAgentRun(userId: string, requestId: string, agentRunId: string): Promise<AgentRun>;
  prepareAgentRun(command: PrepareAgentRunCommand): Promise<PreparedAgentRun>;
}
