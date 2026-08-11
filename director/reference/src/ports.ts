import type { GatewayEvent, SensitivityLevel } from './protocol.js';

export interface SqlResult<Row> {
  rows: Row[];
  rowCount: number;
}

export interface SqlQueryable {
  query<Row>(text: string, parameters?: readonly unknown[]): Promise<SqlResult<Row>>;
}

export interface SqlDatabase extends SqlQueryable {
  transaction<T>(operation: (transaction: SqlQueryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export interface DocumentVersionBytes {
  bytes: Uint8Array;
}

export interface StagedDocument {
  storageUri: string;
}

export interface DocumentStore {
  readImmutable(storageUri: string): Promise<DocumentVersionBytes>;
  stageImmutableDocument(
    deterministicKey: string,
    content: Uint8Array,
    contentType: string,
    expectedHash: string,
  ): Promise<StagedDocument>;
  stageAgentResult(
    deterministicKey: string,
    content: Uint8Array,
    contentType: string,
    expectedHash: string,
  ): Promise<StagedDocument>;
}

export interface ContextDescriptor {
  position: number;
  memoryObjectId: string;
  documentVersionId: string;
  storageUri: string;
  fileName: string;
  mediaType: string;
  sizeBytes: number;
  contentHash: string;
  sensitivityLevel: SensitivityLevel;
  currentSensitivityLevel: SensitivityLevel;
  accessReason: string;
}

export interface ContextGrant {
  capabilityId: string;
  servicePrincipalId: string;
  agentRunId: string;
  projectId: string;
  requestFingerprint: string;
  contextSetHash: string;
  expiresAt: string;
  contexts: ContextDescriptor[];
}

export interface ContextGrantRequest {
  tokenHash: string;
  agentRunId: string;
  requestFingerprint: string;
  contextSetHash: string;
  requestId: string;
  now: string;
}

export interface StagedAgentResult {
  storageUri: string;
  expiresAt: string;
}

export type EventApplyOutcome = 'applied' | 'duplicate' | 'conflict';
export type EventPreflightOutcome = 'new' | 'duplicate' | 'conflict';

export interface DirectorRepository {
  inspectContextGrant(request: ContextGrantRequest): Promise<ContextGrant>;
  consumeContextGrant(
    request: ContextGrantRequest,
    expectedCapabilityId: string,
  ): Promise<ContextGrant>;
  preflightGatewayEvent(event: GatewayEvent): Promise<EventPreflightOutcome>;
  applyGatewayEvent(
    event: GatewayEvent,
    stagedResult: StagedAgentResult | undefined,
  ): Promise<EventApplyOutcome>;
}

export interface ServiceAuthInput {
  authorization?: string;
  socket: unknown;
}

export interface ServiceAuthenticator {
  authenticate(input: ServiceAuthInput): Promise<void> | void;
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };
