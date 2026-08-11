import type {
  Confirmation,
  ConfirmationOperation,
  ConfirmationStatus,
} from './confirmation-protocol.js';

export interface ConfirmationRow {
  id: string;
  operation: ConfirmationOperation;
  targetType: string;
  targetId: string;
  projectId: string;
  requestedByUserId: string;
  decidedByUserId: string | null;
  authorizationDecisionId: string;
  requestId: string;
  status: ConfirmationStatus;
  frozenPayload: unknown;
  payloadHash: string;
  summary: string;
  createdAt: Date | string;
  expiresAt: Date | string;
  decidedAt: Date | string | null;
  consumedAt: Date | string | null;
}

export const confirmationSelect = `
  SELECT
    confirmation.id::text AS id,
    confirmation.operation,
    confirmation.target_type AS "targetType",
    confirmation.target_id::text AS "targetId",
    confirmation.project_id::text AS "projectId",
    confirmation.requested_by_user_id::text AS "requestedByUserId",
    confirmation.decided_by_user_id::text AS "decidedByUserId",
    confirmation.authorization_decision_id::text AS "authorizationDecisionId",
    confirmation.request_id::text AS "requestId",
    confirmation.status,
    confirmation.frozen_payload AS "frozenPayload",
    confirmation.payload_hash AS "payloadHash",
    confirmation.summary,
    confirmation.created_at AS "createdAt",
    confirmation.expires_at AS "expiresAt",
    confirmation.decided_at AS "decidedAt",
    confirmation.consumed_at AS "consumedAt"
  FROM dirizhor.confirmations AS confirmation
`;

export function confirmationFromRow(row: ConfirmationRow): Confirmation {
  return {
    id: row.id,
    operation: row.operation,
    target_type: row.targetType,
    target_id: row.targetId,
    project_id: row.projectId,
    requested_by_user_id: row.requestedByUserId,
    decided_by_user_id: row.decidedByUserId,
    authorization_decision_id: row.authorizationDecisionId,
    request_id: row.requestId,
    status: row.status,
    payload_hash: row.payloadHash,
    summary: row.summary,
    created_at: timestamp(row.createdAt),
    expires_at: timestamp(row.expiresAt),
    decided_at: nullableTimestamp(row.decidedAt),
    consumed_at: nullableTimestamp(row.consumedAt),
  };
}

function timestamp(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error('Database returned an invalid confirmation timestamp.');
  }
  return date.toISOString();
}

function nullableTimestamp(value: Date | string | null): string | null {
  return value === null ? null : timestamp(value);
}
