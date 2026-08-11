import type { SqlQueryable } from './ports.js';

const defaultAllowReasons = ['permissions_satisfied'] as const;
const defaultAllowObligations = ['audit_access_decision'] as const;

export interface AllowAuthorizationDecisionInput {
  principalUserId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  projectId: string | null;
  requestId: string;
  reasonCodes?: readonly string[];
  obligations?: readonly string[];
}

export interface AllowedAccessAuditInput {
  actorUserId: string;
  authorizedAction: string;
  resourceType: string;
  resourceId: string | null;
  projectId: string | null;
  requestId: string;
  authorizationDecisionId: string;
  metadata?: Readonly<Record<string, unknown>>;
}

export async function insertAllowAuthorizationDecision(
  transaction: SqlQueryable,
  input: AllowAuthorizationDecisionInput,
): Promise<string> {
  const reasonCodes = normalizedNonEmpty(
    input.reasonCodes ?? defaultAllowReasons,
    'Authorization reason code',
  );
  const obligations = normalized(input.obligations ?? defaultAllowObligations);
  const inserted = await transaction.query<{ id: string }>(
    `
      INSERT INTO dirizhor.authorization_decisions (
        principal_type,
        principal_id,
        action,
        resource_type,
        resource_id,
        project_id,
        decision,
        reason_codes,
        obligations,
        request_id
      )
      VALUES (
        'user', $1::uuid, $2, $3, $4::uuid, $5::uuid,
        'allow', $6::text[], $7::jsonb, $8::uuid
      )
      RETURNING id::text AS id
    `,
    [
      input.principalUserId,
      requiredText(input.action, 'Authorization action'),
      requiredText(input.resourceType, 'Authorization resource type'),
      input.resourceId,
      input.projectId,
      reasonCodes,
      JSON.stringify(obligations),
      input.requestId,
    ],
  );
  const id = inserted.rows[0]?.id;
  if (id === undefined) {
    throw new Error('Allow authorization decision could not be created.');
  }
  return id;
}

export async function insertAllowedAccessAudit(
  transaction: SqlQueryable,
  input: AllowedAccessAuditInput,
): Promise<void> {
  const authorizedAction = requiredText(input.authorizedAction, 'Authorized action');
  await transaction.query(
    `
      INSERT INTO dirizhor.audit_events (
        actor_type,
        actor_id,
        action,
        target_type,
        target_id,
        project_id,
        metadata,
        request_id,
        authorization_decision_id
      )
      VALUES (
        'user', $1::uuid, 'access.allowed', $2, $3::uuid,
        $4::uuid, $5::jsonb, $6::uuid, $7::uuid
      )
    `,
    [
      input.actorUserId,
      input.resourceId === null
        ? null
        : requiredText(input.resourceType, 'Authorization resource type'),
      input.resourceId,
      input.projectId,
      JSON.stringify({ ...(input.metadata ?? {}), authorized_action: authorizedAction }),
      input.requestId,
      input.authorizationDecisionId,
    ],
  );
}

function normalized(values: readonly string[]): string[] {
  return [
    ...new Set(values.map((value) => value.trim()).filter((value) => value.length > 0)),
  ];
}

function normalizedNonEmpty(values: readonly string[], label: string): string[] {
  const result = normalized(values);
  if (result.length === 0) {
    throw new Error(`${label} must not be empty.`);
  }
  return result;
}

function requiredText(value: string, label: string): string {
  const normalizedValue = value.trim();
  if (normalizedValue.length === 0) {
    throw new Error(`${label} must not be blank.`);
  }
  return normalizedValue;
}
