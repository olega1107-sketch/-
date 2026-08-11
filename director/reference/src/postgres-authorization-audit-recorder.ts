import { randomUUID } from 'node:crypto';

import type {
  AuthorizationAuditRecorder,
  AuthorizationDenial,
} from './authorization-audit.js';
import type { IdGenerator } from './memory-ports.js';
import {
  systemClock,
  type Clock,
  type SqlDatabase,
  type SqlQueryable,
} from './ports.js';

export interface PostgresAuthorizationAuditRecorderOptions {
  database: SqlDatabase;
  clock?: Clock;
  idGenerator?: IdGenerator;
}

const randomIds: IdGenerator = { next: () => randomUUID() };

export class PostgresAuthorizationAuditRecorder implements AuthorizationAuditRecorder {
  private readonly database: SqlDatabase;
  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;

  constructor(options: PostgresAuthorizationAuditRecorderOptions) {
    this.database = options.database;
    this.clock = options.clock ?? systemClock;
    this.idGenerator = options.idGenerator ?? randomIds;
  }

  async recordDenied(denial: AuthorizationDenial): Promise<void> {
    const decisionId = this.idGenerator.next();
    const auditEventId = this.idGenerator.next();
    const createdAt = this.clock.now().toISOString();
    const reasonCodes = normalizedNonEmpty(denial.reasonCodes, 'Authorization reason code');
    const missingPermissions = normalized(denial.missingPermissions);
    await this.database.transaction(async (transaction) => {
      const projectId = await resolveProjectId(transaction, denial);
      await transaction.query(
        `
          INSERT INTO dirizhor.authorization_decisions (
            id,
            principal_type,
            principal_id,
            action,
            resource_type,
            resource_id,
            project_id,
            decision,
            reason_codes,
            obligations,
            request_id,
            created_at
          )
          VALUES (
            $1::uuid,
            'user',
            $2::uuid,
            $3,
            $4,
            $5::uuid,
            $6::uuid,
            'deny',
            $7::text[],
            '["audit_access_decision"]'::jsonb,
            $8::uuid,
            $9::timestamptz
          )
        `,
        [
          decisionId,
          denial.principalUserId,
          requiredText(denial.action, 'Authorization action'),
          requiredText(denial.resourceType, 'Authorization resource type'),
          denial.resourceId,
          projectId,
          reasonCodes,
          denial.requestId,
          createdAt,
        ],
      );
      await transaction.query(
        `
          INSERT INTO dirizhor.audit_events (
            id,
            actor_type,
            actor_id,
            action,
            target_type,
            target_id,
            project_id,
            metadata,
            created_at,
            request_id,
            authorization_decision_id
          )
          VALUES (
            $1::uuid,
            'user',
            $2::uuid,
            'access.denied',
            $3,
            $4::uuid,
            $5::uuid,
            $6::jsonb,
            $7::timestamptz,
            $8::uuid,
            $9::uuid
          )
        `,
        [
          auditEventId,
          denial.actorUserId,
          denial.resourceId === null ? null : denial.resourceType,
          denial.resourceId,
          projectId,
          JSON.stringify({
            action: denial.action,
            reason_codes: reasonCodes,
            missing_permissions: missingPermissions,
            evaluated_principal_id: denial.principalUserId,
            response_concealed: denial.responseConcealed,
            response_status: denial.responseStatusCode,
            response_code: denial.responseCode,
          }),
          createdAt,
          denial.requestId,
          decisionId,
        ],
      );
    });
  }
}

async function resolveProjectId(
  transaction: SqlQueryable,
  denial: AuthorizationDenial,
): Promise<string | null> {
  if (denial.projectId !== null) {
    return denial.projectId;
  }
  if (denial.resourceId === null) {
    return null;
  }
  if (denial.resourceType === 'project') {
    return denial.resourceId;
  }
  const source = projectSource(denial.resourceType);
  if (source === null) {
    return null;
  }
  const result = await transaction.query<{ projectId: string }>(
    `
      SELECT project_id::text AS "projectId"
      FROM ${source}
      WHERE id = $1::uuid
    `,
    [denial.resourceId],
  );
  return result.rows[0]?.projectId ?? null;
}

function projectSource(resourceType: string): string | null {
  switch (resourceType) {
    case 'memory_object':
      return 'dirizhor.memory_objects';
    case 'task':
      return 'dirizhor.tasks';
    case 'agent_run':
      return 'dirizhor.agent_runs';
    case 'confirmation':
      return 'dirizhor.confirmations';
    default:
      return null;
  }
}

function normalized(values: readonly string[]): string[] {
  return [
    ...new Set(
      values.map((value) => value.trim()).filter((value) => value.length > 0),
    ),
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
