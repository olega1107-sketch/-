import { randomUUID } from 'node:crypto';

import type { IdGenerator } from './memory-ports.js';
import type { Clock, SqlDatabase, SqlQueryable } from './ports.js';
import { systemClock } from './ports.js';

interface OidcProvisioningInputBase {
  requestId: string;
  userId: string;
  identityId: string;
  login: string;
  providerSubject: string;
}

export interface CreateOidcUserInput extends OidcProvisioningInputBase {
  operation: 'create_user';
  displayName: string;
}

export interface AttachOidcIdentityInput extends OidcProvisioningInputBase {
  operation: 'attach_identity';
}

export type OidcProvisioningInput = CreateOidcUserInput | AttachOidcIdentityInput;

export interface OidcProvisioningResult {
  outcome: 'created' | 'unchanged';
  userId: string;
  identityId: string;
}

export interface OidcProvisionerOptions {
  database: SqlDatabase;
  providerCode: string;
  issuerUrl: string;
  clock?: Clock;
  idGenerator?: IdGenerator;
}

export class OidcProvisioningError extends Error {
  constructor(
    readonly code:
      | 'conflict'
      | 'database_failure'
      | 'invalid_input'
      | 'user_not_eligible',
  ) {
    super(`OIDC identity provisioning failed: ${code}.`);
    this.name = 'OidcProvisioningError';
  }
}

interface UserRow {
  id: string;
  login: string;
  displayName: string;
  status: string;
}

interface IdentityRow {
  id: string;
  userId: string;
  providerCode: string;
  providerIssuer: string | null;
  providerSubject: string;
}

const randomIds: IdGenerator = { next: () => randomUUID() };
const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

export class OidcProvisioner {
  private readonly database: SqlDatabase;
  private readonly providerCode: string;
  private readonly issuerUrl: string;
  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;

  constructor(options: OidcProvisionerOptions) {
    this.database = options.database;
    this.providerCode = validProviderCode(options.providerCode);
    this.issuerUrl = validIssuer(options.issuerUrl);
    this.clock = options.clock ?? systemClock;
    this.idGenerator = options.idGenerator ?? randomIds;
  }

  async provision(input: OidcProvisioningInput): Promise<OidcProvisioningResult> {
    const validated = validateOidcProvisioningInput(input);
    try {
      return await this.database.transaction(async (transaction) => {
        const user = await this.lockUser(transaction, validated.userId);
        if (validated.operation === 'create_user') {
          await this.ensureCreatedUser(transaction, validated, user);
        } else if (
          user === undefined ||
          user.status !== 'active' ||
          user.login.toLowerCase() !== validated.login.toLowerCase()
        ) {
          throw new OidcProvisioningError('user_not_eligible');
        }

        const identities = await this.lockConflictingIdentities(transaction, validated);
        const exact = identities.find(
          (identity) =>
            identity.id === validated.identityId &&
            identity.userId === validated.userId &&
            identity.providerCode === this.providerCode &&
            identity.providerIssuer === this.issuerUrl &&
            identity.providerSubject === validated.providerSubject,
        );
        if (exact !== undefined && identities.length === 1) {
          return {
            outcome: 'unchanged',
            userId: validated.userId,
            identityId: validated.identityId,
          };
        }
        if (identities.length > 0) {
          throw new OidcProvisioningError('conflict');
        }

        const occurredAt = this.clock.now().toISOString();
        await transaction.query(
          `
            INSERT INTO dirizhor.user_identities (
              id, user_id, provider_code, provider_issuer, provider_subject,
              created_at, updated_at
            )
            VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::timestamptz, $6::timestamptz)
          `,
          [
            validated.identityId,
            validated.userId,
            this.providerCode,
            this.issuerUrl,
            validated.providerSubject,
            occurredAt,
          ],
        );
        await transaction.query(
          `
            INSERT INTO dirizhor.audit_events (
              id, actor_type, action, target_type, target_id, metadata,
              created_at, request_id
            )
            VALUES (
              $1::uuid, 'system', 'identity.provisioned', 'user_identity',
              $2::uuid, $3::jsonb, $4::timestamptz, $5::uuid
            )
          `,
          [
            this.idGenerator.next(),
            validated.identityId,
            JSON.stringify({
              operation: validated.operation,
              provider_code: this.providerCode,
            }),
            occurredAt,
            validated.requestId,
          ],
        );
        return {
          outcome: 'created',
          userId: validated.userId,
          identityId: validated.identityId,
        };
      });
    } catch (error) {
      if (error instanceof OidcProvisioningError) {
        throw error;
      }
      throw new OidcProvisioningError(
        databaseConstraintViolation(error) ? 'conflict' : 'database_failure',
      );
    }
  }

  private async lockUser(
    transaction: SqlQueryable,
    userId: string,
  ): Promise<UserRow | undefined> {
    const result = await transaction.query<UserRow>(
      `
        SELECT
          id::text AS id,
          login,
          display_name AS "displayName",
          status
        FROM dirizhor.app_users
        WHERE id = $1::uuid
        FOR UPDATE
      `,
      [userId],
    );
    return result.rows[0];
  }

  private async ensureCreatedUser(
    transaction: SqlQueryable,
    input: CreateOidcUserInput,
    user: UserRow | undefined,
  ): Promise<void> {
    if (user !== undefined) {
      if (
        user.status !== 'active' ||
        user.login.toLowerCase() !== input.login.toLowerCase() ||
        user.displayName !== input.displayName
      ) {
        throw new OidcProvisioningError('conflict');
      }
      return;
    }
    const loginCollision = await transaction.query<{ id: string }>(
      `SELECT id::text AS id FROM dirizhor.app_users WHERE lower(login) = lower($1)`,
      [input.login],
    );
    if (loginCollision.rows.length > 0) {
      throw new OidcProvisioningError('conflict');
    }
    const occurredAt = this.clock.now().toISOString();
    await transaction.query(
      `
        INSERT INTO dirizhor.app_users (
          id, login, display_name, status, created_at, updated_at
        )
        VALUES ($1::uuid, $2, $3, 'active', $4::timestamptz, $4::timestamptz)
      `,
      [input.userId, input.login, input.displayName, occurredAt],
    );
  }

  private async lockConflictingIdentities(
    transaction: SqlQueryable,
    input: OidcProvisioningInput,
  ): Promise<IdentityRow[]> {
    const result = await transaction.query<IdentityRow>(
      `
        SELECT
          id::text AS id,
          user_id::text AS "userId",
          provider_code AS "providerCode",
          provider_issuer AS "providerIssuer",
          provider_subject AS "providerSubject"
        FROM dirizhor.user_identities
        WHERE id = $1::uuid
          OR (provider_issuer = $2 AND provider_subject = $3)
          OR (provider_code = $4 AND provider_subject = $3)
          OR (user_id = $5::uuid AND provider_code = $4)
        ORDER BY id
        FOR UPDATE
      `,
      [
        input.identityId,
        this.issuerUrl,
        input.providerSubject,
        this.providerCode,
        input.userId,
      ],
    );
    return result.rows;
  }
}

function databaseConstraintViolation(error: unknown): boolean {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return false;
  }
  const code = (error as { code?: unknown }).code;
  return code === '23503' || code === '23505' || code === '23514';
}

export function parseOidcProvisioningInput(value: unknown): OidcProvisioningInput {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new OidcProvisioningError('invalid_input');
  }
  const input = value as Record<string, unknown>;
  const operation = input.operation;
  const allowed = new Set([
    'operation',
    'request_id',
    'user_id',
    'identity_id',
    'login',
    'provider_subject',
    ...(operation === 'create_user' ? ['display_name'] : []),
  ]);
  if (
    (operation !== 'create_user' && operation !== 'attach_identity') ||
    Object.keys(input).some((key) => !allowed.has(key))
  ) {
    throw new OidcProvisioningError('invalid_input');
  }
  const common = {
    requestId: stringField(input.request_id),
    userId: stringField(input.user_id),
    identityId: stringField(input.identity_id),
    login: stringField(input.login),
    providerSubject: stringField(input.provider_subject, false),
  };
  return operation === 'create_user'
    ? {
        operation,
        ...common,
        displayName: stringField(input.display_name),
      }
    : { operation, ...common };
}

function validateOidcProvisioningInput(
  input: OidcProvisioningInput,
): OidcProvisioningInput {
  if (
    !uuidPattern.test(input.requestId) ||
    !uuidPattern.test(input.userId) ||
    !uuidPattern.test(input.identityId) ||
    input.login.length > 320 ||
    input.login.trim().length === 0 ||
    input.login.includes('\0') ||
    input.providerSubject.length > 2048 ||
    input.providerSubject.trim().length === 0 ||
    input.providerSubject.includes('\0') ||
    (input.operation === 'create_user' &&
      (input.displayName.length > 320 ||
        input.displayName.trim().length === 0 ||
        input.displayName.includes('\0')))
  ) {
    throw new OidcProvisioningError('invalid_input');
  }
  return input;
}

function stringField(value: unknown, trim = true): string {
  if (typeof value !== 'string') {
    throw new OidcProvisioningError('invalid_input');
  }
  const normalized = trim ? value.trim() : value;
  if (normalized.length === 0 || normalized.trim().length === 0) {
    throw new OidcProvisioningError('invalid_input');
  }
  return normalized;
}

function validProviderCode(value: string): string {
  const normalized = value.trim();
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(normalized) || normalized === 'local') {
    throw new OidcProvisioningError('invalid_input');
  }
  return normalized;
}

function validIssuer(value: string): string {
  let issuer: URL;
  try {
    issuer = new URL(value);
  } catch {
    throw new OidcProvisioningError('invalid_input');
  }
  if (
    issuer.protocol !== 'https:' ||
    issuer.username.length > 0 ||
    issuer.password.length > 0 ||
    issuer.search.length > 0 ||
    issuer.hash.length > 0 ||
    issuer.href.length > 2048
  ) {
    throw new OidcProvisioningError('invalid_input');
  }
  return issuer.href;
}
