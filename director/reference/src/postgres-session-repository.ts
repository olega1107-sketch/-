import type { SqlDatabase, SqlQueryable } from './ports.js';
import type {
  AuthenticationFailureCommand,
  CreateOidcUserSessionCommand,
  CreateUserSessionCommand,
  LocalIdentityCredential,
  RevokeUserSessionCommand,
  SessionRepository,
} from './session-ports.js';
import type { UserSession } from './session-protocol.js';

interface LocalCredentialRow {
  identityId: string;
  userId: string;
  secretHash: string;
}

interface LockedIdentityRow {
  identityId: string;
  userId: string;
  userStatus: string;
}

interface LockedLocalCredentialRow extends LockedIdentityRow {
  secretHash: string;
}

interface SessionIssueCommand {
  sessionId: string;
  auditEventId: string;
  tokenHash: string;
  authenticationMethod: string;
  createdAt: string;
  expiresAt: string;
  requestId: string;
  ipAddress: string | null;
  userAgent: string | null;
}

interface RevocationRow {
  revokedAt: Date | string | null;
}

export class PostgresSessionRepository implements SessionRepository {
  constructor(private readonly database: SqlDatabase) {}

  async findLocalIdentity(login: string): Promise<LocalIdentityCredential | null> {
    const result = await this.database.query<LocalCredentialRow>(
      `
        SELECT
          user_identity.id::text AS "identityId",
          user_identity.user_id::text AS "userId",
          user_identity.secret_hash AS "secretHash"
        FROM dirizhor.user_identities AS user_identity
        JOIN dirizhor.app_users AS app_user ON app_user.id = user_identity.user_id
        WHERE user_identity.provider_code = 'local'
          AND lower(app_user.login) = lower($1)
        LIMIT 1
      `,
      [login],
    );
    const credential = result.rows[0];
    return credential === undefined ? null : credential;
  }

  async createSession(command: CreateUserSessionCommand): Promise<UserSession | null> {
    return this.database.transaction(async (transaction) => {
      const credential = await this.lockCredential(transaction, command.identityId);
      if (
        credential === undefined ||
        credential.userStatus !== 'active' ||
        credential.secretHash !== command.expectedSecretHash
      ) {
        return null;
      }
      return this.issueSession(transaction, command, credential);
    });
  }

  async createOidcSession(command: CreateOidcUserSessionCommand): Promise<UserSession | null> {
    return this.database.transaction(async (transaction) => {
      const identity = await this.lockOidcIdentity(
        transaction,
        command.providerCode,
        command.providerIssuer,
        command.providerSubject,
      );
      if (identity === undefined || identity.userStatus !== 'active') {
        return null;
      }
      return this.issueSession(transaction, command, identity);
    });
  }

  async recordAuthenticationFailure(command: AuthenticationFailureCommand): Promise<void> {
    await this.database.query(
      `
        INSERT INTO dirizhor.audit_events (
          id,
          actor_type,
          action,
          metadata,
          created_at,
          request_id,
          ip_address
        )
        VALUES (
          $1::uuid,
          'system',
          'authentication.failed',
          $2::jsonb,
          $3::timestamptz,
          $4::uuid,
          $5::inet
        )
      `,
      [
        command.auditEventId,
        JSON.stringify({
          authentication_method: command.authenticationMethod,
          ...(command.principalHash === null
            ? {}
            : { principal_hash: command.principalHash }),
          reason: command.reason,
        }),
        command.occurredAt,
        command.requestId,
        command.ipAddress,
      ],
    );
  }

  async revokeSession(command: RevokeUserSessionCommand): Promise<boolean> {
    return this.database.transaction(async (transaction) => {
      const result = await transaction.query<RevocationRow>(
        `
          SELECT revoked_at AS "revokedAt"
          FROM dirizhor.user_sessions
          WHERE id = $1::uuid
            AND user_id = $2::uuid
          FOR UPDATE
        `,
        [command.sessionId, command.userId],
      );
      const session = result.rows[0];
      if (session === undefined) {
        return false;
      }
      if (session.revokedAt !== null) {
        return true;
      }
      await transaction.query(
        `
          UPDATE dirizhor.user_sessions
          SET revoked_at = $2::timestamptz
          WHERE id = $1::uuid
        `,
        [command.sessionId, command.revokedAt],
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
            metadata,
            created_at,
            request_id,
            ip_address
          )
          VALUES (
            $1::uuid,
            'user',
            $2::uuid,
            'session.revoked',
            'user_session',
            $3::uuid,
            '{"scope":"current"}'::jsonb,
            $4::timestamptz,
            $5::uuid,
            $6::inet
          )
        `,
        [
          command.auditEventId,
          command.userId,
          command.sessionId,
          command.revokedAt,
          command.requestId,
          command.ipAddress,
        ],
      );
      return true;
    });
  }

  private async issueSession(
    transaction: SqlQueryable,
    command: SessionIssueCommand,
    identity: LockedIdentityRow,
  ): Promise<UserSession> {
    await transaction.query(
        `
          INSERT INTO dirizhor.user_sessions (
            id,
            user_id,
            session_token_hash,
            authentication_method,
            created_at,
            expires_at,
            last_seen_at,
            ip_address,
            user_agent
          )
          VALUES (
            $1::uuid,
            $2::uuid,
            $3,
            $4,
            $5::timestamptz,
            $6::timestamptz,
            $5::timestamptz,
            $7::inet,
            $8
          )
        `,
        [
          command.sessionId,
          identity.userId,
          command.tokenHash,
          command.authenticationMethod,
          command.createdAt,
          command.expiresAt,
          command.ipAddress,
          command.userAgent,
        ],
      );
    await transaction.query(
        `
          UPDATE dirizhor.user_identities
          SET last_authenticated_at = $2::timestamptz,
              updated_at = $2::timestamptz
          WHERE id = $1::uuid
        `,
        [identity.identityId, command.createdAt],
      );
    await transaction.query(
        `
          UPDATE dirizhor.app_users
          SET last_authenticated_at = $2::timestamptz,
              updated_at = $2::timestamptz
          WHERE id = $1::uuid
        `,
        [identity.userId, command.createdAt],
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
            metadata,
            created_at,
            request_id,
            ip_address
          )
          VALUES (
            $1::uuid,
            'user',
            $2::uuid,
            'authentication.succeeded',
            'user_session',
            $3::uuid,
            $4::jsonb,
            $5::timestamptz,
            $6::uuid,
            $7::inet
          )
        `,
        [
          command.auditEventId,
          identity.userId,
          command.sessionId,
          JSON.stringify({ authentication_method: command.authenticationMethod }),
          command.createdAt,
          command.requestId,
          command.ipAddress,
        ],
      );
    return {
      id: command.sessionId,
      user_id: identity.userId,
      authentication_method: command.authenticationMethod,
      created_at: command.createdAt,
      expires_at: command.expiresAt,
    };
  }

  private async lockOidcIdentity(
    transaction: SqlQueryable,
    providerCode: string,
    providerIssuer: string,
    providerSubject: string,
  ): Promise<LockedIdentityRow | undefined> {
    const result = await transaction.query<LockedIdentityRow>(
      `
        SELECT
          user_identity.id::text AS "identityId",
          user_identity.user_id::text AS "userId",
          app_user.status AS "userStatus"
        FROM dirizhor.user_identities AS user_identity
        JOIN dirizhor.app_users AS app_user ON app_user.id = user_identity.user_id
        WHERE user_identity.provider_code = $1
          AND user_identity.provider_issuer = $2
          AND user_identity.provider_subject = $3
          AND user_identity.provider_code <> 'local'
        FOR UPDATE OF user_identity, app_user
      `,
      [providerCode, providerIssuer, providerSubject],
    );
    return result.rows[0];
  }

  private async lockCredential(
    transaction: SqlQueryable,
    identityId: string,
  ): Promise<LockedLocalCredentialRow | undefined> {
    const result = await transaction.query<LockedLocalCredentialRow>(
      `
        SELECT
          user_identity.id::text AS "identityId",
          user_identity.user_id::text AS "userId",
          user_identity.secret_hash AS "secretHash",
          app_user.status AS "userStatus"
        FROM dirizhor.user_identities AS user_identity
        JOIN dirizhor.app_users AS app_user ON app_user.id = user_identity.user_id
        WHERE user_identity.id = $1::uuid
          AND user_identity.provider_code = 'local'
        FOR UPDATE OF user_identity, app_user
      `,
      [identityId],
    );
    return result.rows[0];
  }
}
