import { sha256Text } from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import type { AuthenticatedUser, UserAuthenticator } from './memory-ports.js';
import { systemClock, type Clock, type ServiceAuthInput, type SqlDatabase } from './ports.js';
import { extractUserBearer } from './user-auth.js';

interface SessionRow {
  sessionId: string;
  userId: string;
  authenticationMethod: string;
}

export interface PostgresUserSessionAuthenticatorOptions {
  database: SqlDatabase;
  clock?: Clock;
  cookieOrigin?: string;
}

export class PostgresUserSessionAuthenticator implements UserAuthenticator {
  readonly cookieOrigin?: string;
  private readonly database: SqlDatabase;
  private readonly clock: Clock;

  constructor(options: PostgresUserSessionAuthenticatorOptions) {
    this.database = options.database;
    this.clock = options.clock ?? systemClock;
    const cookieOrigin = validatedCookieOrigin(options.cookieOrigin);
    if (cookieOrigin !== undefined) {
      this.cookieOrigin = cookieOrigin;
    }
  }

  async authenticate(input: ServiceAuthInput): Promise<AuthenticatedUser> {
    const tokenHash = sha256Text(extractUserBearer(input.authorization));
    const now = this.clock.now().toISOString();
    const result = await this.database.query<SessionRow>(
      `
        UPDATE dirizhor.user_sessions AS session
        SET last_seen_at = $2::timestamptz
        FROM dirizhor.app_users AS app_user
        WHERE session.session_token_hash = $1
          AND session.user_id = app_user.id
          AND session.created_at <= $2::timestamptz
          AND session.expires_at > $2::timestamptz
          AND session.revoked_at IS NULL
          AND app_user.status = 'active'
        RETURNING
          session.id::text AS "sessionId",
          session.user_id::text AS "userId",
          session.authentication_method AS "authenticationMethod"
      `,
      [tokenHash, now],
    );
    const session = result.rows[0];
    if (session === undefined) {
      throw new DirectorProtocolError(401, 'unauthorized', 'User bearer is invalid.');
    }
    return {
      userId: session.userId,
      sessionId: session.sessionId,
      authenticationMethod: session.authenticationMethod,
    };
  }
}

function validatedCookieOrigin(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  let origin: URL;
  try {
    origin = new URL(value);
  } catch {
    throw new Error('Session cookie origin must be an absolute HTTPS origin.');
  }
  if (
    origin.protocol !== 'https:' ||
    origin.origin !== value ||
    origin.pathname !== '/' ||
    origin.search.length > 0 ||
    origin.hash.length > 0
  ) {
    throw new Error('Session cookie origin must be an absolute HTTPS origin.');
  }
  return origin.origin;
}
