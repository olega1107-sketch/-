import { timingSafeEqual } from 'node:crypto';

import { DirectorProtocolError } from './errors.js';
import type { AuthenticatedUser, UserAuthenticator } from './memory-ports.js';
import type { ServiceAuthInput } from './ports.js';

export interface StaticUserBearerAuthenticatorOptions {
  token: string;
  userId: string;
}

/** Development-only verifier selected only when insecure runtime mode is explicit. */
export class StaticUserBearerAuthenticator implements UserAuthenticator {
  private readonly expectedToken: Buffer;
  private readonly principal: AuthenticatedUser;

  constructor(options: StaticUserBearerAuthenticatorOptions) {
    if (options.token.length === 0) {
      throw new Error('Public user bearer token must not be empty.');
    }
    if (
      !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(
        options.userId,
      )
    ) {
      throw new Error('Public user ID must be a UUID.');
    }
    this.expectedToken = Buffer.from(options.token, 'utf8');
    this.principal = {
      userId: options.userId,
      sessionId: null,
      authenticationMethod: 'static_reference',
    };
  }

  authenticate(input: ServiceAuthInput): AuthenticatedUser {
    const received = Buffer.from(extractUserBearer(input.authorization), 'utf8');
    if (
      received.byteLength !== this.expectedToken.byteLength ||
      !timingSafeEqual(received, this.expectedToken)
    ) {
      throw new DirectorProtocolError(401, 'unauthorized', 'User bearer is invalid.');
    }
    return this.principal;
  }
}

export function extractUserBearer(authorization: string | undefined): string {
  const match = authorization?.match(/^Bearer[ \t]+(.+)$/i);
  if (match?.[1] === undefined) {
    throw new DirectorProtocolError(401, 'unauthorized', 'User bearer is required.');
  }
  return match[1];
}
