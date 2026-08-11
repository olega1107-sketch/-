import { randomBytes, randomUUID } from 'node:crypto';

import { sha256Text } from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import type { IdGenerator } from './memory-ports.js';
import {
  dummyLocalPasswordHash,
  validateLocalPassword,
  verifyLocalPassword,
} from './local-password.js';
import { systemClock, type Clock } from './ports.js';
import type { SessionRepository, SessionTokenGenerator } from './session-ports.js';
import type { IssuedUserSession, SessionCreate } from './session-protocol.js';

export interface SessionRequestContext {
  requestId: string;
  ipAddress: string | null;
  userAgent: string | null;
}

export interface OidcSessionIdentity {
  providerCode: string;
  providerIssuer: string;
  providerSubject: string;
}

export interface SessionServiceOptions {
  repository: SessionRepository;
  clock?: Clock;
  idGenerator?: IdGenerator;
  tokenGenerator?: SessionTokenGenerator;
  passwordVerifier?: (password: string, encodedHash: string) => Promise<boolean>;
  sessionTtlMs?: number;
}

const randomIds: IdGenerator = { next: () => randomUUID() };
const maximumSessionTtlMs = 30 * 24 * 60 * 60 * 1_000;
const secureTokens: SessionTokenGenerator = {
  next: () => randomBytes(32).toString('base64url'),
};

export class SessionService {
  private readonly repository: SessionRepository;
  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;
  private readonly tokenGenerator: SessionTokenGenerator;
  private readonly passwordVerifier: (
    password: string,
    encodedHash: string,
  ) => Promise<boolean>;
  private readonly sessionTtlMs: number;

  constructor(options: SessionServiceOptions) {
    this.repository = options.repository;
    this.clock = options.clock ?? systemClock;
    this.idGenerator = options.idGenerator ?? randomIds;
    this.tokenGenerator = options.tokenGenerator ?? secureTokens;
    this.passwordVerifier = options.passwordVerifier ?? verifyLocalPassword;
    this.sessionTtlMs = positiveDuration(options.sessionTtlMs ?? 12 * 60 * 60 * 1_000);
  }

  async createSession(
    input: SessionCreate,
    context: SessionRequestContext,
  ): Promise<IssuedUserSession> {
    const login = requiredLogin(input.login);
    validatePassword(input.password);
    const now = this.clock.now();
    const occurredAt = now.toISOString();
    const credential = await this.repository.findLocalIdentity(login);
    const validPassword = await this.passwordVerifier(
      input.password,
      credential?.secretHash ?? dummyLocalPasswordHash,
    );
    if (credential === null || !validPassword) {
      await this.recordFailure(login, occurredAt, context);
      throw invalidCredentials();
    }

    const token = this.nextSessionToken();
    const expiresAt = new Date(now.getTime() + this.sessionTtlMs).toISOString();
    const session = await this.repository.createSession({
      sessionId: this.idGenerator.next(),
      auditEventId: this.idGenerator.next(),
      identityId: credential.identityId,
      expectedSecretHash: credential.secretHash,
      tokenHash: sha256Text(token),
      authenticationMethod: 'local_password',
      createdAt: occurredAt,
      expiresAt,
      requestId: context.requestId,
      ipAddress: context.ipAddress,
      userAgent: normalizedUserAgent(context.userAgent),
    });
    if (session === null) {
      await this.recordFailure(login, occurredAt, context);
      throw invalidCredentials();
    }
    return { access_token: token, token_type: 'Bearer', session };
  }

  async createOidcSession(
    identity: OidcSessionIdentity,
    context: SessionRequestContext,
  ): Promise<IssuedUserSession> {
    const providerCode = requiredProviderCode(identity.providerCode);
    const providerIssuer = requiredProviderIssuer(identity.providerIssuer);
    const providerSubject = requiredProviderSubject(identity.providerSubject);
    const authenticationMethod = `oidc:${providerCode}`;
    const now = this.clock.now();
    const createdAt = now.toISOString();
    const token = this.nextSessionToken();
    const session = await this.repository.createOidcSession({
      sessionId: this.idGenerator.next(),
      auditEventId: this.idGenerator.next(),
      providerCode,
      providerIssuer,
      providerSubject,
      tokenHash: sha256Text(token),
      authenticationMethod,
      createdAt,
      expiresAt: new Date(now.getTime() + this.sessionTtlMs).toISOString(),
      requestId: context.requestId,
      ipAddress: context.ipAddress,
      userAgent: normalizedUserAgent(context.userAgent),
    });
    if (session === null) {
      await this.recordOidcFailure(
        providerCode,
        'identity_not_provisioned',
        context,
        providerSubject,
        createdAt,
      );
      throw new DirectorProtocolError(
        403,
        'identity_not_provisioned',
        'The OIDC identity is not provisioned for Director access.',
      );
    }
    return { access_token: token, token_type: 'Bearer', session };
  }

  async recordOidcFailure(
    providerCode: string,
    reason: string,
    context: SessionRequestContext,
    providerSubject: string | null = null,
    occurredAt = this.clock.now().toISOString(),
  ): Promise<void> {
    await this.repository.recordAuthenticationFailure({
      auditEventId: this.idGenerator.next(),
      requestId: context.requestId,
      principalHash:
        providerSubject === null ? null : sha256Text(providerSubject),
      authenticationMethod: `oidc:${requiredProviderCode(providerCode)}`,
      reason,
      occurredAt,
      ipAddress: context.ipAddress,
    });
  }

  async revokeCurrentSession(
    userId: string,
    sessionId: string | null,
    context: SessionRequestContext,
  ): Promise<void> {
    if (sessionId === null) {
      throw new DirectorProtocolError(
        409,
        'session_not_available',
        'The current authentication method does not have a revocable session.',
      );
    }
    const revoked = await this.repository.revokeSession({
      auditEventId: this.idGenerator.next(),
      sessionId,
      userId,
      requestId: context.requestId,
      revokedAt: this.clock.now().toISOString(),
      ipAddress: context.ipAddress,
    });
    if (!revoked) {
      throw new DirectorProtocolError(401, 'unauthorized', 'User bearer is invalid.');
    }
  }

  private async recordFailure(
    login: string,
    occurredAt: string,
    context: SessionRequestContext,
  ): Promise<void> {
    await this.repository.recordAuthenticationFailure({
      auditEventId: this.idGenerator.next(),
      requestId: context.requestId,
      principalHash: sha256Text(login.toLowerCase()),
      authenticationMethod: 'local_password',
      reason: 'invalid_credentials',
      occurredAt,
      ipAddress: context.ipAddress,
    });
  }

  private nextSessionToken(): string {
    const token = this.tokenGenerator.next();
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
      throw new Error('Session token generator must return 32 base64url-encoded bytes.');
    }
    return token;
  }
}

function requiredLogin(value: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new DirectorProtocolError(400, 'validation_error', 'Login must not be blank.');
  }
  return normalized;
}

function validatePassword(value: string): void {
  try {
    validateLocalPassword(value);
  } catch {
    throw new DirectorProtocolError(
      400,
      'validation_error',
      'Password must contain between 1 and 1024 UTF-8 bytes.',
    );
  }
}

function requiredProviderCode(value: string): string {
  const normalized = value.trim();
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(normalized) || normalized === 'local') {
    throw new Error('OIDC provider code is invalid.');
  }
  return normalized;
}

function requiredProviderSubject(value: string): string {
  if (value.length === 0 || value.length > 2048 || value.trim().length === 0) {
    throw new DirectorProtocolError(
      401,
      'oidc_authentication_failed',
      'OIDC authentication failed.',
    );
  }
  return value;
}

function requiredProviderIssuer(value: string): string {
  let issuer: URL;
  try {
    issuer = new URL(value);
  } catch {
    throw new Error('OIDC provider issuer is invalid.');
  }
  if (
    issuer.protocol !== 'https:' ||
    issuer.username.length > 0 ||
    issuer.password.length > 0 ||
    issuer.search.length > 0 ||
    issuer.hash.length > 0 ||
    issuer.href.length > 2048
  ) {
    throw new Error('OIDC provider issuer is invalid.');
  }
  return issuer.href;
}

function normalizedUserAgent(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  const normalized = value.trim();
  return normalized.length === 0 ? null : [...normalized].slice(0, 1024).join('');
}

function positiveDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximumSessionTtlMs) {
    throw new Error('User session TTL must be between 1 millisecond and 30 days.');
  }
  return value;
}

function invalidCredentials(): DirectorProtocolError {
  return new DirectorProtocolError(401, 'unauthorized', 'Credentials are invalid.');
}
