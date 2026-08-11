import type { UserSession } from './session-protocol.js';

export interface LocalIdentityCredential {
  identityId: string;
  userId: string;
  secretHash: string;
}

export interface CreateUserSessionCommand {
  sessionId: string;
  auditEventId: string;
  identityId: string;
  expectedSecretHash: string;
  tokenHash: string;
  authenticationMethod: 'local_password';
  createdAt: string;
  expiresAt: string;
  requestId: string;
  ipAddress: string | null;
  userAgent: string | null;
}

export interface CreateOidcUserSessionCommand {
  sessionId: string;
  auditEventId: string;
  providerCode: string;
  providerIssuer: string;
  providerSubject: string;
  tokenHash: string;
  authenticationMethod: string;
  createdAt: string;
  expiresAt: string;
  requestId: string;
  ipAddress: string | null;
  userAgent: string | null;
}

export interface AuthenticationFailureCommand {
  auditEventId: string;
  requestId: string;
  principalHash: string | null;
  authenticationMethod: string;
  reason: string;
  occurredAt: string;
  ipAddress: string | null;
}

export interface RevokeUserSessionCommand {
  auditEventId: string;
  sessionId: string;
  userId: string;
  requestId: string;
  revokedAt: string;
  ipAddress: string | null;
}

export interface SessionRepository {
  findLocalIdentity(login: string): Promise<LocalIdentityCredential | null>;
  createSession(command: CreateUserSessionCommand): Promise<UserSession | null>;
  createOidcSession(command: CreateOidcUserSessionCommand): Promise<UserSession | null>;
  recordAuthenticationFailure(command: AuthenticationFailureCommand): Promise<void>;
  revokeSession(command: RevokeUserSessionCommand): Promise<boolean>;
}

export interface SessionTokenGenerator {
  next(): string;
}
