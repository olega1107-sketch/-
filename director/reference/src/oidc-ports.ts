export interface OidcAuthorizationRequest {
  state: string;
  nonce: string;
  codeVerifier: string;
  prompt?: 'select_account';
}

export interface OidcCallbackRequest {
  callbackUrl: URL;
  expectedState: string;
  expectedNonce: string;
  codeVerifier: string;
}

export interface OidcIdentityClaims {
  subject: string;
}

export type OidcProviderFailureKind = 'rejected' | 'unavailable';

export class OidcProviderError extends Error {
  constructor(readonly kind: OidcProviderFailureKind) {
    super(kind === 'unavailable' ? 'OIDC provider is unavailable.' : 'OIDC response was rejected.');
    this.name = 'OidcProviderError';
  }
}

export interface OidcProviderClient {
  authorizationUrl(request: OidcAuthorizationRequest): Promise<URL>;
  authenticateCallback(request: OidcCallbackRequest): Promise<OidcIdentityClaims>;
  endSessionUrl(): URL | null;
}

export interface CreateOidcLoginTransactionCommand {
  id: string;
  providerCode: string;
  browserTokenHash: string;
  stateHash: string;
  nonce: string;
  codeVerifier: string;
  createdAt: string;
  expiresAt: string;
  requestId: string;
  ipAddress: string | null;
}

export interface ConsumeOidcLoginTransactionCommand {
  providerCode: string;
  browserTokenHash: string;
  stateHash: string;
  consumedAt: string;
}

export interface OidcLoginTransaction {
  nonce: string;
  codeVerifier: string;
}

export interface OidcLoginTransactionRepository {
  create(command: CreateOidcLoginTransactionCommand): Promise<void>;
  consume(command: ConsumeOidcLoginTransactionCommand): Promise<OidcLoginTransaction | null>;
}

export interface OidcValueGenerator {
  next(): string;
}
