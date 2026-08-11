import { randomBytes, randomUUID } from 'node:crypto';

import { sha256Text } from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import type { IdGenerator } from './memory-ports.js';
import {
  OidcProviderError,
  type OidcLoginTransactionRepository,
  type OidcProviderClient,
  type OidcValueGenerator,
} from './oidc-ports.js';
import type { OidcCallbackQuery } from './oidc-protocol.js';
import { systemClock, type Clock } from './ports.js';
import type { IssuedUserSession } from './session-protocol.js';
import {
  type SessionRequestContext,
  type SessionService,
} from './session-service.js';

export interface OidcServiceOptions {
  providerCode: string;
  issuerUrl: string;
  redirectUri: string;
  repository: OidcLoginTransactionRepository;
  provider: OidcProviderClient;
  sessions: SessionService;
  clock?: Clock;
  idGenerator?: IdGenerator;
  valueGenerator?: OidcValueGenerator;
  transactionTtlMs?: number;
}

export interface StartedOidcLogin {
  authorizationUrl: string;
  browserToken: string;
  expiresAt: string;
  maxAgeSeconds: number;
}

const randomIds: IdGenerator = { next: () => randomUUID() };
const secureValues: OidcValueGenerator = {
  next: () => randomBytes(32).toString('base64url'),
};

export class OidcService {
  private readonly providerCode: string;
  private readonly issuerUrl: string;
  private readonly redirectUri: string;
  private readonly repository: OidcLoginTransactionRepository;
  private readonly provider: OidcProviderClient;
  private readonly sessions: SessionService;
  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;
  private readonly valueGenerator: OidcValueGenerator;
  private readonly transactionTtlMs: number;

  constructor(options: OidcServiceOptions) {
    this.providerCode = options.providerCode;
    this.issuerUrl = options.issuerUrl;
    this.redirectUri = options.redirectUri;
    this.repository = options.repository;
    this.provider = options.provider;
    this.sessions = options.sessions;
    this.clock = options.clock ?? systemClock;
    this.idGenerator = options.idGenerator ?? randomIds;
    this.valueGenerator = options.valueGenerator ?? secureValues;
    this.transactionTtlMs = transactionTtl(options.transactionTtlMs ?? 10 * 60 * 1_000);
  }

  async startLogin(context: SessionRequestContext): Promise<StartedOidcLogin> {
    const browserToken = this.nextValue('browser token');
    const state = this.nextValue('state');
    const nonce = this.nextValue('nonce');
    const codeVerifier = this.nextValue('PKCE code verifier');
    const authorizationUrl = await this.provider.authorizationUrl({
      state,
      nonce,
      codeVerifier,
    });
    const now = this.clock.now();
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + this.transactionTtlMs).toISOString();
    await this.repository.create({
      id: this.idGenerator.next(),
      providerCode: this.providerCode,
      browserTokenHash: sha256Text(browserToken),
      stateHash: sha256Text(state),
      nonce,
      codeVerifier,
      createdAt,
      expiresAt,
      requestId: context.requestId,
      ipAddress: context.ipAddress,
    });
    return {
      authorizationUrl: authorizationUrl.href,
      browserToken,
      expiresAt,
      maxAgeSeconds: Math.floor(this.transactionTtlMs / 1_000),
    };
  }

  async completeLogin(
    query: OidcCallbackQuery,
    browserToken: string | undefined,
    context: SessionRequestContext,
  ): Promise<IssuedUserSession> {
    const state = query.state;
    if (!validValue(browserToken) || !validValue(state)) {
      throw oidcFailure('oidc_transaction_invalid', 400);
    }
    const transaction = await this.repository.consume({
      providerCode: this.providerCode,
      browserTokenHash: sha256Text(browserToken),
      stateHash: sha256Text(state),
      consumedAt: this.clock.now().toISOString(),
    });
    if (transaction === null) {
      throw oidcFailure('oidc_transaction_invalid', 400);
    }

    let subject: string;
    try {
      const identity = await this.provider.authenticateCallback({
        callbackUrl: callbackUrl(this.redirectUri, query),
        expectedState: state,
        expectedNonce: transaction.nonce,
        codeVerifier: transaction.codeVerifier,
      });
      subject = identity.subject;
    } catch (error) {
      const providerError =
        error instanceof OidcProviderError
          ? error
          : new OidcProviderError('unavailable');
      await this.sessions.recordOidcFailure(
        this.providerCode,
        providerError.kind === 'unavailable'
          ? 'provider_unavailable'
          : 'provider_rejected',
        context,
      );
      if (providerError.kind === 'unavailable') {
        throw oidcFailure('oidc_provider_unavailable', 503);
      }
      throw oidcFailure('oidc_authentication_failed', 401);
    }
    return this.sessions.createOidcSession(
      {
        providerCode: this.providerCode,
        providerIssuer: this.issuerUrl,
        providerSubject: subject,
      },
      context,
    );
  }

  async logoutCurrentSession(
    userId: string,
    sessionId: string | null,
    authenticationMethod: string,
    context: SessionRequestContext,
  ): Promise<string | null> {
    if (authenticationMethod !== `oidc:${this.providerCode}`) {
      throw new DirectorProtocolError(
        409,
        'oidc_session_required',
        'The current session was not issued by the configured OIDC provider.',
      );
    }
    await this.sessions.revokeCurrentSession(userId, sessionId, context);
    return this.provider.endSessionUrl()?.href ?? null;
  }

  private nextValue(label: string): string {
    const value = this.valueGenerator.next();
    if (!validValue(value)) {
      throw new Error(`OIDC ${label} generator must return 32 base64url-encoded bytes.`);
    }
    return value;
  }
}

function callbackUrl(redirectUri: string, query: OidcCallbackQuery): URL {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) {
      url.searchParams.set(key, value);
    }
  }
  return url;
}

function validValue(value: string | undefined): value is string {
  return value !== undefined && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function transactionTtl(value: number): number {
  if (!Number.isSafeInteger(value) || value < 60_000 || value > 15 * 60 * 1_000) {
    throw new Error('OIDC transaction TTL must be between 1 and 15 minutes.');
  }
  return value;
}

function oidcFailure(code: string, statusCode: number): DirectorProtocolError {
  return new DirectorProtocolError(
    statusCode,
    code,
    code === 'oidc_provider_unavailable'
      ? 'OIDC provider is temporarily unavailable.'
      : 'OIDC authentication failed.',
  );
}
