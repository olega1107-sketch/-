import { afterEach, describe, expect, it } from 'vitest';

import { userSessionCookieName } from '../src/auth-cookie.js';
import { buildDirectorApp } from '../src/app.js';
import { sha256Text } from '../src/canonical.js';
import { MemoryIngestService } from '../src/memory-ingest-service.js';
import {
  OidcProviderError,
  type OidcAuthorizationRequest,
  type OidcCallbackRequest,
  type OidcProviderClient,
} from '../src/oidc-ports.js';
import { OidcService } from '../src/oidc-service.js';
import { PostgresMemoryIngestRepository } from '../src/postgres-memory-ingest-repository.js';
import { PostgresOidcLoginTransactionRepository } from '../src/postgres-oidc-repository.js';
import { PostgresPublicQueryRepository } from '../src/postgres-public-query-repository.js';
import { PostgresSessionRepository } from '../src/postgres-session-repository.js';
import { PostgresUserSessionAuthenticator } from '../src/postgres-user-session-authenticator.js';
import { PublicQueryService } from '../src/public-query-service.js';
import { StaticBearerAuthenticator } from '../src/service-auth.js';
import { SessionService } from '../src/session-service.js';
import {
  createDirectorFixture,
  gatewayBearerToken,
  ids,
  type DirectorFixture,
} from './helpers.js';

const providerCode = 'corporate';
const issuerUrl = 'https://idp.example/';
const providerSubject = 'idp-user-42';
const externalIdentityId = '70000000-0000-4000-8000-000000000001';
const loginRequestId = '70000000-0000-4000-8000-000000000002';
const projectRequestId = '70000000-0000-4000-8000-000000000003';
const logoutRequestId = '70000000-0000-4000-8000-000000000004';
const browserToken = 'b'.repeat(43);
const state = 's'.repeat(43);
const nonce = 'n'.repeat(43);
const codeVerifier = 'v'.repeat(43);
const sessionToken = 't'.repeat(43);
const postLoginRedirect = 'https://director.example/';

describe('OIDC HTTP boundary', () => {
  let fixture: DirectorFixture | undefined;
  let app: ReturnType<typeof buildDirectorApp> | undefined;

  afterEach(async () => {
    await app?.close();
    await fixture?.close();
    app = undefined;
    fixture = undefined;
  });

  it('uses a one-time PKCE transaction, issues a cookie session, and revokes it', async () => {
    const provider = new FakeOidcProvider(providerSubject);
    ({ fixture, app } = await createOidcApp(provider, true));

    const started = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/oidc/start',
      headers: { 'x-request-id': loginRequestId },
    });
    expect(started.statusCode, started.body).toBe(302);
    expect(started.headers.location).toContain('https://idp.example/authorize?');
    expect(started.headers.location).toContain(`state=${state}`);
    expect(started.headers.location).not.toContain(codeVerifier);
    expect(started.headers['cache-control']).toBe('no-store');
    expect(started.headers['referrer-policy']).toBe('no-referrer');
    const transactionCookie = cookiePair(setCookies(started)[0]!);
    expect(setCookies(started)[0]).toContain('HttpOnly');
    expect(setCookies(started)[0]).toContain('Secure');
    expect(setCookies(started)[0]).toContain('SameSite=Lax');
    expect(setCookies(started)[0]).toContain('Max-Age=600');

    const storedBefore = await fixture.database.query<{
      browserTokenHash: string;
      stateHash: string;
      nonce: string | null;
      codeVerifier: string | null;
    }>(
      `
        SELECT
          browser_token_hash AS "browserTokenHash",
          state_hash AS "stateHash",
          nonce,
          code_verifier AS "codeVerifier"
        FROM dirizhor.oidc_login_transactions
      `,
    );
    expect(storedBefore.rows[0]).toEqual({
      browserTokenHash: sha256Text(browserToken),
      stateHash: sha256Text(state),
      nonce,
      codeVerifier,
    });
    expect(JSON.stringify(storedBefore.rows[0])).not.toContain(browserToken);
    expect(JSON.stringify(storedBefore.rows[0])).not.toContain(state);

    const completed = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/oidc/callback?code=authorization-code&state=${state}`,
      headers: { cookie: transactionCookie },
    });
    expect(completed.statusCode, completed.body).toBe(303);
    expect(completed.headers.location).toBe(postLoginRedirect);
    expect(completed.headers.location).not.toContain(sessionToken);
    const sessionSetCookie = setCookies(completed).find((value) =>
      value.startsWith(`${userSessionCookieName}=`),
    );
    expect(sessionSetCookie).toBeDefined();
    expect(sessionSetCookie).toContain('HttpOnly');
    expect(sessionSetCookie).toContain('Secure');
    const sessionCookie = cookiePair(sessionSetCookie!);

    expect(provider.callbackRequests).toHaveLength(1);
    expect(provider.callbackRequests[0]).toMatchObject({
      expectedState: state,
      expectedNonce: nonce,
      codeVerifier,
    });
    const storedAfter = await fixture.database.query<{
      nonce: string | null;
      codeVerifier: string | null;
      consumedAt: string | null;
      sessionTokenHash: string;
      authenticationMethod: string;
    }>(
      `
        SELECT
          login.nonce,
          login.code_verifier AS "codeVerifier",
          login.consumed_at::text AS "consumedAt",
          session.session_token_hash AS "sessionTokenHash",
          session.authentication_method AS "authenticationMethod"
        FROM dirizhor.oidc_login_transactions AS login
        CROSS JOIN dirizhor.user_sessions AS session
      `,
    );
    expect(storedAfter.rows[0]).toMatchObject({
      nonce: null,
      codeVerifier: null,
      sessionTokenHash: sha256Text(sessionToken),
      authenticationMethod: `oidc:${providerCode}`,
    });
    expect(storedAfter.rows[0]?.consumedAt).not.toBeNull();

    const projects = await app.inject({
      method: 'GET',
      url: '/api/v1/projects?limit=1',
      headers: { cookie: sessionCookie, 'x-request-id': projectRequestId },
    });
    expect(projects.statusCode, projects.body).toBe(200);
    expect(projects.json()).toMatchObject({ items: [{ id: ids.project }] });

    const replayed = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/oidc/callback?code=authorization-code&state=${state}`,
      headers: { cookie: transactionCookie },
    });
    expect(replayed.statusCode, replayed.body).toBe(303);
    expect(replayed.headers.location).toBe(
      `${postLoginRedirect}?auth_error=oidc_transaction_invalid`,
    );
    const sessionCount = await fixture.database.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM dirizhor.user_sessions`,
    );
    expect(sessionCount.rows[0]?.count).toBe('1');
    const replayFailureAuditCount = await fixture.database.query<{ count: string }>(
      `
        SELECT count(*)::text AS count
        FROM dirizhor.audit_events
        WHERE action = 'authentication.failed'
      `,
    );
    expect(replayFailureAuditCount.rows[0]?.count).toBe('0');

    const missingOrigin = await app.inject({
      method: 'DELETE',
      url: '/api/v1/auth/sessions/current',
      headers: {
        host: 'director.example',
        cookie: sessionCookie,
        'x-request-id': logoutRequestId,
      },
    });
    expect(missingOrigin.statusCode, missingOrigin.body).toBe(403);
    expect(missingOrigin.json()).toMatchObject({ error: { code: 'csrf_check_failed' } });

    const wrongOrigin = await app.inject({
      method: 'DELETE',
      url: '/api/v1/auth/sessions/current',
      headers: {
        host: 'director.example',
        origin: 'https://attacker.example',
        cookie: sessionCookie,
        'x-request-id': logoutRequestId,
      },
    });
    expect(wrongOrigin.statusCode, wrongOrigin.body).toBe(403);

    const loggedOut = await app.inject({
      method: 'DELETE',
      url: '/api/v1/auth/sessions/current',
      headers: {
        host: 'director.example',
        origin: 'https://director.example',
        cookie: sessionCookie,
        'x-request-id': logoutRequestId,
      },
    });
    expect(loggedOut.statusCode, loggedOut.body).toBe(204);
    expect(setCookies(loggedOut).join(';')).toContain(`${userSessionCookieName}=`);
    expect(setCookies(loggedOut).join(';')).toContain('Max-Age=0');

    const revoked = await app.inject({
      method: 'GET',
      url: '/api/v1/projects?limit=1',
      headers: { cookie: sessionCookie, 'x-request-id': projectRequestId },
    });
    expect(revoked.statusCode, revoked.body).toBe(401);
  });

  it('does not provision an unknown subject or expose it in audit metadata', async () => {
    const unknownSubject = 'sensitive-unprovisioned-subject';
    ({ fixture, app } = await createOidcApp(new FakeOidcProvider(unknownSubject), false));
    const transactionCookie = await start(app);

    const completed = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/oidc/callback?code=authorization-code&state=${state}`,
      headers: { cookie: transactionCookie },
    });
    expect(completed.statusCode, completed.body).toBe(303);
    expect(completed.headers.location).toBe(
      `${postLoginRedirect}?auth_error=identity_not_provisioned`,
    );
    const sessions = await fixture.database.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM dirizhor.user_sessions`,
    );
    expect(sessions.rows[0]?.count).toBe('0');
    const failure = await fixture.database.query<{ metadata: string }>(
      `
        SELECT metadata::text AS metadata
        FROM dirizhor.audit_events
        WHERE action = 'authentication.failed'
        ORDER BY created_at DESC
        LIMIT 1
      `,
    );
    expect(failure.rows[0]?.metadata).toContain(sha256Text(unknownSubject));
    expect(failure.rows[0]?.metadata).not.toContain(unknownSubject);
    expect(failure.rows[0]?.metadata).toContain('identity_not_provisioned');
  });

  it('revokes the local OIDC session before returning the provider logout URL', async () => {
    const provider = new FakeOidcProvider(
      providerSubject,
      new URL(
        'https://idp.example/logout?client_id=director&post_logout_redirect_uri=https%3A%2F%2Fdirector.example%2F',
      ),
    );
    ({ fixture, app } = await createOidcApp(provider, true));
    const transactionCookie = await start(app);
    const completed = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/oidc/callback?code=authorization-code&state=${state}`,
      headers: { cookie: transactionCookie },
    });
    const sessionCookie = cookiePair(
      setCookies(completed).find((value) =>
        value.startsWith(`${userSessionCookieName}=`),
      )!,
    );

    const loggedOut = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/oidc/logout',
      headers: {
        host: 'director.example',
        origin: 'https://director.example',
        cookie: sessionCookie,
        'x-request-id': logoutRequestId,
      },
    });
    expect(loggedOut.statusCode, loggedOut.body).toBe(200);
    expect(loggedOut.json()).toEqual({
      logout_url:
        'https://idp.example/logout?client_id=director&post_logout_redirect_uri=https%3A%2F%2Fdirector.example%2F',
    });
    expect(provider.endSessionRequests).toBe(1);
    expect(setCookies(loggedOut).join(';')).toContain('Max-Age=0');

    const revoked = await app.inject({
      method: 'GET',
      url: '/api/v1/projects?limit=1',
      headers: { cookie: sessionCookie, 'x-request-id': projectRequestId },
    });
    expect(revoked.statusCode, revoked.body).toBe(401);
  });

  it('consumes the transaction when the provider rejects the response', async () => {
    const provider = new FakeOidcProvider(providerSubject);
    provider.callbackError = new OidcProviderError('rejected');
    ({ fixture, app } = await createOidcApp(provider, true));
    const transactionCookie = await start(app);

    const rejected = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/oidc/callback?error=access_denied&state=${state}`,
      headers: { cookie: transactionCookie },
    });
    expect(rejected.statusCode, rejected.body).toBe(303);
    expect(rejected.headers.location).toBe(
      `${postLoginRedirect}?auth_error=oidc_authentication_failed`,
    );
    const transaction = await fixture.database.query<{
      consumedAt: string | null;
      nonce: string | null;
      codeVerifier: string | null;
    }>(
      `
        SELECT
          consumed_at::text AS "consumedAt",
          nonce,
          code_verifier AS "codeVerifier"
        FROM dirizhor.oidc_login_transactions
      `,
    );
    expect(transaction.rows[0]?.consumedAt).not.toBeNull();
    expect(transaction.rows[0]).toMatchObject({ nonce: null, codeVerifier: null });
  });

  it('reports a provider outage without exposing provider details', async () => {
    const provider = new FakeOidcProvider(providerSubject);
    provider.callbackError = new OidcProviderError('unavailable');
    ({ fixture, app } = await createOidcApp(provider, true));
    const transactionCookie = await start(app);

    const unavailable = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/oidc/callback?code=authorization-code&state=${state}`,
      headers: { cookie: transactionCookie },
    });
    expect(unavailable.statusCode, unavailable.body).toBe(303);
    expect(unavailable.headers.location).toBe(
      `${postLoginRedirect}?auth_error=oidc_provider_unavailable`,
    );
    expect(unavailable.headers.location).not.toContain('authorization-code');

    const failure = await fixture.database.query<{ metadata: string }>(
      `
        SELECT metadata::text AS metadata
        FROM dirizhor.audit_events
        WHERE action = 'authentication.failed'
      `,
    );
    expect(failure.rows).toHaveLength(1);
    expect(failure.rows[0]?.metadata).toContain('provider_unavailable');
    expect(failure.rows[0]?.metadata).not.toContain(providerSubject);
  });

  it('does not match the same provider code and subject under a different issuer', async () => {
    ({ fixture, app } = await createOidcApp(
      new FakeOidcProvider(providerSubject),
      true,
      'https://replacement-idp.example/',
    ));
    const transactionCookie = await start(app);

    const completed = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/oidc/callback?code=authorization-code&state=${state}`,
      headers: { cookie: transactionCookie },
    });
    expect(completed.statusCode, completed.body).toBe(303);
    expect(completed.headers.location).toBe(
      `${postLoginRedirect}?auth_error=identity_not_provisioned`,
    );
    const sessions = await fixture.database.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM dirizhor.user_sessions`,
    );
    expect(sessions.rows[0]?.count).toBe('0');
  });
});

async function createOidcApp(
  provider: FakeOidcProvider,
  provisionIdentity: boolean,
  provisionedIssuer = issuerUrl,
): Promise<{
  fixture: DirectorFixture;
  app: ReturnType<typeof buildDirectorApp>;
}> {
  const fixture = await createDirectorFixture();
  if (provisionIdentity) {
    await fixture.database.query(
      `
        INSERT INTO dirizhor.user_identities (
          id, user_id, provider_code, provider_issuer, provider_subject
        )
        VALUES ($1::uuid, $2::uuid, $3, $4, $5)
      `,
      [externalIdentityId, ids.user, providerCode, provisionedIssuer, providerSubject],
    );
  }
  const sessionService = new SessionService({
    repository: new PostgresSessionRepository(fixture.database),
    clock: fixture.clock,
    tokenGenerator: { next: () => sessionToken },
    sessionTtlMs: 60 * 60 * 1_000,
  });
  const oidcService = new OidcService({
    providerCode,
    issuerUrl,
    redirectUri: 'https://director.example/api/v1/auth/oidc/callback',
    repository: new PostgresOidcLoginTransactionRepository(fixture.database),
    provider,
    sessions: sessionService,
    clock: fixture.clock,
    valueGenerator: new SequenceValues([browserToken, state, nonce, codeVerifier]),
  });
  const app = buildDirectorApp({
    service: fixture.service,
    authenticator: new StaticBearerAuthenticator({
      token: gatewayBearerToken,
      requireMutualTls: false,
    }),
    publicApi: {
      memoryIngest: new MemoryIngestService({
        repository: new PostgresMemoryIngestRepository(fixture.database),
        documentStore: fixture.documentStore,
      }),
      authenticator: new PostgresUserSessionAuthenticator({
        database: fixture.database,
        clock: fixture.clock,
        cookieOrigin: 'https://director.example',
      }),
      queries: new PublicQueryService({
        repository: new PostgresPublicQueryRepository(fixture.database),
      }),
      sessions: {
        service: sessionService,
        allowLocalPasswordIssuance: false,
        oidc: { service: oidcService, postLoginRedirectUri: postLoginRedirect },
      },
    },
  });
  return { fixture, app };
}

async function start(app: ReturnType<typeof buildDirectorApp>): Promise<string> {
  const response = await app.inject({
    method: 'GET',
    url: '/api/v1/auth/oidc/start',
    headers: { 'x-request-id': loginRequestId },
  });
  expect(response.statusCode, response.body).toBe(302);
  return cookiePair(setCookies(response)[0]!);
}

function setCookies(response: { headers: Record<string, unknown> }): string[] {
  const value = response.headers['set-cookie'];
  if (Array.isArray(value)) return value.map(String);
  return value === undefined ? [] : [String(value)];
}

function cookiePair(setCookie: string): string {
  return setCookie.split(';', 1)[0]!;
}

class SequenceValues {
  constructor(private readonly values: string[]) {}

  next(): string {
    const value = this.values.shift();
    if (value === undefined) throw new Error('No OIDC test value remains.');
    return value;
  }
}

class FakeOidcProvider implements OidcProviderClient {
  readonly authorizationRequests: OidcAuthorizationRequest[] = [];
  readonly callbackRequests: OidcCallbackRequest[] = [];
  endSessionRequests = 0;
  callbackError: Error | undefined;

  constructor(
    private readonly subject: string,
    private readonly configuredEndSessionUrl: URL | null = null,
  ) {}

  async authorizationUrl(request: OidcAuthorizationRequest): Promise<URL> {
    this.authorizationRequests.push(request);
    const url = new URL('https://idp.example/authorize');
    url.searchParams.set('state', request.state);
    url.searchParams.set('nonce', request.nonce);
    return url;
  }

  async authenticateCallback(request: OidcCallbackRequest): Promise<{ subject: string }> {
    this.callbackRequests.push(request);
    if (this.callbackError !== undefined) throw this.callbackError;
    return { subject: this.subject };
  }

  endSessionUrl(): URL | null {
    this.endSessionRequests += 1;
    return this.configuredEndSessionUrl === null
      ? null
      : new URL(this.configuredEndSessionUrl);
  }
}
