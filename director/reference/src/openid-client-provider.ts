import {
  AuthorizationResponseError,
  ClientError,
  ResponseBodyError,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  buildEndSessionUrl,
  calculatePKCECodeChallenge,
  ClientSecretBasic,
  ClientSecretPost,
  discovery,
  type Configuration,
} from 'openid-client';

import {
  assertOidcConformance,
  type OidcConformanceReport,
  type OidcIdTokenSigningAlgorithm,
} from './oidc-conformance.js';
import {
  OidcProviderError,
  type OidcAuthorizationRequest,
  type OidcCallbackRequest,
  type OidcIdentityClaims,
  type OidcProviderClient,
} from './oidc-ports.js';

export interface OpenidClientProviderConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post';
  idTokenSigningAlgorithm: OidcIdTokenSigningAlgorithm;
  postLogoutRedirectUri?: string;
  timeoutSeconds?: number;
}

export interface OpenidClientProviderResult {
  provider: OidcProviderClient;
  conformance: OidcConformanceReport;
}

const unavailableAuthorizationErrors = new Set([
  'server_error',
  'temporarily_unavailable',
]);
const unavailableClientErrorCodes = new Set([
  'OAUTH_TIMEOUT',
  'OAUTH_ABORT',
  'OAUTH_RESPONSE_IS_NOT_CONFORM',
  'OAUTH_RESPONSE_IS_NOT_JSON',
  'OAUTH_PARSE_ERROR',
]);

export async function createOpenidClientProvider(
  options: OpenidClientProviderConfig,
): Promise<OidcProviderClient> {
  return (await createOpenidClientProviderWithReport(options)).provider;
}

export async function createOpenidClientProviderWithReport(
  options: OpenidClientProviderConfig,
): Promise<OpenidClientProviderResult> {
  const clientAuthentication =
    options.tokenEndpointAuthMethod === 'client_secret_basic'
      ? ClientSecretBasic(options.clientSecret)
      : ClientSecretPost(options.clientSecret);
  const configuration = await discovery(
    new URL(options.issuerUrl),
    options.clientId,
    {
      client_secret: options.clientSecret,
      redirect_uris: [options.redirectUri],
      response_types: ['code'],
      token_endpoint_auth_method: options.tokenEndpointAuthMethod,
      id_token_signed_response_alg: options.idTokenSigningAlgorithm,
      ...(options.postLogoutRedirectUri === undefined
        ? {}
        : { post_logout_redirect_uris: [options.postLogoutRedirectUri] }),
    },
    clientAuthentication,
    { timeout: options.timeoutSeconds ?? 10 },
  );
  const conformance = assertOidcConformance(configuration.serverMetadata(), {
    expectedIssuer: options.issuerUrl,
    requestedScopes: options.scopes,
    tokenEndpointAuthMethod: options.tokenEndpointAuthMethod,
    idTokenSigningAlgorithm: options.idTokenSigningAlgorithm,
    requireRpInitiatedLogout: options.postLogoutRedirectUri !== undefined,
  });
  return {
    provider: new OpenidClientProvider(
      configuration,
      options.redirectUri,
      options.scopes,
      options.postLogoutRedirectUri,
    ),
    conformance,
  };
}

class OpenidClientProvider implements OidcProviderClient {
  constructor(
    private readonly configuration: Configuration,
    private readonly redirectUri: string,
    private readonly scopes: string[],
    private readonly postLogoutRedirectUri: string | undefined,
  ) {}

  async authorizationUrl(request: OidcAuthorizationRequest): Promise<URL> {
    const codeChallenge = await calculatePKCECodeChallenge(request.codeVerifier);
    return buildAuthorizationUrl(this.configuration, {
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: this.scopes.join(' '),
      state: request.state,
      nonce: request.nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      ...(request.prompt === undefined ? {} : { prompt: request.prompt }),
    });
  }

  async authenticateCallback(request: OidcCallbackRequest): Promise<OidcIdentityClaims> {
    try {
      const tokens = await authorizationCodeGrant(
        this.configuration,
        request.callbackUrl,
        {
          pkceCodeVerifier: request.codeVerifier,
          expectedState: request.expectedState,
          expectedNonce: request.expectedNonce,
          idTokenExpected: true,
        },
      );
      const subject = tokens.claims()?.sub;
      if (typeof subject !== 'string' || subject.length === 0) {
        throw new OidcProviderError('rejected');
      }
      return { subject };
    } catch (error) {
      if (error instanceof OidcProviderError) {
        throw error;
      }
      throw mapOpenidClientError(error);
    }
  }

  endSessionUrl(): URL | null {
    if (this.configuration.serverMetadata().end_session_endpoint === undefined) {
      return null;
    }
    return buildEndSessionUrl(this.configuration, {
      ...(this.postLogoutRedirectUri === undefined
        ? {}
        : { post_logout_redirect_uri: this.postLogoutRedirectUri }),
    });
  }
}

export function mapOpenidClientError(error: unknown): OidcProviderError {
  if (error instanceof ResponseBodyError) {
    const unavailable =
      error.status >= 500 ||
      error.error === 'server_error' ||
      error.error === 'temporarily_unavailable';
    return new OidcProviderError(unavailable ? 'unavailable' : 'rejected');
  }
  if (error instanceof AuthorizationResponseError) {
    return new OidcProviderError(
      unavailableAuthorizationErrors.has(error.error) ? 'unavailable' : 'rejected',
    );
  }
  if (error instanceof ClientError) {
    return new OidcProviderError(
      error.code !== undefined && unavailableClientErrorCodes.has(error.code)
        ? 'unavailable'
        : 'rejected',
    );
  }
  return new OidcProviderError('unavailable');
}
