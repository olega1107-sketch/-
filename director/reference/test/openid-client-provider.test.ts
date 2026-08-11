import {
  AuthorizationResponseError,
  ClientError,
  type ServerMetadata,
} from 'openid-client';
import { describe, expect, it } from 'vitest';

import {
  assertOidcConformance,
  OidcConformanceError,
} from '../src/oidc-conformance.js';
import { OidcProviderError } from '../src/oidc-ports.js';
import { mapOpenidClientError } from '../src/openid-client-provider.js';

describe('openid-client provider error mapping', () => {
  it.each(['server_error', 'temporarily_unavailable'])(
    'classifies authorization response %s as unavailable',
    (errorCode) => {
      const error = new AuthorizationResponseError('provider error', {
        cause: new URLSearchParams({ error: errorCode }),
      });

      expect(mapOpenidClientError(error)).toEqual(new OidcProviderError('unavailable'));
    },
  );

  it('classifies access_denied as rejected', () => {
    const error = new AuthorizationResponseError('provider error', {
      cause: new URLSearchParams({ error: 'access_denied' }),
    });

    expect(mapOpenidClientError(error)).toEqual(new OidcProviderError('rejected'));
  });

  it('classifies network timeouts as unavailable', () => {
    const error = new ClientError('operation timed out');
    error.code = 'OAUTH_TIMEOUT';

    expect(mapOpenidClientError(error)).toEqual(new OidcProviderError('unavailable'));
  });
});

describe('OIDC provider metadata conformance', () => {
  it('accepts the pinned authorization-code security profile', () => {
    const report = assertOidcConformance(validMetadata(), conformanceOptions());

    expect(report).toMatchObject({
      issuer: 'https://idp.example/',
      authorizationCodeFlow: true,
      pkceMethod: 'S256',
      tokenEndpointAuthMethod: 'client_secret_basic',
      idTokenSigningAlgorithm: 'RS256',
      rpInitiatedLogout: true,
      warnings: [],
    });
  });

  it.each([
    ['issuer', (metadata: Record<string, unknown>) => { metadata.issuer = 'https://other.example/'; }],
    ['S256', (metadata: Record<string, unknown>) => { metadata.code_challenge_methods_supported = ['plain']; }],
    ['signing algorithm', (metadata: Record<string, unknown>) => { metadata.id_token_signing_alg_values_supported = ['ES256']; }],
    ['HTTPS', (metadata: Record<string, unknown>) => { metadata.token_endpoint = 'http://idp.example/token'; }],
  ])('rejects non-conformant metadata for %s', (expected, mutate) => {
    const metadata = validMetadata();
    mutate(metadata as unknown as Record<string, unknown>);

    expect(() => assertOidcConformance(metadata, conformanceOptions())).toThrow(
      new RegExp(expected, 'i'),
    );
  });

  it('requires an advertised end-session endpoint only when post-logout return is configured', () => {
    const metadata = validMetadata();
    delete (metadata as { end_session_endpoint?: string }).end_session_endpoint;

    expect(() => assertOidcConformance(metadata, conformanceOptions())).toThrow(
      OidcConformanceError,
    );
    const report = assertOidcConformance(metadata, {
      ...conformanceOptions(),
      requireRpInitiatedLogout: false,
    });
    expect(report.rpInitiatedLogout).toBe(false);
    expect(report.warnings).toContainEqual(
      expect.objectContaining({ code: 'logout_not_advertised' }),
    );
  });

  it('treats incompletely advertised optional scopes and claims as warnings', () => {
    const metadata = validMetadata();
    delete (metadata as { scopes_supported?: string[] }).scopes_supported;
    delete (metadata as { claims_supported?: string[] }).claims_supported;

    const report = assertOidcConformance(metadata, conformanceOptions());
    expect(report.warnings.map((warning) => warning.code)).toEqual([
      'scopes_not_advertised',
      'claims_not_advertised',
    ]);
  });
});

function conformanceOptions() {
  return {
    expectedIssuer: 'https://idp.example/',
    requestedScopes: ['openid', 'profile'],
    tokenEndpointAuthMethod: 'client_secret_basic' as const,
    idTokenSigningAlgorithm: 'RS256' as const,
    requireRpInitiatedLogout: true,
  };
}

function validMetadata(): ServerMetadata {
  return {
    issuer: 'https://idp.example/',
    authorization_endpoint: 'https://idp.example/authorize',
    token_endpoint: 'https://idp.example/token',
    jwks_uri: 'https://idp.example/jwks',
    scopes_supported: ['openid', 'profile'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    claims_supported: ['sub'],
    end_session_endpoint: 'https://idp.example/logout',
  };
}
