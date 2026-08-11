import type { ServerMetadata } from 'openid-client';

export type OidcIdTokenSigningAlgorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'EdDSA';

export interface OidcConformanceOptions {
  expectedIssuer: string;
  requestedScopes: string[];
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post';
  idTokenSigningAlgorithm: OidcIdTokenSigningAlgorithm;
  requireRpInitiatedLogout: boolean;
}

export interface OidcConformanceWarning {
  code: 'claims_not_advertised' | 'logout_not_advertised' | 'scopes_not_advertised';
  message: string;
}

export interface OidcConformanceReport {
  issuer: string;
  authorizationCodeFlow: true;
  pkceMethod: 'S256';
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post';
  idTokenSigningAlgorithm: OidcIdTokenSigningAlgorithm;
  rpInitiatedLogout: boolean;
  warnings: OidcConformanceWarning[];
}

export class OidcConformanceError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`OIDC provider metadata failed conformance: ${issues.join('; ')}`);
    this.name = 'OidcConformanceError';
  }
}

const asymmetricIdTokenAlgorithms = new Set<OidcIdTokenSigningAlgorithm>([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);

export function oidcIdTokenSigningAlgorithm(
  value: string,
): OidcIdTokenSigningAlgorithm {
  if (!asymmetricIdTokenAlgorithms.has(value as OidcIdTokenSigningAlgorithm)) {
    throw new Error(
      'DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG must be an allowed asymmetric JWS algorithm.',
    );
  }
  return value as OidcIdTokenSigningAlgorithm;
}

export function assertOidcConformance(
  metadata: Readonly<ServerMetadata>,
  options: OidcConformanceOptions,
): OidcConformanceReport {
  const issues: string[] = [];
  if (metadata.issuer !== options.expectedIssuer) {
    issues.push('issuer does not exactly match the configured issuer');
  }
  requiredHttpsEndpoint(metadata.authorization_endpoint, 'authorization_endpoint', issues);
  requiredHttpsEndpoint(metadata.token_endpoint, 'token_endpoint', issues);
  requiredHttpsEndpoint(metadata.jwks_uri, 'jwks_uri', issues);

  if (metadata.response_types_supported?.includes('code') !== true) {
    issues.push('response_types_supported does not include code');
  }
  if (
    metadata.grant_types_supported !== undefined &&
    !metadata.grant_types_supported.includes('authorization_code')
  ) {
    issues.push('grant_types_supported does not include authorization_code');
  }
  const tokenMethods =
    metadata.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
  if (!tokenMethods.includes(options.tokenEndpointAuthMethod)) {
    issues.push('configured token endpoint authentication method is not supported');
  }
  if (metadata.code_challenge_methods_supported?.includes('S256') !== true) {
    issues.push('code_challenge_methods_supported does not include S256');
  }
  if (
    metadata.id_token_signing_alg_values_supported?.includes(
      options.idTokenSigningAlgorithm,
    ) !== true
  ) {
    issues.push('configured ID Token signing algorithm is not supported');
  }
  if (
    metadata.subject_types_supported === undefined ||
    !metadata.subject_types_supported.some(
      (subjectType) => subjectType === 'public' || subjectType === 'pairwise',
    )
  ) {
    issues.push('subject_types_supported has no public or pairwise subject type');
  }

  const endSessionEndpoint = optionalHttpsEndpoint(
    metadata.end_session_endpoint,
    'end_session_endpoint',
    issues,
  );
  if (options.requireRpInitiatedLogout && endSessionEndpoint === null) {
    issues.push('RP-initiated logout is configured but end_session_endpoint is absent');
  }
  if (issues.length > 0) {
    throw new OidcConformanceError(issues);
  }

  const warnings: OidcConformanceWarning[] = [];
  if (metadata.scopes_supported === undefined) {
    warnings.push({
      code: 'scopes_not_advertised',
      message: 'Provider metadata does not advertise supported scopes.',
    });
  } else {
    const missingScopes = options.requestedScopes.filter(
      (scope) => !metadata.scopes_supported!.includes(scope),
    );
    if (missingScopes.length > 0) {
      warnings.push({
        code: 'scopes_not_advertised',
        message: 'Provider metadata does not advertise every requested scope.',
      });
    }
  }
  if (metadata.claims_supported?.includes('sub') !== true) {
    warnings.push({
      code: 'claims_not_advertised',
      message: 'Provider metadata does not advertise the sub claim.',
    });
  }
  if (endSessionEndpoint === null) {
    warnings.push({
      code: 'logout_not_advertised',
      message: 'Provider metadata does not advertise RP-initiated logout.',
    });
  }
  return {
    issuer: metadata.issuer,
    authorizationCodeFlow: true,
    pkceMethod: 'S256',
    tokenEndpointAuthMethod: options.tokenEndpointAuthMethod,
    idTokenSigningAlgorithm: options.idTokenSigningAlgorithm,
    rpInitiatedLogout: endSessionEndpoint !== null,
    warnings,
  };
}

function requiredHttpsEndpoint(
  value: string | undefined,
  name: string,
  issues: string[],
): void {
  if (optionalHttpsEndpoint(value, name, issues) === null) {
    issues.push(`${name} is absent`);
  }
}

function optionalHttpsEndpoint(
  value: string | undefined,
  name: string,
  issues: string[],
): URL | null {
  if (value === undefined) {
    return null;
  }
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    issues.push(`${name} is not an absolute URL`);
    return null;
  }
  if (
    endpoint.protocol !== 'https:' ||
    endpoint.username.length > 0 ||
    endpoint.password.length > 0 ||
    endpoint.hash.length > 0
  ) {
    issues.push(`${name} must be HTTPS without credentials or fragment`);
    return null;
  }
  return endpoint;
}
