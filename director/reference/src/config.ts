import { isIP } from 'node:net';

import type {
  AgentRoute,
  AgentRouteDefinition,
  StaticAgentRouteResolverOptions,
} from './agent-routing.js';
import type { DeploymentClass } from './protocol.js';
import {
  oidcIdTokenSigningAlgorithm,
  type OidcIdTokenSigningAlgorithm,
} from './oidc-conformance.js';
import {
  requiredSecret,
  type SecretFileReader,
} from './secret-config.js';
import {
  parseWorkloadVerificationKeyset,
  type WorkloadVerificationKey,
} from './workload-identity.js';

export type PublicAuthenticationConfig =
  | { mode: 'session' }
  | { mode: 'static'; token: string; userId: string };

export interface OidcAuthenticationConfig {
  providerCode: string;
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  postLoginRedirectUri: string;
  postLogoutRedirectUri?: string;
  scopes: string[];
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post';
  idTokenSigningAlgorithm: OidcIdTokenSigningAlgorithm;
  transactionTtlMs: number;
  discoveryTimeoutMs: number;
}

export interface ClientTlsConfig {
  certPath: string;
  keyPath: string;
  caPath: string;
}

export interface DirectorConfig {
  host: string;
  port: number;
  databaseUrl: string;
  databaseCaPath?: string;
  databasePoolSize: number;
  documentStoreRoot: string;
  gatewayBaseUrl: string;
  serviceIdentity:
    | {
        mode: 'static-development';
        inboundToken: string;
        outboundToken: string;
      }
    | {
        mode: 'workload';
        signingKeyId: string;
        signingPrivateKeyBase64: string;
        verificationKeys: WorkloadVerificationKey[];
        tokenTtlSeconds: number;
      };
  capabilityKeyBase64: string;
  agentRouting: StaticAgentRouteResolverOptions;
  agentRunDeadlineMs: number;
  capabilityTtlMs: number;
  confirmationTtlMs: number;
  gatewayRequestTimeoutMs: number;
  publicAuthentication: PublicAuthenticationConfig;
  oidcAuthentication?: OidcAuthenticationConfig;
  localPasswordLoginEnabled: boolean;
  userSessionTtlMs: number;
  maxDocumentUploadBytes: number;
  trustedProxyCidrs: string[];
  allowInsecureDevelopment: boolean;
  resultTtlMs: number;
  gatewayClientTls?: ClientTlsConfig;
  tls?: {
    certPath: string;
    keyPath: string;
    caPath: string;
    allowedPeerCommonNames: string[];
  };
}

export function loadDirectorConfig(
  env: NodeJS.ProcessEnv = process.env,
  secretFileReader?: SecretFileReader,
): DirectorConfig {
  const allowInsecureDevelopment = env.DIRECTOR_ALLOW_INSECURE_DEV === 'true';
  const port = positiveInteger(env.DIRECTOR_PORT ?? '8444', 'DIRECTOR_PORT', 65_535);
  const databasePoolSize = positiveInteger(
    env.DIRECTOR_DATABASE_POOL_SIZE ?? '10',
    'DIRECTOR_DATABASE_POOL_SIZE',
    100,
  );
  const resultTtlMs = positiveInteger(
    env.DIRECTOR_RESULT_TTL_MS ?? String(24 * 60 * 60 * 1_000),
    'DIRECTOR_RESULT_TTL_MS',
    Number.MAX_SAFE_INTEGER,
  );
  const maxDocumentUploadBytes = positiveInteger(
    env.DIRECTOR_MAX_DOCUMENT_UPLOAD_BYTES ?? String(25 * 1024 * 1024),
    'DIRECTOR_MAX_DOCUMENT_UPLOAD_BYTES',
    Number.MAX_SAFE_INTEGER,
  );
  const agentRunDeadlineMs = positiveInteger(
    env.DIRECTOR_AGENT_RUN_DEADLINE_MS ?? String(10 * 60 * 1_000),
    'DIRECTOR_AGENT_RUN_DEADLINE_MS',
    Number.MAX_SAFE_INTEGER,
  );
  const capabilityTtlMs = positiveInteger(
    env.DIRECTOR_CAPABILITY_TTL_MS ?? String(5 * 60 * 1_000),
    'DIRECTOR_CAPABILITY_TTL_MS',
    Number.MAX_SAFE_INTEGER,
  );
  const confirmationTtlMs = positiveInteger(
    env.DIRECTOR_CONFIRMATION_TTL_MS ?? String(15 * 60 * 1_000),
    'DIRECTOR_CONFIRMATION_TTL_MS',
    Number.MAX_SAFE_INTEGER,
  );
  const gatewayRequestTimeoutMs = positiveInteger(
    env.DIRECTOR_GATEWAY_REQUEST_TIMEOUT_MS ?? '10000',
    'DIRECTOR_GATEWAY_REQUEST_TIMEOUT_MS',
    Number.MAX_SAFE_INTEGER,
  );
  const userSessionTtlMs = positiveInteger(
    env.DIRECTOR_USER_SESSION_TTL_MS ?? String(12 * 60 * 60 * 1_000),
    'DIRECTOR_USER_SESSION_TTL_MS',
    30 * 24 * 60 * 60 * 1_000,
  );
  const agentRouting = configuredAgentRouting(env, allowInsecureDevelopment);
  const publicAuthentication = configuredPublicAuthentication(
    env,
    allowInsecureDevelopment,
    secretFileReader,
  );
  const localPasswordLoginEnabled =
    env.DIRECTOR_LOCAL_PASSWORD_LOGIN_ENABLED === 'true';
  if (localPasswordLoginEnabled && publicAuthentication.mode !== 'session') {
    throw new Error('Local password login requires session public authentication mode.');
  }
  const oidcAuthentication = configuredOidcAuthentication(
    env,
    allowInsecureDevelopment,
    secretFileReader,
  );
  if (oidcAuthentication !== undefined && publicAuthentication.mode !== 'session') {
    throw new Error('OIDC login requires session public authentication mode.');
  }
  const base = {
    host: env.DIRECTOR_HOST ?? '127.0.0.1',
    port,
    databaseUrl: requiredSecret(env, 'DATABASE_URL', secretFileReader),
    databasePoolSize,
    documentStoreRoot: required(env, 'DOCUMENT_STORE_ROOT'),
    gatewayBaseUrl: required(env, 'GATEWAY_BASE_URL'),
    serviceIdentity: configuredServiceIdentity(
      env,
      allowInsecureDevelopment,
      secretFileReader,
    ),
    capabilityKeyBase64: requiredSecret(
      env,
      'DIRECTOR_CAPABILITY_KEY_BASE64',
      secretFileReader,
    ),
    agentRouting,
    agentRunDeadlineMs,
    capabilityTtlMs,
    confirmationTtlMs,
    gatewayRequestTimeoutMs,
    publicAuthentication,
    ...(oidcAuthentication === undefined ? {} : { oidcAuthentication }),
    localPasswordLoginEnabled,
    userSessionTtlMs,
    maxDocumentUploadBytes,
    trustedProxyCidrs: configuredTrustedProxyCidrs(env),
    allowInsecureDevelopment,
    resultTtlMs,
    ...(env.DIRECTOR_DATABASE_CA_PATH === undefined
      ? {}
      : { databaseCaPath: env.DIRECTOR_DATABASE_CA_PATH }),
  };
  if (allowInsecureDevelopment) {
    return base;
  }
  const tls = {
    certPath: required(env, 'DIRECTOR_TLS_CERT_PATH'),
    keyPath: required(env, 'DIRECTOR_TLS_KEY_PATH'),
    caPath: required(env, 'DIRECTOR_TLS_CA_PATH'),
    allowedPeerCommonNames: requiredPeerCommonNames(
      env.DIRECTOR_ALLOWED_PEER_CNS ?? 'agent-gateway',
      'DIRECTOR_ALLOWED_PEER_CNS',
    ),
  };
  return {
    ...base,
    tls,
    gatewayClientTls: {
      certPath: optional(env, 'DIRECTOR_GATEWAY_CLIENT_CERT_PATH') ?? tls.certPath,
      keyPath: optional(env, 'DIRECTOR_GATEWAY_CLIENT_KEY_PATH') ?? tls.keyPath,
      caPath: optional(env, 'DIRECTOR_GATEWAY_CA_PATH') ?? tls.caPath,
    },
  };
}

function configuredServiceIdentity(
  env: NodeJS.ProcessEnv,
  allowInsecureDevelopment: boolean,
  secretFileReader?: SecretFileReader,
): DirectorConfig['serviceIdentity'] {
  if (
    allowInsecureDevelopment &&
    [
      'DIRECTOR_GATEWAY_TOKEN',
      'DIRECTOR_GATEWAY_TOKEN_FILE',
      'GATEWAY_DIRECTOR_TOKEN',
      'GATEWAY_DIRECTOR_TOKEN_FILE',
    ].some((name) => env[name] !== undefined)
  ) {
    return {
      mode: 'static-development',
      inboundToken: requiredSecret(env, 'DIRECTOR_GATEWAY_TOKEN', secretFileReader),
      outboundToken: requiredSecret(env, 'GATEWAY_DIRECTOR_TOKEN', secretFileReader),
    };
  }
  for (const legacyName of [
    'DIRECTOR_GATEWAY_TOKEN',
    'DIRECTOR_GATEWAY_TOKEN_FILE',
    'GATEWAY_DIRECTOR_TOKEN',
    'GATEWAY_DIRECTOR_TOKEN_FILE',
  ]) {
    if (env[legacyName] !== undefined) {
      throw new Error(`${legacyName} is allowed only in insecure development mode.`);
    }
  }
  const tokenTtlSeconds = positiveInteger(
    env.DIRECTOR_WORKLOAD_TOKEN_TTL_SECONDS ?? '60',
    'DIRECTOR_WORKLOAD_TOKEN_TTL_SECONDS',
    300,
  );
  if (tokenTtlSeconds < 10) {
    throw new Error('DIRECTOR_WORKLOAD_TOKEN_TTL_SECONDS must be at least 10.');
  }
  return {
    mode: 'workload',
    signingKeyId: required(env, 'DIRECTOR_WORKLOAD_SIGNING_KEY_ID'),
    signingPrivateKeyBase64: requiredSecret(
      env,
      'DIRECTOR_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64',
      secretFileReader,
    ),
    verificationKeys: parseWorkloadVerificationKeyset(
      requiredSecret(env, 'GATEWAY_WORKLOAD_VERIFY_KEYS_JSON', secretFileReader),
    ),
    tokenTtlSeconds,
  };
}

export function loadOidcAuthenticationConfig(
  env: NodeJS.ProcessEnv = process.env,
  secretFileReader?: SecretFileReader,
): OidcAuthenticationConfig {
  const config = configuredOidcAuthentication(env, false, secretFileReader);
  if (config === undefined) {
    throw new Error('OIDC configuration is required.');
  }
  return config;
}

function configuredOidcAuthentication(
  env: NodeJS.ProcessEnv,
  allowInsecureDevelopment: boolean,
  secretFileReader?: SecretFileReader,
): OidcAuthenticationConfig | undefined {
  const oidcVariables = [
    'DIRECTOR_OIDC_ISSUER_URL',
    'DIRECTOR_OIDC_CLIENT_ID',
    'DIRECTOR_OIDC_CLIENT_SECRET',
    'DIRECTOR_OIDC_REDIRECT_URI',
    'DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI',
    'DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI',
    'DIRECTOR_OIDC_PROVIDER_CODE',
    'DIRECTOR_OIDC_SCOPES',
    'DIRECTOR_OIDC_TOKEN_ENDPOINT_AUTH_METHOD',
    'DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG',
    'DIRECTOR_OIDC_TRANSACTION_TTL_MS',
    'DIRECTOR_OIDC_DISCOVERY_TIMEOUT_MS',
    'DIRECTOR_OIDC_CLIENT_SECRET_FILE',
  ] as const;
  if (oidcVariables.every((name) => optional(env, name) === undefined)) {
    return undefined;
  }
  if (allowInsecureDevelopment) {
    throw new Error('OIDC login is available only in protected HTTPS mode.');
  }
  const configuredIssuerUrl = required(env, 'DIRECTOR_OIDC_ISSUER_URL');
  exactHttpsUrl(configuredIssuerUrl, 'DIRECTOR_OIDC_ISSUER_URL');
  const redirectUri = exactHttpsUrl(
    required(env, 'DIRECTOR_OIDC_REDIRECT_URI'),
    'DIRECTOR_OIDC_REDIRECT_URI',
  );
  if (redirectUri.pathname !== '/api/v1/auth/oidc/callback') {
    throw new Error(
      'DIRECTOR_OIDC_REDIRECT_URI path must be /api/v1/auth/oidc/callback.',
    );
  }
  const postLoginRedirectUri = exactHttpsUrl(
    required(env, 'DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI'),
    'DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI',
  );
  if (postLoginRedirectUri.origin !== redirectUri.origin) {
    throw new Error('OIDC callback and post-login redirect must use the same origin.');
  }
  const configuredPostLogoutRedirectUri = optional(
    env,
    'DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI',
  );
  const postLogoutRedirectUri =
    configuredPostLogoutRedirectUri === undefined
      ? undefined
      : exactHttpsUrl(
          configuredPostLogoutRedirectUri,
          'DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI',
        );
  if (
    postLogoutRedirectUri !== undefined &&
    postLogoutRedirectUri.origin !== redirectUri.origin
  ) {
    throw new Error('OIDC callback and post-logout redirect must use the same origin.');
  }
  const providerCode = optional(env, 'DIRECTOR_OIDC_PROVIDER_CODE') ?? 'corporate';
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(providerCode) || providerCode === 'local') {
    throw new Error('DIRECTOR_OIDC_PROVIDER_CODE is invalid.');
  }
  const tokenEndpointAuthMethod =
    optional(env, 'DIRECTOR_OIDC_TOKEN_ENDPOINT_AUTH_METHOD') ??
    'client_secret_basic';
  if (
    tokenEndpointAuthMethod !== 'client_secret_basic' &&
    tokenEndpointAuthMethod !== 'client_secret_post'
  ) {
    throw new Error(
      'DIRECTOR_OIDC_TOKEN_ENDPOINT_AUTH_METHOD must be client_secret_basic or client_secret_post.',
    );
  }
  const transactionTtlMs = positiveInteger(
    env.DIRECTOR_OIDC_TRANSACTION_TTL_MS ?? String(10 * 60 * 1_000),
    'DIRECTOR_OIDC_TRANSACTION_TTL_MS',
    15 * 60 * 1_000,
  );
  if (transactionTtlMs < 60_000) {
    throw new Error('DIRECTOR_OIDC_TRANSACTION_TTL_MS must be at least 60000.');
  }
  return {
    providerCode,
    issuerUrl: configuredIssuerUrl,
    clientId: required(env, 'DIRECTOR_OIDC_CLIENT_ID'),
    clientSecret: requiredSecret(
      env,
      'DIRECTOR_OIDC_CLIENT_SECRET',
      secretFileReader,
    ),
    redirectUri: redirectUri.href,
    postLoginRedirectUri: postLoginRedirectUri.href,
    ...(postLogoutRedirectUri === undefined
      ? {}
      : { postLogoutRedirectUri: postLogoutRedirectUri.href }),
    scopes: oidcScopes(optional(env, 'DIRECTOR_OIDC_SCOPES') ?? 'openid'),
    tokenEndpointAuthMethod,
    idTokenSigningAlgorithm: oidcIdTokenSigningAlgorithm(
      optional(env, 'DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG') ?? 'RS256',
    ),
    transactionTtlMs,
    discoveryTimeoutMs: positiveInteger(
      env.DIRECTOR_OIDC_DISCOVERY_TIMEOUT_MS ?? '10000',
      'DIRECTOR_OIDC_DISCOVERY_TIMEOUT_MS',
      60_000,
    ),
  };
}

function exactHttpsUrl(value: string, name: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL.`);
  }
  if (
    url.protocol !== 'https:' ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    throw new Error(`${name} must be an absolute HTTPS URL without credentials, query, or fragment.`);
  }
  return url;
}

function oidcScopes(value: string): string[] {
  const scopes = [...new Set(value.split(/[ ,]+/).filter((scope) => scope.length > 0))];
  if (
    !scopes.includes('openid') ||
    scopes.some((scope) => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))
  ) {
    throw new Error('DIRECTOR_OIDC_SCOPES must contain openid and valid OAuth scope tokens.');
  }
  return scopes;
}

function configuredAgentRouting(
  env: NodeJS.ProcessEnv,
  allowInsecureDevelopment: boolean,
): StaticAgentRouteResolverOptions {
  const encodedRoutes = optional(env, 'DIRECTOR_AGENT_ROUTES_JSON');
  if (encodedRoutes !== undefined) {
    return { routes: parseAgentRoutes(encodedRoutes) };
  }
  if (!allowInsecureDevelopment) {
    throw new Error('DIRECTOR_AGENT_ROUTES_JSON is required in protected mode.');
  }
  const provider =
    optional(env, 'DIRECTOR_AGENT_PROVIDER') ??
    optional(env, 'DIRECTOR_INTERNAL_AGENT_PROVIDER');
  if (provider === undefined) {
    throw new Error(
      'DIRECTOR_AGENT_ROUTES_JSON or DIRECTOR_AGENT_PROVIDER is required.',
    );
  }
  const fallback: AgentRoute = {
    provider,
    model:
      optional(env, 'DIRECTOR_AGENT_MODEL') ??
      optional(env, 'DIRECTOR_INTERNAL_AGENT_MODEL') ??
      null,
    deploymentClass: deploymentClass(
      env.DIRECTOR_AGENT_DEPLOYMENT_CLASS ?? 'internal',
    ),
    providerDataProfileVersion:
      optional(env, 'DIRECTOR_PROVIDER_DATA_PROFILE_VERSION') ?? null,
  };
  return { routes: [], fallback };
}

function configuredPublicAuthentication(
  env: NodeJS.ProcessEnv,
  allowInsecureDevelopment: boolean,
  secretFileReader?: SecretFileReader,
): PublicAuthenticationConfig {
  const mode = optional(env, 'DIRECTOR_PUBLIC_AUTH_MODE') ??
    (allowInsecureDevelopment ? 'static' : 'session');
  if (mode === 'session') {
    return { mode };
  }
  if (mode !== 'static') {
    throw new Error('DIRECTOR_PUBLIC_AUTH_MODE must be session or static.');
  }
  if (!allowInsecureDevelopment) {
    throw new Error('Static public authentication is allowed only in development mode.');
  }
  return {
    mode,
    token: requiredSecret(env, 'DIRECTOR_PUBLIC_USER_TOKEN', secretFileReader),
    userId: required(env, 'DIRECTOR_PUBLIC_USER_ID'),
  };
}

function parseAgentRoutes(value: string): AgentRouteDefinition[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('DIRECTOR_AGENT_ROUTES_JSON must be valid JSON.');
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('DIRECTOR_AGENT_ROUTES_JSON must be a non-empty array.');
  }
  return parsed.map((item, index) => parseAgentRoute(item, index));
}

function parseAgentRoute(value: unknown, index: number): AgentRouteDefinition {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalidAgentRoute(index);
  }
  const route = value as Record<string, unknown>;
  const allowed = new Set([
    'agent_type',
    'provider',
    'model',
    'deployment_class',
    'provider_data_profile_version',
  ]);
  if (Object.keys(route).some((key) => !allowed.has(key))) {
    throw invalidAgentRoute(index);
  }
  if (
    typeof route.agent_type !== 'string' ||
    typeof route.provider !== 'string' ||
    typeof route.deployment_class !== 'string' ||
    !nullableString(route.model) ||
    !nullableString(route.provider_data_profile_version)
  ) {
    throw invalidAgentRoute(index);
  }
  return {
    agentType: route.agent_type,
    provider: route.provider,
    model: route.model ?? null,
    deploymentClass: deploymentClass(route.deployment_class),
    providerDataProfileVersion: route.provider_data_profile_version ?? null,
  };
}

function nullableString(value: unknown): value is string | null | undefined {
  return value === undefined || value === null || typeof value === 'string';
}

function invalidAgentRoute(index: number): Error {
  return new Error(`DIRECTOR_AGENT_ROUTES_JSON route at index ${index} is invalid.`);
}

function deploymentClass(value: string): DeploymentClass {
  if (value !== 'internal' && value !== 'external') {
    throw new Error('DIRECTOR_AGENT_DEPLOYMENT_CLASS must be internal or external.');
  }
  return value;
}

function optional(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name]?.trim();
  return value === undefined || value.length === 0 ? undefined : value;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = optional(env, name);
  if (value === undefined) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function requiredPeerCommonNames(value: string, name: string): string[] {
  const commonNames = [...new Set(
    value.split(',').map((item) => item.trim()).filter((item) => item.length > 0),
  )];
  if (commonNames.length === 0) {
    throw new Error(`${name} must contain at least one certificate Common Name.`);
  }
  return commonNames;
}

function configuredTrustedProxyCidrs(env: NodeJS.ProcessEnv): string[] {
  const value = optional(env, 'DIRECTOR_TRUSTED_PROXY_CIDRS');
  if (value === undefined) return [];
  const cidrs = [...new Set(
    value.split(',').map((item) => item.trim()).filter((item) => item.length > 0),
  )];
  if (cidrs.length === 0 || cidrs.some((cidr) => !validIpOrCidr(cidr))) {
    throw new Error(
      'DIRECTOR_TRUSTED_PROXY_CIDRS must contain only explicit IP addresses or CIDRs.',
    );
  }
  return cidrs;
}

function validIpOrCidr(value: string): boolean {
  const parts = value.split('/');
  if (parts.length === 1) return isIP(value) !== 0;
  if (parts.length !== 2) return false;
  const family = isIP(parts[0]!);
  if (family === 0 || !/^\d+$/.test(parts[1]!)) return false;
  const prefix = Number(parts[1]);
  return Number.isSafeInteger(prefix) && prefix >= 0 && prefix <= (family === 4 ? 32 : 128);
}

function positiveInteger(value: string, name: string, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`${name} must be a positive integer no greater than ${maximum}.`);
  }
  return parsed;
}
