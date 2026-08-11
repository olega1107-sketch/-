import { describe, expect, it } from 'vitest';

import { loadDirectorConfig } from '../src/config.js';
import { ids } from './helpers.js';

describe('Director runtime configuration', () => {
  it('uses database sessions and explicit per-agent routes in protected mode', () => {
    const config = loadDirectorConfig({
      ...baseEnvironment(),
      DIRECTOR_AGENT_ROUTES_JSON: JSON.stringify([
        {
          agent_type: 'architect',
          provider: 'internal-llm',
          model: 'architecture-v2',
          deployment_class: 'internal',
        },
        {
          agent_type: 'researcher',
          provider: 'openai',
          model: 'gpt-5',
          deployment_class: 'external',
          provider_data_profile_version: 'openai-enterprise-v1',
        },
      ]),
      DIRECTOR_TLS_CERT_PATH: '/tls/director.crt',
      DIRECTOR_TLS_KEY_PATH: '/tls/director.key',
      DIRECTOR_TLS_CA_PATH: '/tls/ca.crt',
    });

    expect(config.publicAuthentication).toEqual({ mode: 'session' });
    expect(config.localPasswordLoginEnabled).toBe(false);
    expect(config.userSessionTtlMs).toBe(12 * 60 * 60 * 1_000);
    expect(config.trustedProxyCidrs).toEqual([]);
    expect(config.gatewayClientTls).toEqual({
      certPath: '/tls/director.crt',
      keyPath: '/tls/director.key',
      caPath: '/tls/ca.crt',
    });
    expect(config.agentRouting.routes).toEqual([
      {
        agentType: 'architect',
        provider: 'internal-llm',
        model: 'architecture-v2',
        deploymentClass: 'internal',
        providerDataProfileVersion: null,
      },
      {
        agentType: 'researcher',
        provider: 'openai',
        model: 'gpt-5',
        deploymentClass: 'external',
        providerDataProfileVersion: 'openai-enterprise-v1',
      },
    ]);
    expect(config.agentRouting.fallback).toBeUndefined();
  });

  it('keeps legacy provider and static user bearer only as an insecure development fallback', () => {
    const config = loadDirectorConfig({
      ...baseEnvironment(),
      DIRECTOR_ALLOW_INSECURE_DEV: 'true',
      DIRECTOR_AGENT_PROVIDER: 'fixture',
      DIRECTOR_AGENT_MODEL: 'fixture-v1',
      DIRECTOR_PUBLIC_USER_TOKEN: 'local-user-token',
      DIRECTOR_PUBLIC_USER_ID: ids.user,
    });

    expect(config.publicAuthentication).toEqual({
      mode: 'static',
      token: 'local-user-token',
      userId: ids.user,
    });
    expect(config.agentRouting).toMatchObject({
      routes: [],
      fallback: {
        provider: 'fixture',
        model: 'fixture-v1',
        deploymentClass: 'internal',
        providerDataProfileVersion: null,
      },
    });
    expect(config.tls).toBeUndefined();
  });

  it('rejects static public authentication in protected mode', () => {
    expect(() =>
      loadDirectorConfig({
        ...baseEnvironment(),
        DIRECTOR_AGENT_ROUTES_JSON: validRoutes(),
        DIRECTOR_PUBLIC_AUTH_MODE: 'static',
        DIRECTOR_PUBLIC_USER_TOKEN: 'unsafe-static-token',
        DIRECTOR_PUBLIC_USER_ID: ids.user,
        DIRECTOR_TLS_CERT_PATH: '/tls/director.crt',
        DIRECTOR_TLS_KEY_PATH: '/tls/director.key',
        DIRECTOR_TLS_CA_PATH: '/tls/ca.crt',
      }),
    ).toThrow(/only in development mode/);

    expect(() =>
      loadDirectorConfig({
        ...baseEnvironment(),
        DIRECTOR_ALLOW_INSECURE_DEV: 'true',
        DIRECTOR_AGENT_PROVIDER: 'fixture',
        DIRECTOR_PUBLIC_USER_TOKEN: 'local-user-token',
        DIRECTOR_PUBLIC_USER_ID: ids.user,
        DIRECTOR_LOCAL_PASSWORD_LOGIN_ENABLED: 'true',
      }),
    ).toThrow(/requires session public authentication mode/);
  });

  it('enables local password login explicitly and validates the session TTL', () => {
    const config = loadDirectorConfig({
      ...baseEnvironment(),
      DIRECTOR_ALLOW_INSECURE_DEV: 'true',
      DIRECTOR_AGENT_PROVIDER: 'fixture',
      DIRECTOR_PUBLIC_AUTH_MODE: 'session',
      DIRECTOR_LOCAL_PASSWORD_LOGIN_ENABLED: 'true',
      DIRECTOR_USER_SESSION_TTL_MS: '3600000',
    });
    expect(config.publicAuthentication).toEqual({ mode: 'session' });
    expect(config.localPasswordLoginEnabled).toBe(true);
    expect(config.userSessionTtlMs).toBe(3_600_000);

    expect(() =>
      loadDirectorConfig({
        ...baseEnvironment(),
        DIRECTOR_ALLOW_INSECURE_DEV: 'true',
        DIRECTOR_AGENT_PROVIDER: 'fixture',
        DIRECTOR_PUBLIC_AUTH_MODE: 'session',
        DIRECTOR_USER_SESSION_TTL_MS: '0',
      }),
    ).toThrow(/DIRECTOR_USER_SESSION_TTL_MS/);
  });

  it('loads a complete protected OIDC configuration', () => {
    const config = loadDirectorConfig({
      ...protectedEnvironment(),
      DIRECTOR_OIDC_ISSUER_URL: 'https://idp.example.com/tenant',
      DIRECTOR_OIDC_CLIENT_ID: 'dirizhor-client',
      DIRECTOR_OIDC_CLIENT_SECRET: 'client-secret-from-manager',
      DIRECTOR_OIDC_REDIRECT_URI:
        'https://director.example.com/api/v1/auth/oidc/callback',
      DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI: 'https://director.example.com/',
      DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI:
        'https://director.example.com/signed-out',
      DIRECTOR_OIDC_PROVIDER_CODE: 'entra-prod',
      DIRECTOR_OIDC_SCOPES: 'openid profile email',
      DIRECTOR_OIDC_TOKEN_ENDPOINT_AUTH_METHOD: 'client_secret_post',
      DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG: 'PS256',
      DIRECTOR_OIDC_TRANSACTION_TTL_MS: '300000',
      DIRECTOR_OIDC_DISCOVERY_TIMEOUT_MS: '8000',
    });

    expect(config.oidcAuthentication).toEqual({
      providerCode: 'entra-prod',
      issuerUrl: 'https://idp.example.com/tenant',
      clientId: 'dirizhor-client',
      clientSecret: 'client-secret-from-manager',
      redirectUri: 'https://director.example.com/api/v1/auth/oidc/callback',
      postLoginRedirectUri: 'https://director.example.com/',
      postLogoutRedirectUri: 'https://director.example.com/signed-out',
      scopes: ['openid', 'profile', 'email'],
      tokenEndpointAuthMethod: 'client_secret_post',
      idTokenSigningAlgorithm: 'PS256',
      transactionTtlMs: 300_000,
      discoveryTimeoutMs: 8_000,
    });
  });

  it('loads a dedicated outbound Gateway mTLS identity', () => {
    const config = loadDirectorConfig({
      ...protectedEnvironment(),
      DIRECTOR_GATEWAY_CLIENT_CERT_PATH: '/tls/director-client.crt',
      DIRECTOR_GATEWAY_CLIENT_KEY_PATH: '/tls/director-client.key',
      DIRECTOR_GATEWAY_CA_PATH: '/tls/gateway-ca.crt',
    });

    expect(config.gatewayClientTls).toEqual({
      certPath: '/tls/director-client.crt',
      keyPath: '/tls/director-client.key',
      caPath: '/tls/gateway-ca.crt',
    });
  });

  it('loads runtime and OIDC secrets from mounted files', () => {
    const mounted: Record<string, string> = {
      '/run/secrets/database-url': 'postgresql://mounted/dirizhor\n',
      '/run/secrets/inbound-token': 'mounted-inbound-token\n',
      '/run/secrets/outbound-token': 'mounted-outbound-token\n',
      '/run/secrets/capability-key': `${Buffer.alloc(32, 0x5a).toString('base64')}\n`,
      '/run/secrets/oidc-client-secret': 'mounted-oidc-secret\n',
    };
    const config = loadDirectorConfig(
      {
        ...protectedEnvironment(),
        ...validOidcEnvironment(),
        DATABASE_URL: undefined,
        DATABASE_URL_FILE: '/run/secrets/database-url',
        DIRECTOR_GATEWAY_TOKEN: undefined,
        DIRECTOR_GATEWAY_TOKEN_FILE: '/run/secrets/inbound-token',
        GATEWAY_DIRECTOR_TOKEN: undefined,
        GATEWAY_DIRECTOR_TOKEN_FILE: '/run/secrets/outbound-token',
        DIRECTOR_CAPABILITY_KEY_BASE64: undefined,
        DIRECTOR_CAPABILITY_KEY_BASE64_FILE: '/run/secrets/capability-key',
        DIRECTOR_OIDC_CLIENT_SECRET: undefined,
        DIRECTOR_OIDC_CLIENT_SECRET_FILE: '/run/secrets/oidc-client-secret',
      },
      (path) => mounted[path] ?? (() => { throw new Error('missing fixture'); })(),
    );

    expect(config).toMatchObject({
      databaseUrl: 'postgresql://mounted/dirizhor',
      inboundGatewayToken: 'mounted-inbound-token',
      outboundGatewayToken: 'mounted-outbound-token',
      capabilityKeyBase64: Buffer.alloc(32, 0x5a).toString('base64'),
      oidcAuthentication: { clientSecret: 'mounted-oidc-secret' },
    });
  });

  it('rejects an empty protected mTLS peer allowlist', () => {
    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        DIRECTOR_ALLOWED_PEER_CNS: ' , ',
      }),
    ).toThrow(/DIRECTOR_ALLOWED_PEER_CNS must contain at least one/);
  });

  it('accepts explicit trusted proxy networks and rejects wildcard trust', () => {
    const config = loadDirectorConfig({
      ...protectedEnvironment(),
      DIRECTOR_TRUSTED_PROXY_CIDRS: '127.0.0.1, 10.70.0.0/24, 127.0.0.1',
    });
    expect(config.trustedProxyCidrs).toEqual(['127.0.0.1', '10.70.0.0/24']);

    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        DIRECTOR_TRUSTED_PROXY_CIDRS: '*',
      }),
    ).toThrow(/only explicit IP addresses or CIDRs/);
    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        DIRECTOR_TRUSTED_PROXY_CIDRS: 'reverse-proxy.internal',
      }),
    ).toThrow(/only explicit IP addresses or CIDRs/);
  });

  it('rejects incomplete or insecure OIDC configuration before startup', () => {
    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        DIRECTOR_OIDC_ISSUER_URL: 'https://idp.example.com',
      }),
    ).toThrow(/DIRECTOR_OIDC_.* is required/);

    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        ...validOidcEnvironment(),
        DIRECTOR_OIDC_ISSUER_URL: 'http://idp.example.com',
      }),
    ).toThrow(/absolute HTTPS URL/);

    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        ...validOidcEnvironment(),
        DIRECTOR_OIDC_REDIRECT_URI: 'https://director.example.com/wrong-callback',
      }),
    ).toThrow(/path must be \/api\/v1\/auth\/oidc\/callback/);

    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        ...validOidcEnvironment(),
        DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI: 'https://evil.example/',
      }),
    ).toThrow(/same origin/);

    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        ...validOidcEnvironment(),
        DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI: 'https://evil.example/signed-out',
      }),
    ).toThrow(/post-logout redirect must use the same origin/);

    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        ...validOidcEnvironment(),
        DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG: 'HS256',
      }),
    ).toThrow(/allowed asymmetric JWS algorithm/);

    expect(() =>
      loadDirectorConfig({
        ...protectedEnvironment(),
        ...validOidcEnvironment(),
        DIRECTOR_OIDC_TRANSACTION_TTL_MS: '59999',
      }),
    ).toThrow(/at least 60000/);

    expect(() =>
      loadDirectorConfig({
        ...baseEnvironment(),
        ...validOidcEnvironment(),
        DIRECTOR_ALLOW_INSECURE_DEV: 'true',
        DIRECTOR_AGENT_PROVIDER: 'fixture',
        DIRECTOR_PUBLIC_AUTH_MODE: 'session',
      }),
    ).toThrow(/only in protected HTTPS mode/);
  });

  it('requires explicit routing in protected mode and rejects malformed route JSON', () => {
    expect(() =>
      loadDirectorConfig({
        ...baseEnvironment(),
        DIRECTOR_TLS_CERT_PATH: '/tls/director.crt',
        DIRECTOR_TLS_KEY_PATH: '/tls/director.key',
        DIRECTOR_TLS_CA_PATH: '/tls/ca.crt',
      }),
    ).toThrow(/DIRECTOR_AGENT_ROUTES_JSON is required/);

    expect(() =>
      loadDirectorConfig({
        ...baseEnvironment(),
        DIRECTOR_AGENT_ROUTES_JSON: '{not-json}',
        DIRECTOR_TLS_CERT_PATH: '/tls/director.crt',
        DIRECTOR_TLS_KEY_PATH: '/tls/director.key',
        DIRECTOR_TLS_CA_PATH: '/tls/ca.crt',
      }),
    ).toThrow(/must be valid JSON/);
  });
});

function baseEnvironment(): NodeJS.ProcessEnv {
  return {
    DATABASE_URL: 'postgresql://director.test/dirizhor',
    DOCUMENT_STORE_ROOT: '/var/lib/director/documents',
    DIRECTOR_GATEWAY_TOKEN: 'gateway-to-director-token',
    GATEWAY_BASE_URL: 'https://gateway.internal',
    GATEWAY_DIRECTOR_TOKEN: 'director-to-gateway-token',
    DIRECTOR_CAPABILITY_KEY_BASE64: Buffer.alloc(32, 0x4a).toString('base64'),
  };
}

function validRoutes(): string {
  return JSON.stringify([
    {
      agent_type: 'architect',
      provider: 'internal-llm',
      deployment_class: 'internal',
    },
  ]);
}

function protectedEnvironment(): NodeJS.ProcessEnv {
  return {
    ...baseEnvironment(),
    DIRECTOR_AGENT_ROUTES_JSON: validRoutes(),
    DIRECTOR_TLS_CERT_PATH: '/tls/director.crt',
    DIRECTOR_TLS_KEY_PATH: '/tls/director.key',
    DIRECTOR_TLS_CA_PATH: '/tls/ca.crt',
  };
}

function validOidcEnvironment(): NodeJS.ProcessEnv {
  return {
    DIRECTOR_OIDC_ISSUER_URL: 'https://idp.example.com',
    DIRECTOR_OIDC_CLIENT_ID: 'dirizhor-client',
    DIRECTOR_OIDC_CLIENT_SECRET: 'client-secret-from-manager',
    DIRECTOR_OIDC_REDIRECT_URI:
      'https://director.example.com/api/v1/auth/oidc/callback',
    DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI: 'https://director.example.com/',
  };
}
