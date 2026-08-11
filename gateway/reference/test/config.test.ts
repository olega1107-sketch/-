import { describe, expect, it } from 'vitest';

import { loadGatewayConfig } from '../src/config.js';

describe('Gateway runtime configuration', () => {
  it('reuses the service identity for outbound mTLS by default', () => {
    const config = loadGatewayConfig(protectedEnvironment());

    expect(config.directorClientTls).toEqual({
      certPath: '/tls/gateway.crt',
      keyPath: '/tls/gateway.key',
      caPath: '/tls/ca.crt',
    });
  });

  it('loads a dedicated outbound Director mTLS identity', () => {
    const config = loadGatewayConfig({
      ...protectedEnvironment(),
      GATEWAY_DIRECTOR_CLIENT_CERT_PATH: '/tls/gateway-client.crt',
      GATEWAY_DIRECTOR_CLIENT_KEY_PATH: '/tls/gateway-client.key',
      GATEWAY_DIRECTOR_CA_PATH: '/tls/director-ca.crt',
    });

    expect(config.directorClientTls).toEqual({
      certPath: '/tls/gateway-client.crt',
      keyPath: '/tls/gateway-client.key',
      caPath: '/tls/director-ca.crt',
    });
  });

  it('loads runtime and provider secrets from mounted files', () => {
    const mounted: Record<string, string> = {
      '/run/secrets/spool-key': `${Buffer.alloc(32, 0x41).toString('base64')}\n`,
      '/run/secrets/signing-key': `${Buffer.alloc(48, 0x42).toString('base64')}\n`,
      '/run/secrets/verify-keys': `${verificationKeyset('director-key-mounted')}\n`,
      '/run/secrets/openai-key': 'mounted-openai-key\n',
    };
    const config = loadGatewayConfig(
      {
        ...protectedEnvironment(),
        GATEWAY_SPOOL_KEY_BASE64: undefined,
        GATEWAY_SPOOL_KEY_BASE64_FILE: '/run/secrets/spool-key',
        GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64: undefined,
        GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64_FILE: '/run/secrets/signing-key',
        DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON: undefined,
        DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON_FILE: '/run/secrets/verify-keys',
        OPENAI_API_KEY_FILE: '/run/secrets/openai-key',
      },
      (path) => mounted[path] ?? (() => { throw new Error('missing fixture'); })(),
    );

    expect(config).toMatchObject({
      spoolKeyBase64: Buffer.alloc(32, 0x41).toString('base64'),
      serviceIdentity: {
        mode: 'workload',
        signingPrivateKeyBase64: Buffer.alloc(48, 0x42).toString('base64'),
      },
      openAiApiKey: 'mounted-openai-key',
    });
  });

  it('does not construct TLS profiles in explicit insecure development mode', () => {
    const config = loadGatewayConfig({
      ...baseEnvironment(),
      GATEWAY_ALLOW_INSECURE_DEV: 'true',
    });

    expect(config.tls).toBeUndefined();
    expect(config.directorClientTls).toBeUndefined();
  });

  it('requires the protected service TLS identity', () => {
    expect(() => loadGatewayConfig(baseEnvironment())).toThrow(/GATEWAY_TLS_CERT_PATH/);
  });

  it('rejects an empty protected mTLS peer allowlist', () => {
    expect(() =>
      loadGatewayConfig({
        ...protectedEnvironment(),
        GATEWAY_ALLOWED_PEER_CNS: ' , ',
      }),
    ).toThrow(/GATEWAY_ALLOWED_PEER_CNS must contain at least one/);
  });

  it('loads a protected internal provider with model allowlist, token file, and mTLS', () => {
    const config = loadGatewayConfig(
      {
        ...protectedEnvironment(),
        INTERNAL_PROVIDER_ORIGIN: 'https://inference.internal.test',
        INTERNAL_PROVIDER_MODELS: 'internal-model-v1,internal-model-v2',
        INTERNAL_PROVIDER_TOKEN_FILE: '/run/secrets/internal-token',
        INTERNAL_PROVIDER_CLIENT_CERT_PATH: '/tls/internal-client.crt',
        INTERNAL_PROVIDER_CLIENT_KEY_PATH: '/tls/internal-client.key',
        INTERNAL_PROVIDER_CA_PATH: '/tls/internal-ca.crt',
      },
      (path) => {
        if (path === '/run/secrets/internal-token') return 'internal-token\n';
        throw new Error('missing fixture');
      },
    );

    expect(config.internalProvider).toEqual({
      origin: 'https://inference.internal.test/',
      models: ['internal-model-v1', 'internal-model-v2'],
      token: 'internal-token',
      clientTls: {
        certPath: '/tls/internal-client.crt',
        keyPath: '/tls/internal-client.key',
        caPath: '/tls/internal-ca.crt',
      },
    });
  });

  it('rejects partial, unprotected, and ambiguous internal provider configuration', () => {
    expect(() =>
      loadGatewayConfig({
        ...protectedEnvironment(),
        INTERNAL_PROVIDER_MODELS: 'internal-model-v1',
      }),
    ).toThrow(/INTERNAL_PROVIDER_ORIGIN/);
    expect(() =>
      loadGatewayConfig({
        ...protectedEnvironment(),
        INTERNAL_PROVIDER_ORIGIN: 'http://inference.internal.test',
        INTERNAL_PROVIDER_MODELS: 'internal-model-v1',
        INTERNAL_PROVIDER_TOKEN: 'token',
      }),
    ).toThrow(/exact HTTPS origin/);
    expect(() =>
      loadGatewayConfig({
        ...protectedEnvironment(),
        INTERNAL_PROVIDER_ORIGIN: 'https://inference.internal.test',
        INTERNAL_PROVIDER_MODELS: 'internal-model-v1',
        INTERNAL_PROVIDER_TOKEN: 'token',
      }),
    ).toThrow(/dedicated mTLS identity/);
    expect(() =>
      loadGatewayConfig({
        ...protectedEnvironment(),
        INTERNAL_PROVIDER_ORIGIN: 'https://inference.internal.test',
        INTERNAL_PROVIDER_MODELS: 'internal-model-v1',
        INTERNAL_PROVIDER_TOKEN: 'token',
        INTERNAL_PROVIDER_CLIENT_CERT_PATH: '/tls/client.crt',
      }),
    ).toThrow(/configured together/);
  });
});

function baseEnvironment(): NodeJS.ProcessEnv {
  return {
    GATEWAY_STATE_DIR: '/var/lib/gateway',
    GATEWAY_SPOOL_KEY_BASE64: Buffer.alloc(32, 0x31).toString('base64'),
    DIRECTOR_BASE_URL: 'https://director.internal',
    GATEWAY_WORKLOAD_SIGNING_KEY_ID: 'gateway-key-2026-08',
    GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64: Buffer.alloc(48, 0x41).toString('base64'),
    DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON: verificationKeyset('director-key-2026-08'),
    GATEWAY_ENABLE_FIXTURE_PROVIDER: 'true',
  };
}

function verificationKeyset(kid: string): string {
  return JSON.stringify({
    schema_version: 1,
    keys: [{ kid, public_key_base64: Buffer.alloc(44, 0x43).toString('base64') }],
  });
}

function protectedEnvironment(): NodeJS.ProcessEnv {
  return {
    ...baseEnvironment(),
    GATEWAY_TLS_CERT_PATH: '/tls/gateway.crt',
    GATEWAY_TLS_KEY_PATH: '/tls/gateway.key',
    GATEWAY_TLS_CA_PATH: '/tls/ca.crt',
  };
}
