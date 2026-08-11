import { isIP } from 'node:net';

import {
  optionalSecret,
  requiredSecret,
  type SecretFileReader,
} from './secret-config.js';

const hostnamePattern = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;

export interface GatewayConfig {
  host: string;
  port: number;
  stateDirectory: string;
  spoolKeyBase64: string;
  directorBaseUrl: string;
  directorServiceToken: string;
  inboundDirectorToken: string;
  allowInsecureDevelopment: boolean;
  enableFixtureProvider: boolean;
  openAiApiKey?: string;
  internalProvider?: {
    origin: string;
    models: string[];
    token: string;
    clientTls?: {
      certPath: string;
      keyPath: string;
      caPath: string;
    };
  };
  directorClientTls?: {
    certPath: string;
    keyPath: string;
    caPath: string;
  };
  tls?: {
    certPath: string;
    keyPath: string;
    caPath: string;
    allowedPeerCommonNames: string[];
  };
}

export function loadGatewayConfig(
  env: NodeJS.ProcessEnv = process.env,
  secretFileReader?: SecretFileReader,
): GatewayConfig {
  const allowInsecureDevelopment = env.GATEWAY_ALLOW_INSECURE_DEV === 'true';
  const port = Number(env.GATEWAY_PORT ?? '8443');
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('GATEWAY_PORT must be an integer between 1 and 65535.');
  }

  const base = {
    host: env.GATEWAY_HOST ?? '127.0.0.1',
    port,
    stateDirectory: required(env, 'GATEWAY_STATE_DIR'),
    spoolKeyBase64: requiredSecret(
      env,
      'GATEWAY_SPOOL_KEY_BASE64',
      secretFileReader,
    ),
    directorBaseUrl: required(env, 'DIRECTOR_BASE_URL'),
    directorServiceToken: requiredSecret(
      env,
      'DIRECTOR_SERVICE_TOKEN',
      secretFileReader,
    ),
    inboundDirectorToken: requiredSecret(
      env,
      'GATEWAY_DIRECTOR_TOKEN',
      secretFileReader,
    ),
    allowInsecureDevelopment,
    enableFixtureProvider: env.GATEWAY_ENABLE_FIXTURE_PROVIDER === 'true',
    ...optionalOpenAiApiKey(env, secretFileReader),
    ...optionalInternalProvider(
      env,
      allowInsecureDevelopment,
      secretFileReader,
    ),
  };

  if (allowInsecureDevelopment) {
    return base;
  }
  const tls = {
    certPath: required(env, 'GATEWAY_TLS_CERT_PATH'),
    keyPath: required(env, 'GATEWAY_TLS_KEY_PATH'),
    caPath: required(env, 'GATEWAY_TLS_CA_PATH'),
    allowedPeerCommonNames: requiredPeerCommonNames(
      env.GATEWAY_ALLOWED_PEER_CNS ?? 'director-api',
      'GATEWAY_ALLOWED_PEER_CNS',
    ),
  };
  return {
    ...base,
    tls,
    directorClientTls: {
      certPath: optionalPath(env, 'GATEWAY_DIRECTOR_CLIENT_CERT_PATH') ?? tls.certPath,
      keyPath: optionalPath(env, 'GATEWAY_DIRECTOR_CLIENT_KEY_PATH') ?? tls.keyPath,
      caPath: optionalPath(env, 'GATEWAY_DIRECTOR_CA_PATH') ?? tls.caPath,
    },
  };
}

function optionalInternalProvider(
  env: NodeJS.ProcessEnv,
  allowInsecureDevelopment: boolean,
  secretFileReader?: SecretFileReader,
): { internalProvider?: NonNullable<GatewayConfig['internalProvider']> } {
  const relatedNames = [
    'INTERNAL_PROVIDER_MODELS',
    'INTERNAL_PROVIDER_TOKEN',
    'INTERNAL_PROVIDER_TOKEN_FILE',
    'INTERNAL_PROVIDER_CLIENT_CERT_PATH',
    'INTERNAL_PROVIDER_CLIENT_KEY_PATH',
    'INTERNAL_PROVIDER_CA_PATH',
  ];
  const origin = env.INTERNAL_PROVIDER_ORIGIN?.trim();
  if (origin === undefined || origin.length === 0) {
    if (relatedNames.some((name) => env[name] !== undefined)) {
      throw new Error('INTERNAL_PROVIDER_ORIGIN is required when internal provider settings are present.');
    }
    return {};
  }
  const parsedOrigin = exactProviderOrigin(origin, allowInsecureDevelopment);
  const models = modelAllowlist(required(env, 'INTERNAL_PROVIDER_MODELS'));
  const token = requiredSecret(env, 'INTERNAL_PROVIDER_TOKEN', secretFileReader);
  const tlsValues = [
    optionalPath(env, 'INTERNAL_PROVIDER_CLIENT_CERT_PATH'),
    optionalPath(env, 'INTERNAL_PROVIDER_CLIENT_KEY_PATH'),
    optionalPath(env, 'INTERNAL_PROVIDER_CA_PATH'),
  ];
  const configuredTlsValues = tlsValues.filter((value) => value !== undefined);
  if (configuredTlsValues.length !== 0 && configuredTlsValues.length !== 3) {
    throw new Error('Internal provider mTLS paths must be configured together.');
  }
  if (!allowInsecureDevelopment && configuredTlsValues.length !== 3) {
    throw new Error('Protected internal provider transport requires a dedicated mTLS identity.');
  }
  const clientTls =
    configuredTlsValues.length === 0
      ? undefined
      : {
          certPath: tlsValues[0]!,
          keyPath: tlsValues[1]!,
          caPath: tlsValues[2]!,
        };
  return {
    internalProvider: {
      origin: parsedOrigin.href,
      models,
      token,
      ...(clientTls === undefined ? {} : { clientTls }),
    },
  };
}

function optionalOpenAiApiKey(
  env: NodeJS.ProcessEnv,
  secretFileReader?: SecretFileReader,
): { openAiApiKey?: string } {
  const value = optionalSecret(env, 'OPENAI_API_KEY', secretFileReader);
  return value === undefined ? {} : { openAiApiKey: value };
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function exactProviderOrigin(value: string, allowHttpForDevelopment: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('INTERNAL_PROVIDER_ORIGIN must be an absolute URL.');
  }
  if (
    (url.protocol !== 'https:' && !(allowHttpForDevelopment && url.protocol === 'http:')) ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.pathname !== '/' ||
    url.search.length > 0 ||
    url.hash.length > 0 ||
    isIP(url.hostname) !== 0 ||
    !hostnamePattern.test(url.hostname)
  ) {
    throw new Error('INTERNAL_PROVIDER_ORIGIN must be an exact HTTPS origin.');
  }
  return url;
}

function modelAllowlist(value: string): string[] {
  const models = value.split(',').map((model) => model.trim()).filter(Boolean);
  if (
    models.length === 0 ||
    models.length > 100 ||
    new Set(models).size !== models.length ||
    models.some((model) => !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(model))
  ) {
    throw new Error('INTERNAL_PROVIDER_MODELS must contain 1 through 100 model identifiers.');
  }
  return models;
}

function optionalPath(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name]?.trim();
  return value === undefined || value.length === 0 ? undefined : value;
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
