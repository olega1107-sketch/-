export interface InferenceConfig {
  host: string;
  port: number;
  model: string;
  upstreamOrigin: string;
  tokenFile: string;
  tlsCertPath: string;
  tlsKeyPath: string;
  tlsCaPath: string;
  allowedPeerCommonName: string;
  maxRequestBytes: number;
  maxPromptCharacters: number;
  maxOutputTokens: number;
  upstreamTimeoutMs: number;
}

export function loadInferenceConfig(env: NodeJS.ProcessEnv = process.env): InferenceConfig {
  const port = integer(env.INFERENCE_PORT ?? '8443', 'INFERENCE_PORT', 1, 65_535);
  const upstreamOrigin = exactLoopbackOrigin(required(env, 'LLAMA_UPSTREAM_ORIGIN'));
  return {
    host: env.INFERENCE_HOST ?? '0.0.0.0',
    port,
    model: modelName(required(env, 'INFERENCE_MODEL')),
    upstreamOrigin,
    tokenFile: absolutePath(required(env, 'INFERENCE_TOKEN_FILE'), 'INFERENCE_TOKEN_FILE'),
    tlsCertPath: absolutePath(required(env, 'INFERENCE_TLS_CERT_PATH'), 'INFERENCE_TLS_CERT_PATH'),
    tlsKeyPath: absolutePath(required(env, 'INFERENCE_TLS_KEY_PATH'), 'INFERENCE_TLS_KEY_PATH'),
    tlsCaPath: absolutePath(required(env, 'INFERENCE_TLS_CA_PATH'), 'INFERENCE_TLS_CA_PATH'),
    allowedPeerCommonName: dnsLabel(
      env.INFERENCE_ALLOWED_PEER_CN ?? 'agent-gateway-internal-provider',
    ),
    maxRequestBytes: integer(
      env.INFERENCE_MAX_REQUEST_BYTES ?? '8388608',
      'INFERENCE_MAX_REQUEST_BYTES',
      1024,
      16 * 1024 * 1024,
    ),
    maxPromptCharacters: integer(
      env.INFERENCE_MAX_PROMPT_CHARACTERS ?? '48000',
      'INFERENCE_MAX_PROMPT_CHARACTERS',
      1024,
      250_000,
    ),
    maxOutputTokens: integer(
      env.INFERENCE_MAX_OUTPUT_TOKENS ?? '1024',
      'INFERENCE_MAX_OUTPUT_TOKENS',
      1,
      4096,
    ),
    upstreamTimeoutMs: integer(
      env.INFERENCE_UPSTREAM_TIMEOUT_MS ?? '120000',
      'INFERENCE_UPSTREAM_TIMEOUT_MS',
      1000,
      300_000,
    ),
  };
}

function exactLoopbackOrigin(value: string): string {
  const url = new URL(value);
  if (
    url.protocol !== 'http:' ||
    !['127.0.0.1', 'localhost', '::1'].includes(url.hostname) ||
    url.username !== '' ||
    url.password !== '' ||
    (url.pathname !== '/' && url.pathname !== '') ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new Error('LLAMA_UPSTREAM_ORIGIN must be an exact HTTP loopback origin.');
  }
  return url.origin;
}

function modelName(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(value)) {
    throw new Error('INFERENCE_MODEL is invalid.');
  }
  return value;
}

function absolutePath(value: string, name: string): string {
  if (!value.startsWith('/') || value.includes('\0')) throw new Error(`${name} must be absolute.`);
  return value;
}

function dnsLabel(value: string): string {
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) {
    throw new Error('INFERENCE_ALLOWED_PEER_CN must be a DNS label.');
  }
  return value;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (value === undefined || value.length === 0) throw new Error(`${name} is required.`);
  return value;
}

function integer(value: string, name: string, minimum: number, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}.`);
  }
  return parsed;
}
