import assert from 'node:assert/strict';
import test from 'node:test';

import { loadInferenceConfig } from '../src/config.js';

test('loads a loopback-only llama runtime configuration', () => {
  const config = loadInferenceConfig(environment());
  assert.equal(config.upstreamOrigin, 'http://127.0.0.1:8080');
  assert.equal(config.model, 'Qwen3-4B-Q4_K_M');
});

test('rejects non-loopback and credential-bearing upstream origins', () => {
  assert.throws(
    () => loadInferenceConfig(environment({ LLAMA_UPSTREAM_ORIGIN: 'https://model.example.test' })),
    /loopback/,
  );
  assert.throws(
    () => loadInferenceConfig(environment({ LLAMA_UPSTREAM_ORIGIN: 'http://user:pass@127.0.0.1:8080' })),
    /loopback/,
  );
});

function environment(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    INFERENCE_MODEL: 'Qwen3-4B-Q4_K_M',
    LLAMA_UPSTREAM_ORIGIN: 'http://127.0.0.1:8080',
    INFERENCE_TOKEN_FILE: '/run/secrets/token',
    INFERENCE_TLS_CERT_PATH: '/run/tls/tls.crt',
    INFERENCE_TLS_KEY_PATH: '/run/tls/tls.key',
    INFERENCE_TLS_CA_PATH: '/run/tls/ca.crt',
    ...overrides,
  };
}
