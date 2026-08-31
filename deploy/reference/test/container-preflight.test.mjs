import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import {
  validateContainerContract,
  validateDockerfileText,
  validatePinnedImageReference,
} from '../scripts/container-preflight.mjs';

const digest = 'a'.repeat(64);
const validEnvironment = {
  DIRIZHOR_NODE_BUILD_IMAGE: `registry.invalid/build/node@sha256:${digest}`,
  DIRIZHOR_NODE_RUNTIME_IMAGE: `registry.invalid/runtime/node@sha256:${digest}`,
  DIRIZHOR_NGINX_RUNTIME_IMAGE: `registry.invalid/runtime/nginx@sha256:${digest}`,
  DIRIZHOR_PNPM_VERSION: '11.18.0',
};

test('repository container contract passes with canonical base references', async () => {
  const report = await validateContainerContract({ environment: validEnvironment });
  assert.equal(report.status, 'ok');
  assert.equal(report.runtime_uid, 10_001);
  assert.deepEqual(report.dockerfiles, ['director', 'gateway', 'inference-adapter', 'edge', 'alert-relay']);
});

test('mutable or malformed base image references are rejected', () => {
  for (const reference of [
    'node:latest',
    'node:22',
    `NODE@sha256:${digest}`,
    'node@sha256:short',
    `node@sha512:${digest}`,
  ]) {
    assert.throws(
      () => validatePinnedImageReference(reference),
      /canonical SHA-256/,
    );
  }
});

test('pnpm version is exact and cannot float', async () => {
  await assert.rejects(
    validateContainerContract({
      environment: { ...validEnvironment, DIRIZHOR_PNPM_VERSION: 'latest' },
    }),
    /must be exactly/,
  );
});

test('Dockerfiles reject secret arguments, root users, and direct base tags', () => {
  const profile = { required: ['USER 10001:10001'] };
  const base = `# syntax=docker/dockerfile:1.7
FROM \${NODE_BUILD_IMAGE} AS build
FROM \${NODE_RUNTIME_IMAGE} AS runtime
USER 10001:10001
`;
  assert.doesNotThrow(() => validateDockerfileText(base, profile));
  assert.throws(
    () => validateDockerfileText(`${base}ARG API_TOKEN\n`, profile),
    /forbidden mutable or privileged/,
  );
  assert.throws(
    () => validateDockerfileText(base.replace('USER 10001:10001', 'USER root'), profile),
    /forbidden mutable or privileged/,
  );
  assert.doesNotThrow(() => validateDockerfileText(
    base.replace('USER 10001:10001', [
      'USER 0',
      'RUN apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0',
      'USER 10001:10001',
    ].join('\n')),
    profile,
  ));
  assert.throws(
    () => validateDockerfileText(base.replace('\${NODE_BUILD_IMAGE}', 'node:latest'), profile),
    /approved image arguments/,
  );
});

test('Node application runtimes must remove bundled npm', () => {
  const profile = {
    required: [
      'USER 10001:10001',
      'rm -rf /usr/local/lib/node_modules/npm',
      'rm -f /usr/local/bin/npm /usr/local/bin/npx',
    ],
  };
  const hardened = `# syntax=docker/dockerfile:1.7
FROM \${NODE_BUILD_IMAGE} AS build
FROM \${NODE_RUNTIME_IMAGE} AS runtime
RUN rm -rf /usr/local/lib/node_modules/npm && \\
    rm -f /usr/local/bin/npm /usr/local/bin/npx
USER 10001:10001
`;

  assert.doesNotThrow(() => validateDockerfileText(hardened, profile));
  assert.throws(
    () => validateDockerfileText(
      hardened.replace('rm -rf /usr/local/lib/node_modules/npm', 'true'),
      profile,
    ),
    /missing a required supply-chain or runtime control/,
  );
});

test('Edge TLS permission check follows Kubernetes projected-volume symlinks', async () => {
  const entrypoint = await readFile(
    new URL('../container/edge-entrypoint.sh', import.meta.url),
    'utf8',
  );
  assert.match(entrypoint, /stat -L -c '%a' \/run\/secrets\/public-tls\.key/);
});
