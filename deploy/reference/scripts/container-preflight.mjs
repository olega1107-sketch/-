import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const pinnedImagePattern = /^[a-z0-9][a-z0-9._:/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$/;
const pnpmVersionPattern = /^\d+\.\d+\.\d+$/;
const expectedPnpmVersion = '11.18.0';

const dockerfileProfiles = [
  {
    name: 'director',
    path: 'director/reference/Dockerfile',
    required: [
      'FROM ${NODE_BUILD_IMAGE} AS build',
      'FROM ${NODE_RUNTIME_IMAGE} AS runtime',
      'const p=/^[^@\\s]+@sha256:[0-9a-f]{64}$/',
      'pnpm install --frozen-lockfile --offline --ignore-scripts',
      'pnpm prune --prod',
      'apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0',
      'rm -rf /usr/local/lib/node_modules/npm',
      'rm -f /usr/local/bin/npm /usr/local/bin/npx',
      'COPY --from=build --chown=10001:10001',
      'USER 10001:10001',
      'ENTRYPOINT []',
      'CMD ["node", "dist/main.js"]',
    ],
  },
  {
    name: 'gateway',
    path: 'gateway/reference/Dockerfile',
    required: [
      'FROM ${NODE_BUILD_IMAGE} AS build',
      'FROM ${NODE_RUNTIME_IMAGE} AS runtime',
      'const p=/^[^@\\s]+@sha256:[0-9a-f]{64}$/',
      'pnpm install --frozen-lockfile --offline --ignore-scripts',
      'pnpm prune --prod',
      'apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0',
      'rm -rf /usr/local/lib/node_modules/npm',
      'rm -f /usr/local/bin/npm /usr/local/bin/npx',
      'COPY --from=build --chown=10001:10001',
      'USER 10001:10001',
      'ENTRYPOINT []',
      'CMD ["node", "dist/main.js"]',
    ],
  },
  {
    name: 'inference-adapter',
    path: 'inference/reference/Dockerfile',
    required: [
      'FROM ${NODE_BUILD_IMAGE} AS build',
      'FROM ${NODE_RUNTIME_IMAGE} AS runtime',
      'const p=/^[^@\\s]+@sha256:[0-9a-f]{64}$/',
      'pnpm install --frozen-lockfile --offline --ignore-scripts',
      'apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0',
      'rm -rf /usr/local/lib/node_modules/npm',
      'rm -f /usr/local/bin/npm /usr/local/bin/npx',
      'COPY --from=build --chown=10001:10001',
      'USER 10001:10001',
      'ENTRYPOINT []',
      'CMD ["node", "dist/main.js"]',
    ],
  },
  {
    name: 'edge',
    path: 'deploy/reference/Dockerfile.edge',
    required: [
      'FROM ${NODE_BUILD_IMAGE} AS ui-build',
      'FROM ${NGINX_RUNTIME_IMAGE} AS runtime',
      'const p=/^[^@\\s]+@sha256:[0-9a-f]{64}$/',
      'pnpm install --frozen-lockfile --offline --ignore-scripts',
      'COPY --from=ui-build --chown=10001:10001',
      'USER 10001:10001',
      'ENTRYPOINT ["/usr/local/bin/dirizhor-edge"]',
    ],
  },
];

export async function validateContainerContract({
  environment = process.env,
  workspaceRoot = defaultWorkspaceRoot,
} = {}) {
  const images = {
    node_build: requiredPinnedImage(environment, 'DIRIZHOR_NODE_BUILD_IMAGE'),
    node_runtime: requiredPinnedImage(environment, 'DIRIZHOR_NODE_RUNTIME_IMAGE'),
    nginx_runtime: requiredPinnedImage(environment, 'DIRIZHOR_NGINX_RUNTIME_IMAGE'),
  };
  const pnpmVersion = environment.DIRIZHOR_PNPM_VERSION?.trim();
  if (
    pnpmVersion === undefined ||
    !pnpmVersionPattern.test(pnpmVersion) ||
    pnpmVersion !== expectedPnpmVersion
  ) {
    throw new Error(`DIRIZHOR_PNPM_VERSION must be exactly ${expectedPnpmVersion}.`);
  }

  const root = path.resolve(workspaceRoot);
  for (const profile of dockerfileProfiles) {
    const contents = await readFile(path.join(root, profile.path), 'utf8').catch(() => {
      throw new Error('A required Dockerfile could not be read.');
    });
    validateDockerfileText(contents, profile);
  }
  await validatePackageManagers(root);
  await validateDockerIgnore(root);
  await validateEdgeFiles(root);
  await validateInferenceModelDockerfile(root);
  await validateNodeBuildDockerfile(root);

  return {
    status: 'ok',
    pnpm_version: pnpmVersion,
    base_images: Object.fromEntries(
      Object.entries(images).map(([name, reference]) => [
        name,
        reference.slice(reference.indexOf('@') + 1),
      ]),
    ),
    dockerfiles: dockerfileProfiles.map((profile) => profile.name),
    runtime_uid: 10_001,
    runtime_gid: 10_001,
  };
}

export function validateDockerfileText(contents, profile) {
  if (typeof contents !== 'string' || !contents.startsWith('# syntax=docker/dockerfile:1.7\n')) {
    throw new Error('Dockerfile must pin the supported BuildKit syntax.');
  }
  const fromLines = contents
    .split(/\r?\n/)
    .filter((line) => line.trimStart().startsWith('FROM '));
  if (
    fromLines.length !== 2 ||
    fromLines.some((line) => !/^FROM \$\{[A-Z_]+_IMAGE\} AS [a-z-]+$/.test(line))
  ) {
    throw new Error('Dockerfile base stages must use approved image arguments.');
  }
  if (
    /:latest(?:\s|$)/.test(contents) ||
    /^ADD\s/m.test(contents) ||
    /^USER\s+(?:0|root)(?::|\s|$)/m.test(contents) ||
    /^(?:ARG|ENV)\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY)[A-Z0-9_]*/m.test(
      contents,
    )
  ) {
    throw new Error('Dockerfile contains a forbidden mutable or privileged instruction.');
  }
  if (profile.required.some((marker) => !contents.includes(marker))) {
    throw new Error('Dockerfile is missing a required supply-chain or runtime control.');
  }
}

export function validatePinnedImageReference(value) {
  if (typeof value !== 'string' || !pinnedImagePattern.test(value.trim())) {
    throw new Error('Base image references must be canonical SHA-256 digest references.');
  }
  return value.trim();
}

function requiredPinnedImage(environment, name) {
  return validatePinnedImageReference(environment[name]);
}

async function validatePackageManagers(root) {
  for (const relativePath of [
    'director/reference/package.json',
    'gateway/reference/package.json',
    'inference/reference/package.json',
    'ui/reference/package.json',
  ]) {
    const document = JSON.parse(await readFile(path.join(root, relativePath), 'utf8'));
    if (document.packageManager !== `pnpm@${expectedPnpmVersion}`) {
      throw new Error('Every package must pin the approved pnpm version.');
    }
  }
}

async function validateInferenceModelDockerfile(root) {
  const contents = await readFile(path.join(root, 'inference/reference/Dockerfile.model'), 'utf8');
  const required = [
    '# syntax=docker/dockerfile:1.7',
    'ARG LLAMA_SERVER_IMAGE',
    'ARG MODEL_PREP_IMAGE',
    'FROM ${MODEL_PREP_IMAGE} AS prepare',
    'FROM ${LLAMA_SERVER_IMAGE}',
    'ARG MODEL_URL',
    'ADD --checksum=sha256:7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5',
    '${MODEL_URL} /tmp/Qwen3-4B-Q4_K_M.gguf',
    'split -b 125000000 -d -a 2',
    'test "$(find /model-parts -type f | wc -l | tr -d \' \')" = 20',
    'COPY --from=prepare --chown=10001:10001 /model-parts/part-00 /model-parts/part-00',
    'COPY --from=prepare --chown=10001:10001 /model-parts/part-19 /model-parts/part-19',
    'USER 10001:10001',
    'ENTRYPOINT ["/app/llama-server"]',
  ];
  if (
    required.some((marker) => !contents.includes(marker)) ||
    /:latest(?:\s|$)/.test(contents) ||
    /^(?:ARG|ENV)\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY)[A-Z0-9_]*/m.test(contents)
  ) {
    throw new Error('Inference model Dockerfile is missing an immutable model control.');
  }
}

async function validateNodeBuildDockerfile(root) {
  const contents = await readFile(path.join(root, 'deploy/reference/Dockerfile.node-build'), 'utf8');
  if (!contents.includes('apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0')) {
    throw new Error('Node build image is missing the approved OpenSSL security patch.');
  }
}

async function validateDockerIgnore(root) {
  const contents = await readFile(path.join(root, '.dockerignore'), 'utf8');
  for (const required of [
    '.git',
    '**/.env',
    '**/.env.*',
    '**/.npmrc',
    '**/dist',
    '**/node_modules',
    '**/*.key',
    '**/*.log',
    '**/*.pem',
  ]) {
    if (!contents.split(/\r?\n/).includes(required)) {
      throw new Error('.dockerignore is missing a required exclusion.');
    }
  }
}

async function validateEdgeFiles(root) {
  const entrypoint = path.join(
    root,
    'deploy/reference/container/edge-entrypoint.sh',
  );
  const shellCheck = spawnSync('sh', ['-n', entrypoint], {
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  if (shellCheck.error !== undefined || shellCheck.status !== 0) {
    throw new Error('Edge entrypoint shell syntax is invalid.');
  }
  const [script, nginxTemplate, proxyTemplate] = await Promise.all([
    readFile(entrypoint, 'utf8'),
    readFile(path.join(root, 'deploy/reference/nginx/nginx.conf.template'), 'utf8'),
    readFile(
      path.join(root, 'deploy/reference/nginx/director-proxy.conf.template'),
      'utf8',
    ),
  ]);
  for (const marker of [
    "umask 077",
    "safe_port PUBLIC_LISTEN_PORT \"$PUBLIC_LISTEN_PORT\" 1024",
    "safe_port DIRECTOR_PUBLIC_PORT \"$DIRECTOR_PUBLIC_PORT\" 1",
    "nginx -t -q",
    "exec nginx",
  ]) {
    if (!script.includes(marker)) {
      throw new Error('Edge entrypoint is missing a required runtime control.');
    }
  }
  if (
    !nginxTemplate.includes('${DIRIZHOR_NGINX_INCLUDE_DIR}') ||
    nginxTemplate.includes('include /etc/nginx/director-proxy.conf') ||
    !nginxTemplate.includes('map $http_x_request_id $dirizhor_request_id') ||
    !nginxTemplate.includes('"~^[0-9a-fA-F]{8}-') ||
    !proxyTemplate.includes('proxy_set_header X-Request-Id $dirizhor_request_id;')
  ) {
    throw new Error('Nginx template is missing a required runtime boundary control.');
  }
  assertTemplateVariables(
    nginxTemplate,
    new Set([
      'DIRECTOR_MAX_BODY_SIZE',
      'DIRECTOR_PUBLIC_HOST',
      'DIRECTOR_UPSTREAM_HOST',
      'DIRECTOR_UPSTREAM_PORT',
      'DIRIZHOR_NGINX_INCLUDE_DIR',
      'PUBLIC_LISTEN_PORT',
    ]),
  );
  assertTemplateVariables(
    proxyTemplate,
    new Set([
      'DIRECTOR_PUBLIC_HOST',
      'DIRECTOR_PUBLIC_PORT',
      'DIRECTOR_UPSTREAM_TLS_NAME',
    ]),
  );
}

function assertTemplateVariables(template, allowed) {
  const found = new Set(
    [...template.matchAll(/\$\{([A-Z0-9_]+)\}/g)].map((match) => match[1]),
  );
  if (
    found.size !== allowed.size ||
    [...found].some((variable) => !allowed.has(variable))
  ) {
    throw new Error('Nginx template variables differ from the allowlist.');
  }
}

async function main() {
  try {
    const report = await validateContainerContract();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown validation error.';
    process.stderr.write(`Container preflight failed: ${message}\n`);
    process.exitCode = 2;
  }
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  await main();
}
