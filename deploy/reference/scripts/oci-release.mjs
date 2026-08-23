import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstat, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { validateContainerContract } from './container-preflight.mjs';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const executionIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;
const platformPattern = /^linux\/(?:amd64|arm64)$/;
const releaseTagPattern = /^[a-z0-9][a-z0-9.:-]*(?:\/[a-z0-9][a-z0-9._-]*)+:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const versionPattern = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const kmsPattern = /^(?:awskms|azurekms|gcpkms|hashivault|openbao|k8s|pkcs11):\/\/[^\s]+$/;
const imageNames = ['director', 'gateway', 'edge'];

export const imageProfiles = {
  director: {
    dockerfile: 'director/reference/Dockerfile',
    baseArguments: ['NODE_BUILD_IMAGE', 'NODE_RUNTIME_IMAGE'],
  },
  gateway: {
    dockerfile: 'gateway/reference/Dockerfile',
    baseArguments: ['NODE_BUILD_IMAGE', 'NODE_RUNTIME_IMAGE'],
  },
  edge: {
    dockerfile: 'deploy/reference/Dockerfile.edge',
    baseArguments: ['NODE_BUILD_IMAGE', 'NGINX_RUNTIME_IMAGE'],
  },
};

export async function executeOciRelease({
  config,
  outputDirectory,
  workspaceRoot = defaultWorkspaceRoot,
  runner = runCommand,
  contractValidator = validateContainerContract,
}) {
  const normalized = validateOciReleaseConfig(config);
  const root = path.resolve(workspaceRoot);
  const output = path.resolve(outputDirectory ?? '');
  if (outputDirectory === undefined || outputDirectory.length === 0) {
    throw new Error('A new protected output directory is required.');
  }
  if (insidePath(root, output)) {
    throw new Error('OCI release evidence must be stored outside the source workspace.');
  }
  await mkdir(output, { mode: 0o700 });
  await chmod(output, 0o700);

  const startedAt = new Date().toISOString();
  const completedImages = [];
  try {
    const contract = await contractValidator({
      workspaceRoot: root,
      environment: contractEnvironment(normalized),
    });
    const toolchain = await verifyToolchain(
      normalized.toolchain,
      normalized.vulnerability_policy,
      runner,
      root,
    );
    await writePrivateJson(path.join(output, 'toolchain.json'), toolchain);
    await writePrivateText(
      path.join(output, 'trivy-empty.ignore'),
      '# Suppressions are prohibited by the baseline release policy.\n',
    );

    for (const name of imageNames) {
      completedImages.push(
        await releaseImage({ name, config: normalized, root, output, runner }),
      );
    }

    const completedAt = new Date().toISOString();
    const manifestWithoutHash = {
      schema_version: 1,
      execution_id: normalized.execution_id,
      status: 'PASS',
      started_at: startedAt,
      completed_at: completedAt,
      platforms: normalized.platforms,
      vulnerability_policy: normalized.vulnerability_policy,
      signing: publicSigningPolicy(normalized.signing),
      container_contract: contract,
      toolchain: {
        policy_id: normalized.toolchain.policy_id,
        evidence_file: 'toolchain.json',
        evidence_sha256: await fileHash(path.join(output, 'toolchain.json')),
      },
      images: completedImages,
    };
    const manifest = {
      ...manifestWithoutHash,
      collection_sha256: canonicalHash(manifestWithoutHash),
    };
    await writePrivateJson(path.join(output, 'oci-release-evidence.json'), manifest);
    return manifest;
  } catch (error) {
    await writePrivateJson(path.join(output, 'oci-release-failed.json'), {
      schema_version: 1,
      execution_id: normalized.execution_id,
      status: 'FAIL',
      failed_at: new Date().toISOString(),
      completed_images: completedImages.map(({ name, digest_reference }) => ({
        name,
        digest_reference,
      })),
      remediation: 'Quarantine any published digest and retain this directory for review.',
    }).catch(() => undefined);
    throw error;
  }
}

export function validateOciReleaseConfig(config) {
  assertObject(config, 'config');
  assertExactKeys(config, [
    'schema_version',
    'execution_id',
    'platforms',
    'base_images',
    'package_manager',
    'images',
    'toolchain',
    'vulnerability_policy',
    'signing',
  ], 'config');
  if (config.schema_version !== 1) throw new Error('Unsupported OCI release schema.');
  if (!executionIdPattern.test(config.execution_id) || config.execution_id.startsWith('replace-')) {
    throw new Error('A non-placeholder execution ID is required.');
  }
  if (
    !Array.isArray(config.platforms) ||
    config.platforms.length === 0 ||
    new Set(config.platforms).size !== config.platforms.length ||
    config.platforms.some((platform) => !platformPattern.test(platform))
  ) {
    throw new Error('Platforms must be unique supported Linux targets.');
  }
  validateBaseImages(config.base_images);
  if (config.package_manager !== 'pnpm@11.18.0') {
    throw new Error('package_manager must be exactly pnpm@11.18.0.');
  }
  validateReleaseTags(config.images);
  validateToolchain(config.toolchain);
  validateVulnerabilityPolicy(config.vulnerability_policy);
  validateSigning(config.signing);
  return structuredClone(config);
}

async function releaseImage({ name, config, root, output, runner }) {
  const profile = imageProfiles[name];
  const slug = `image-${name}`;
  const metadataPath = path.join(output, `${slug}-build-metadata.json`);
  const sbomPath = path.join(output, `${slug}-sbom.cdx.json`);
  const scanPath = path.join(output, `${slug}-trivy.json`);
  const logPath = path.join(output, `${slug}.log`);
  const logs = [];
  const buildArguments = baseBuildArguments(config);
  const arguments_ = [
    'buildx', 'build',
    '--file', profile.dockerfile,
    '--platform', config.platforms.join(','),
    '--provenance=mode=max',
    '--sbom=true',
    '--metadata-file', metadataPath,
    '--tag', config.images[name],
    '--push',
  ];
  for (const argumentName of profile.baseArguments) {
    arguments_.push('--build-arg', `${argumentName}=${buildArguments[argumentName]}`);
  }
  arguments_.push('--build-arg', `PNPM_VERSION=${config.package_manager.slice(5)}`, '.');

  await checkedRun(runner, 'docker', arguments_, root, logs);
  const buildMetadata = await readJsonFile(metadataPath, 'Build metadata');
  const digest = buildMetadata['containerimage.digest'];
  if (!digestPattern.test(digest) || !hasObject(buildMetadata, 'buildx.build.provenance')) {
    throw new Error(`${name} build metadata lacks a digest or maximal provenance record.`);
  }
  const digestReference = `${repositoryOf(config.images[name])}@${digest}`;

  const rawIndex = await checkedRun(
    runner,
    'docker',
    ['buildx', 'imagetools', 'inspect', '--raw', digestReference],
    root,
    logs,
  );
  validatePlatformIndex(rawIndex.stdout, config.platforms);

  await checkedRun(
    runner,
    'syft',
    [digestReference, '-o', `cyclonedx-json=${sbomPath}`],
    root,
    logs,
  );
  const sbom = await readJsonFile(sbomPath, 'CycloneDX SBOM');
  if (sbom.bomFormat !== 'CycloneDX' || !Array.isArray(sbom.components) || sbom.components.length === 0) {
    throw new Error(`${name} SBOM is invalid or unexpectedly empty.`);
  }

  const scanArguments = [
    'image', '--scanners', 'vuln', '--exit-code', '1',
    '--severity', config.vulnerability_policy.severities.join(','),
    '--ignorefile', path.join(output, 'trivy-empty.ignore'),
    '--format', 'json', '--output', scanPath,
  ];
  if (config.vulnerability_policy.ignore_unfixed) scanArguments.push('--ignore-unfixed');
  if (config.vulnerability_policy.exit_on_eol) scanArguments.push('--exit-on-eol', '1');
  scanArguments.push(digestReference);
  await checkedRun(runner, 'trivy', scanArguments, root, logs);
  const scan = await readJsonFile(scanPath, 'Trivy report');
  if (!Number.isSafeInteger(scan.SchemaVersion) || !Array.isArray(scan.Results)) {
    throw new Error(`${name} vulnerability report is invalid.`);
  }

  const signingArguments = signingKeyArguments(config.signing);
  await checkedRun(runner, 'cosign', ['sign', '--yes', ...signingArguments, digestReference], root, logs);
  await checkedRun(
    runner,
    'cosign',
    ['attest', '--yes', '--type', 'cyclonedx', '--predicate', sbomPath, ...signingArguments, digestReference],
    root,
    logs,
  );
  const verificationArguments = signingVerificationArguments(config.signing);
  const signature = await checkedRun(
    runner,
    'cosign',
    ['verify', '--output', 'json', ...verificationArguments, digestReference],
    root,
    logs,
  );
  validateJsonEvidence(signature.stdout, `${name} signature verification`);
  const attestation = await checkedRun(
    runner,
    'cosign',
    ['verify-attestation', '--type', 'cyclonedx', ...verificationArguments, digestReference],
    root,
    logs,
  );
  validateJsonEvidence(attestation.stdout, `${name} SBOM attestation verification`);

  await writePrivateText(logPath, logs.join(''));
  return {
    name,
    release_tag: config.images[name],
    digest,
    digest_reference: digestReference,
    platforms: config.platforms,
    build_metadata_file: path.basename(metadataPath),
    build_metadata_sha256: await fileHash(metadataPath),
    sbom_file: path.basename(sbomPath),
    sbom_sha256: await fileHash(sbomPath),
    sbom_components: sbom.components.length,
    vulnerability_report_file: path.basename(scanPath),
    vulnerability_report_sha256: await fileHash(scanPath),
    command_log_file: path.basename(logPath),
    command_log_sha256: await fileHash(logPath),
    signature_verified: true,
    sbom_attestation_verified: true,
  };
}

async function verifyToolchain(policy, vulnerabilityPolicy, runner, root) {
  await checkedRun(runner, 'trivy', ['image', '--download-db-only'], root, []);
  const commands = [
    ['docker', ['version', '--format', '{{.Client.Version}}'], policy.docker],
    ['docker', ['buildx', 'version'], policy.buildx],
    ['syft', ['version'], policy.syft],
    ['trivy', ['--version'], policy.trivy],
    ['cosign', ['version'], policy.cosign],
  ];
  const tools = {};
  let vulnerabilityDatabaseUpdatedAt;
  for (const [program, arguments_, expectedVersion] of commands) {
    const result = await checkedRun(runner, program, arguments_, root, []);
    const output = `${result.stdout}\n${result.stderr}`;
    const versionBoundary = new RegExp(`(^|[^0-9A-Za-z])v?${escapeRegex(expectedVersion)}([^0-9A-Za-z]|$)`);
    if (!versionBoundary.test(output)) {
      throw new Error(`${program} does not match the approved toolchain version.`);
    }
    tools[program === 'docker' && arguments_[0] === 'buildx' ? 'buildx' : program] = {
      expected_version: expectedVersion,
      output_sha256: canonicalHash(output.trim()),
    };
    if (program === 'trivy') {
      vulnerabilityDatabaseUpdatedAt = validateTrivyDatabaseAge(
        output,
        vulnerabilityPolicy.database_max_age_hours,
      );
    }
  }
  return {
    schema_version: 1,
    policy_id: policy.policy_id,
    vulnerability_database_updated_at: vulnerabilityDatabaseUpdatedAt,
    tools,
  };
}

async function checkedRun(runner, program, arguments_, cwd, logs) {
  const result = await runner(program, arguments_, {
    cwd,
    environment: childEnvironment(),
  });
  logs.push(
    `$ ${program} ${arguments_.join(' ')}\n`,
    `exit_code=${result.exitCode ?? 'not_executed'} duration_ms=${result.durationMs}\n`,
    result.stdout,
    result.stdout.endsWith('\n') ? '' : '\n',
    result.stderr,
    result.stderr.length === 0 || result.stderr.endsWith('\n') ? '' : '\n',
  );
  if (result.exitCode !== 0) {
    throw new Error(`${program} command failed; OCI release is blocked.`);
  }
  return result;
}

function runCommand(program, arguments_, options) {
  const startedAt = Date.now();
  const result = spawnSync(program, arguments_, {
    cwd: options.cwd,
    env: options.environment,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    timeout: 45 * 60 * 1_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    exitCode: result.status,
    durationMs: Date.now() - startedAt,
    stdout: typeof result.stdout === 'string' ? result.stdout : '',
    stderr: typeof result.stderr === 'string'
      ? result.stderr
      : result.error === undefined
        ? ''
        : 'Command execution failed before a normal exit.\n',
  };
}

function validateBaseImages(baseImages) {
  assertObject(baseImages, 'base_images');
  assertExactKeys(baseImages, ['node_build', 'node_runtime', 'nginx_runtime'], 'base_images');
  for (const reference of Object.values(baseImages)) {
    if (!/^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$/.test(reference)) {
      throw new Error('Base images must be canonical SHA-256 references.');
    }
  }
}

function validateReleaseTags(images) {
  assertObject(images, 'images');
  assertExactKeys(images, imageNames, 'images');
  const tags = Object.values(images);
  if (
    new Set(tags).size !== imageNames.length ||
    tags.some((tag) => !releaseTagPattern.test(tag) || /:latest$/i.test(tag) || tag.includes('@'))
  ) {
    throw new Error('Release tags must be unique immutable non-latest registry tags.');
  }
}

function validateToolchain(toolchain) {
  assertObject(toolchain, 'toolchain');
  assertExactKeys(toolchain, ['policy_id', 'docker', 'buildx', 'syft', 'trivy', 'cosign'], 'toolchain');
  if (!executionIdPattern.test(toolchain.policy_id)) throw new Error('toolchain.policy_id is invalid.');
  for (const name of ['docker', 'buildx', 'syft', 'trivy', 'cosign']) {
    if (!versionPattern.test(toolchain[name])) throw new Error('Toolchain versions must be exact semantic versions.');
  }
}

function validateVulnerabilityPolicy(policy) {
  assertObject(policy, 'vulnerability_policy');
  assertExactKeys(policy, [
    'policy_id', 'scanner', 'severities', 'ignore_unfixed', 'exit_on_eol',
    'database_max_age_hours', 'allow_suppressions',
  ], 'vulnerability_policy');
  if (!executionIdPattern.test(policy.policy_id) || policy.scanner !== 'trivy') {
    throw new Error('Vulnerability policy identity or scanner is invalid.');
  }
  if (
    !Array.isArray(policy.severities) ||
    policy.severities.length === 0 ||
    new Set(policy.severities).size !== policy.severities.length ||
    policy.severities.some((severity) => !['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity)) ||
    typeof policy.ignore_unfixed !== 'boolean' ||
    typeof policy.exit_on_eol !== 'boolean' ||
    !Number.isSafeInteger(policy.database_max_age_hours) ||
    policy.database_max_age_hours < 1 ||
    policy.database_max_age_hours > 168 ||
    policy.allow_suppressions !== false
  ) {
    throw new Error('Vulnerability policy is invalid.');
  }
}

function validateTrivyDatabaseAge(output, maximumAgeHours) {
  const match = output.match(/UpdatedAt:\s*([^\s]+)/i);
  const updatedAt = match === null ? Number.NaN : Date.parse(match[1]);
  const now = Date.now();
  if (
    !Number.isFinite(updatedAt) ||
    updatedAt > now + 5 * 60_000 ||
    now - updatedAt > maximumAgeHours * 60 * 60_000
  ) {
    throw new Error('Trivy vulnerability database is missing, stale, or future-dated.');
  }
  return new Date(updatedAt).toISOString();
}

function validateSigning(signing) {
  assertObject(signing, 'signing');
  if (signing.mode === 'keyless') {
    assertExactKeys(signing, ['mode', 'certificate_identity', 'certificate_oidc_issuer'], 'signing');
    if (
      typeof signing.certificate_identity !== 'string' ||
      signing.certificate_identity.length < 3 ||
      !isHttpsUrl(signing.certificate_oidc_issuer)
    ) {
      throw new Error('Keyless signing requires an identity and HTTPS OIDC issuer.');
    }
    return;
  }
  if (signing.mode === 'kms') {
    assertExactKeys(signing, ['mode', 'key_ref'], 'signing');
    if (!kmsPattern.test(signing.key_ref)) throw new Error('KMS signing key reference is invalid.');
    return;
  }
  throw new Error('Signing mode must be keyless or kms.');
}

function validatePlatformIndex(raw, expectedPlatforms) {
  let index;
  try {
    index = JSON.parse(raw);
  } catch {
    throw new Error('Registry platform manifest is not valid JSON.');
  }
  if (!Array.isArray(index.manifests)) throw new Error('Registry result is not a multi-platform image index.');
  const actual = index.manifests
    .map((manifest) => manifest?.platform)
    .filter((platform) => platform?.os === 'linux' && ['amd64', 'arm64'].includes(platform.architecture))
    .map((platform) => `${platform.os}/${platform.architecture}`);
  if (
    actual.length !== expectedPlatforms.length ||
    expectedPlatforms.some((platform) => !actual.includes(platform)) ||
    new Set(actual).size !== actual.length
  ) {
    throw new Error('Registry platform manifest differs from the approved platform set.');
  }
}

function validateJsonEvidence(raw, label) {
  const trimmed = raw.trim();
  if (trimmed.length === 0) throw new Error(`${label} returned no evidence.`);
  let document;
  try {
    document = JSON.parse(trimmed);
  } catch {
    const lines = trimmed.split(/\r?\n/);
    if (lines.length === 0 || lines.some((line) => {
      try { return JSON.parse(line) === null; } catch { return true; }
    })) {
      throw new Error(`${label} is not valid non-empty JSON evidence.`);
    }
    return;
  }
  if ((Array.isArray(document) && document.length === 0) || document === null) {
    throw new Error(`${label} is empty.`);
  }
}

function baseBuildArguments(config) {
  return {
    NODE_BUILD_IMAGE: config.base_images.node_build,
    NODE_RUNTIME_IMAGE: config.base_images.node_runtime,
    NGINX_RUNTIME_IMAGE: config.base_images.nginx_runtime,
  };
}

function contractEnvironment(config) {
  return {
    DIRIZHOR_NODE_BUILD_IMAGE: config.base_images.node_build,
    DIRIZHOR_NODE_RUNTIME_IMAGE: config.base_images.node_runtime,
    DIRIZHOR_NGINX_RUNTIME_IMAGE: config.base_images.nginx_runtime,
    DIRIZHOR_PNPM_VERSION: config.package_manager.slice(5),
  };
}

function signingKeyArguments(signing) {
  return signing.mode === 'kms' ? ['--key', signing.key_ref] : [];
}

function signingVerificationArguments(signing) {
  return signing.mode === 'kms'
    ? ['--key', signing.key_ref]
    : [
        '--certificate-identity', signing.certificate_identity,
        '--certificate-oidc-issuer', signing.certificate_oidc_issuer,
      ];
}

function publicSigningPolicy(signing) {
  return signing.mode === 'kms'
    ? { mode: 'kms', key_ref: signing.key_ref }
    : { ...signing };
}

function repositoryOf(tag) {
  return tag.slice(0, tag.lastIndexOf(':'));
}

function childEnvironment() {
  const environment = { CI: 'true', NO_COLOR: '1', BUILDX_METADATA_PROVENANCE: 'max' };
  for (const name of [
    'PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'DOCKER_CONFIG',
    'COSIGN_EXPERIMENTAL', 'SIGSTORE_ID_TOKEN',
    'AWS_REGION', 'AWS_DEFAULT_REGION', 'AWS_ROLE_ARN', 'AWS_WEB_IDENTITY_TOKEN_FILE',
    'AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_FEDERATED_TOKEN_FILE',
    'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES',
  ]) {
    const value = process.env[name];
    if (value !== undefined && value.length > 0) environment[name] = value;
  }
  return environment;
}

async function readJsonFile(filePath, label) {
  const metadata = await lstat(filePath).catch(() => undefined);
  if (metadata === undefined || !metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} was not produced as a regular file.`);
  }
  await chmod(filePath, 0o600);
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

async function writePrivateJson(filePath, value) {
  await writePrivateText(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

async function writePrivateText(filePath, value) {
  await writeFile(filePath, value, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  await chmod(filePath, 0o600);
}

async function fileHash(filePath) {
  const contents = await readFile(filePath);
  return `sha256:${createHash('sha256').update(contents).digest('hex')}`;
}

function canonicalHash(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

function insidePath(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function assertObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new Error(`${label} contains missing or unsupported fields.`);
  }
}

function hasObject(value, key) {
  return value[key] !== null && typeof value[key] === 'object' && !Array.isArray(value[key]);
}

function isHttpsUrl(value) {
  try { return new URL(value).protocol === 'https:'; } catch { return false; }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function main() {
  const [outputDirectory, configPath] = process.argv.slice(2);
  if (outputDirectory === undefined || configPath === undefined || process.argv.length !== 4) {
    process.stderr.write('Usage: node scripts/oci-release.mjs <new-evidence-directory> <config.json>\n');
    process.exitCode = 2;
    return;
  }
  try {
    const config = JSON.parse(await readFile(path.resolve(configPath), 'utf8'));
    const manifest = await executeOciRelease({ config, outputDirectory });
    process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown OCI release error.';
    process.stderr.write(`OCI release failed: ${message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
