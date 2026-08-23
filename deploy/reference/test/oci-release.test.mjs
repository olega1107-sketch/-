import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  executeOciRelease,
  validateOciReleaseConfig,
} from '../scripts/oci-release.mjs';

const digest = (character) => `sha256:${character.repeat(64)}`;

test('config requires pinned inputs, immutable tags, exact tools, and explicit signing', () => {
  const config = validConfig();
  assert.doesNotThrow(() => validateOciReleaseConfig(config));
  assert.throws(
    () => validateOciReleaseConfig({ ...config, images: { ...config.images, edge: 'registry.invalid/dirizhor/edge:latest' } }),
    /immutable non-latest/,
  );
  assert.throws(
    () => validateOciReleaseConfig({ ...config, base_images: { ...config.base_images, node_build: 'node:22' } }),
    /canonical SHA-256/,
  );
  assert.throws(
    () => validateOciReleaseConfig({ ...config, toolchain: { ...config.toolchain, syft: 'latest' } }),
    /exact semantic versions/,
  );
  assert.throws(
    () => validateOciReleaseConfig({ ...config, signing: { mode: 'keyless', certificate_identity: 'ci', certificate_oidc_issuer: 'http://issuer.invalid' } }),
    /HTTPS OIDC issuer/,
  );
  assert.throws(
    () => validateOciReleaseConfig({ ...config, vulnerability_policy: { ...config.vulnerability_policy, allow_suppressions: true } }),
    /Vulnerability policy is invalid/,
  );
});

test('successful release records three digest-only images and private evidence', async () => {
  const fixture = await fixtureDirectories();
  try {
    const calls = [];
    const manifest = await executeOciRelease({
      config: validConfig(),
      outputDirectory: fixture.output,
      workspaceRoot: fixture.workspace,
      contractValidator: successfulContract,
      runner: syntheticRunner({ calls }),
    });

    assert.equal(manifest.status, 'PASS');
    assert.equal(manifest.images.length, 3);
    assert.deepEqual(manifest.images.map((image) => image.name), ['director', 'gateway', 'edge']);
    assert.ok(manifest.images.every((image) => image.digest_reference.includes('@sha256:')));
    assert.ok(manifest.images.every((image) => image.signature_verified && image.sbom_attestation_verified));
    assert.equal(calls.filter((call) => call.program === 'docker' && call.arguments[0] === 'buildx' && call.arguments[1] === 'build').length, 3);
    assert.equal(calls.filter((call) => call.program === 'trivy' && call.arguments[0] === 'image' && !call.arguments.includes('--download-db-only')).length, 3);
    assert.equal(calls.filter((call) => call.program === 'cosign' && call.arguments[0] === 'sign').length, 3);
    assert.match(manifest.collection_sha256, /^sha256:[0-9a-f]{64}$/);

    assert.equal((await stat(fixture.output)).mode & 0o777, 0o700);
    for (const file of [
      'oci-release-evidence.json',
      'toolchain.json',
      'image-director-build-metadata.json',
      'image-director-sbom.cdx.json',
      'image-director-trivy.json',
      'image-director.log',
      'trivy-empty.ignore',
    ]) {
      assert.equal((await stat(path.join(fixture.output, file))).mode & 0o777, 0o600);
    }
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('vulnerability stop-ship failure blocks signing and writes failure evidence', async () => {
  const fixture = await fixtureDirectories();
  try {
    const calls = [];
    await assert.rejects(
      executeOciRelease({
        config: validConfig(),
        outputDirectory: fixture.output,
        workspaceRoot: fixture.workspace,
        contractValidator: successfulContract,
        runner: syntheticRunner({ calls, failProgram: 'trivy' }),
      }),
      /trivy command failed/,
    );
    assert.equal(
      calls.some((call) => call.program === 'cosign' && call.arguments[0] !== 'version'),
      false,
    );
    const failure = JSON.parse(await readFile(path.join(fixture.output, 'oci-release-failed.json'), 'utf8'));
    assert.equal(failure.status, 'FAIL');
    assert.deepEqual(failure.completed_images, []);
    await assert.rejects(stat(path.join(fixture.output, 'oci-release-evidence.json')));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('empty SBOM and wrong platform index fail closed', async () => {
  for (const variant of ['emptySbom', 'wrongPlatform', 'emptyVerification']) {
    const fixture = await fixtureDirectories();
    try {
      await assert.rejects(
        executeOciRelease({
          config: validConfig(),
          outputDirectory: fixture.output,
          workspaceRoot: fixture.workspace,
          contractValidator: successfulContract,
          runner: syntheticRunner({ [variant]: true }),
        }),
        variant === 'emptySbom'
          ? /SBOM is invalid or unexpectedly empty/
          : variant === 'wrongPlatform'
            ? /platform manifest differs/
            : /signature verification is empty/,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test('stale vulnerability database blocks every build', async () => {
  const fixture = await fixtureDirectories();
  try {
    const calls = [];
    await assert.rejects(
      executeOciRelease({
        config: validConfig(),
        outputDirectory: fixture.output,
        workspaceRoot: fixture.workspace,
        contractValidator: successfulContract,
        runner: syntheticRunner({ calls, staleDatabase: true }),
      }),
      /database is missing, stale, or future-dated/,
    );
    assert.equal(calls.some((call) => call.program === 'docker' && call.arguments.includes('build')), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('evidence directory must be new and outside the source workspace', async () => {
  const fixture = await fixtureDirectories();
  try {
    await assert.rejects(
      executeOciRelease({
        config: validConfig(),
        outputDirectory: path.join(fixture.workspace, 'evidence'),
        workspaceRoot: fixture.workspace,
        contractValidator: successfulContract,
        runner: syntheticRunner({}),
      }),
      /outside the source workspace/,
    );
    await mkdir(fixture.output);
    await assert.rejects(
      executeOciRelease({
        config: validConfig(),
        outputDirectory: fixture.output,
        workspaceRoot: fixture.workspace,
        contractValidator: successfulContract,
        runner: syntheticRunner({}),
      }),
      /EEXIST/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

function validConfig() {
  return {
    schema_version: 1,
    execution_id: 'CHG-2026-OCI-001',
    platforms: ['linux/amd64', 'linux/arm64'],
    base_images: {
      node_build: `registry.invalid/approved/node-build@${digest('a')}`,
      node_runtime: `registry.invalid/approved/node-runtime@${digest('b')}`,
      nginx_runtime: `registry.invalid/approved/nginx-runtime@${digest('c')}`,
    },
    package_manager: 'pnpm@11.18.0',
    images: {
      director: 'registry.invalid/dirizhor/director:2026.08.11-1',
      gateway: 'registry.invalid/dirizhor/gateway:2026.08.11-1',
      edge: 'registry.invalid/dirizhor/edge:2026.08.11-1',
    },
    toolchain: {
      policy_id: 'oci-toolchain-2026-01',
      docker: '28.3.3',
      buildx: '0.28.0',
      syft: '1.45.1',
      trivy: '0.66.0',
      cosign: '3.0.2',
    },
    vulnerability_policy: {
      policy_id: 'vulnerability-policy-2026-01',
      scanner: 'trivy',
      severities: ['HIGH', 'CRITICAL'],
      ignore_unfixed: false,
      exit_on_eol: true,
      database_max_age_hours: 24,
      allow_suppressions: false,
    },
    signing: {
      mode: 'keyless',
      certificate_identity: 'release-workflow@example.invalid',
      certificate_oidc_issuer: 'https://issuer.example.invalid',
    },
  };
}

async function fixtureDirectories() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-oci-release-'));
  const workspace = path.join(root, 'workspace');
  await mkdir(workspace);
  return { root, workspace, output: path.join(root, 'evidence') };
}

async function successfulContract() {
  return { status: 'ok', runtime_uid: 10_001, runtime_gid: 10_001 };
}

function syntheticRunner(options) {
  let buildNumber = 0;
  return async (program, arguments_, commandOptions) => {
    options.calls?.push({ program, arguments: [...arguments_] });
    if (
      options.failProgram === program &&
      !(program === 'trivy' && arguments_.includes('--download-db-only')) &&
      !(program === 'trivy' && arguments_[0] === '--version')
    ) return result(1, '', 'synthetic stop-ship failure\n');

    if (program === 'docker' && arguments_[0] === 'version') return result(0, '28.3.3\n');
    if (program === 'docker' && arguments_[0] === 'buildx' && arguments_[1] === 'version') {
      return result(0, 'github.com/docker/buildx v0.28.0\n');
    }
    if (program === 'syft' && arguments_[0] === 'version') return result(0, 'Version: 1.45.1\n');
    if (program === 'trivy' && arguments_[0] === 'image' && arguments_.includes('--download-db-only')) {
      return result(0, 'database updated\n');
    }
    if (program === 'trivy' && arguments_[0] === '--version') {
      const databaseDate = options.staleDatabase
        ? new Date(Date.now() - 48 * 60 * 60_000)
        : new Date();
      return result(0, `Version: 0.66.0\nVulnerability DB:\n  UpdatedAt: ${databaseDate.toISOString()}\n`);
    }
    if (program === 'cosign' && arguments_[0] === 'version') return result(0, 'GitVersion: v3.0.2\n');

    if (program === 'docker' && arguments_[0] === 'buildx' && arguments_[1] === 'build') {
      buildNumber += 1;
      const metadataPath = arguments_[arguments_.indexOf('--metadata-file') + 1];
      await writeFile(metadataPath, JSON.stringify({
        'buildx.build.provenance': { mode: 'max' },
        'containerimage.digest': digest(String(buildNumber)),
      }));
      return result(0, 'build pushed\n');
    }
    if (program === 'docker' && arguments_[0] === 'buildx' && arguments_[1] === 'imagetools') {
      const platforms = options.wrongPlatform
        ? [{ os: 'linux', architecture: 'amd64' }]
        : [{ os: 'linux', architecture: 'amd64' }, { os: 'linux', architecture: 'arm64' }];
      return result(0, JSON.stringify({
        schemaVersion: 2,
        manifests: platforms.map((platform, index) => ({ digest: digest(String(index + 4)), platform })),
      }));
    }
    if (program === 'syft') {
      const outputArgument = arguments_.find((argument) => argument.startsWith('cyclonedx-json='));
      await writeFile(outputArgument.slice('cyclonedx-json='.length), JSON.stringify({
        bomFormat: 'CycloneDX',
        components: options.emptySbom ? [] : [{ type: 'library', name: 'fixture', version: '1.0.0' }],
      }));
      return result(0, 'sbom generated\n');
    }
    if (program === 'trivy') {
      const reportPath = arguments_[arguments_.indexOf('--output') + 1];
      await writeFile(reportPath, JSON.stringify({ SchemaVersion: 2, Results: [] }));
      return result(0, 'scan passed\n');
    }
    if (program === 'cosign' && ['verify', 'verify-attestation'].includes(arguments_[0])) {
      return result(0, options.emptyVerification && arguments_[0] === 'verify' ? '[]\n' : '[{"verified":true}]\n');
    }
    if (program === 'cosign') return result(0, 'published\n');
    throw new Error(`Unexpected synthetic command: ${program} ${arguments_.join(' ')}`);
  };
}

function result(exitCode, stdout = '', stderr = '') {
  return { exitCode, durationMs: 1, stdout, stderr };
}
