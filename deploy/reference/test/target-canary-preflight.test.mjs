import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  runTargetCanaryPreflight,
  writeTargetCanaryPreflight,
} from '../scripts/target-canary-preflight.mjs';

const projectId = '11111111-1111-4111-8111-111111111111';
const preflightScript = fileURLToPath(
  new URL('../scripts/target-canary-preflight.mjs', import.meta.url),
);

test('preflight reports every local input ready without reading or disclosing material', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    const inspected = [];
    const report = await runTargetCanaryPreflight(config, {
      nodeVersion: '22.18.0',
      now: () => new Date('2026-08-13T10:00:00.000Z'),
      lstat: async (materialPath) => {
        inspected.push(materialPath);
        return lstat(materialPath);
      },
    });

    assert.equal(report.status, 'PASS');
    assert.equal(report.checks.length, 10);
    assert.ok(report.checks.every((check) => check.status === 'PASS'));
    assert.equal(inspected.length, 9);
    assert.match(report.config_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.match(report.report_sha256, /^sha256:[0-9a-f]{64}$/);
    const serialized = JSON.stringify(report);
    assert.equal(serialized.includes(fixture.root), false);
    assert.equal(serialized.includes(fixture.secretValue), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('preflight collects independent missing, symlink, permission, and size blockers', async () => {
  const fixture = await materialFixture();
  try {
    await chmod(fixture.sessionToken, 0o644);
    await rm(fixture.directorSigningKey);
    await rm(fixture.gatewayCa);
    await symlink(fixture.directorCa, fixture.gatewayCa);
    await writeFile(fixture.gatewaySigningKey, '', { mode: 0o600 });

    const report = await runTargetCanaryPreflight(validConfig(fixture), {
      nodeVersion: '24.0.0',
      access: async (materialPath) => {
        if (materialPath === fixture.directorPrivateKey) {
          throw new Error('fixture access denied');
        }
      },
    });
    assert.equal(report.status, 'BLOCKED');
    assert.equal(reason(report, 'material.session_token'), 'material_permissions');
    assert.equal(
      reason(report, 'material.director_to_gateway_workload_signing_key'),
      'material_unreadable',
    );
    assert.equal(
      reason(report, 'material.gateway_to_director_ca'),
      'material_symlink_forbidden',
    );
    assert.equal(
      reason(report, 'material.gateway_to_director_workload_signing_key'),
      'material_size',
    );
    assert.equal(
      reason(report, 'material.director_to_gateway_client_private_key'),
      'material_unreadable',
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('preflight includes optional trust files and blocks an unsupported Node runtime', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    config.public.ca_path = fixture.publicCa;
    config.oidc.ca_path = fixture.oidcCa;
    const report = await runTargetCanaryPreflight(config, { nodeVersion: '22.17.9' });

    assert.equal(report.status, 'BLOCKED');
    assert.equal(reason(report, 'runtime.node'), 'node_version_unsupported');
    assert.equal(check(report, 'material.public_ca').status, 'PASS');
    assert.equal(check(report, 'material.oidc_ca').status, 'PASS');
    assert.equal(report.checks.length, 12);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('preflight rejects an invalid target config before inspecting filesystem inputs', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    config.public.origin = 'http://director.example.test';
    let inspections = 0;
    await assert.rejects(
      runTargetCanaryPreflight(config, {
        lstat: async () => {
          inspections += 1;
          throw new Error('must not run');
        },
      }),
      /absolute HTTPS URL/,
    );
    assert.equal(inspections, 0);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('preflight writer requires a new external directory and private output modes', async () => {
  const fixture = await materialFixture();
  const workspace = path.join(fixture.root, 'workspace');
  const output = path.join(fixture.root, 'preflight-evidence');
  await mkdir(workspace);
  try {
    const result = await writeTargetCanaryPreflight({
      config: validConfig(fixture),
      outputDirectory: output,
      workspaceRoot: workspace,
      dependencies: { nodeVersion: '22.18.0' },
    });
    assert.equal(result.report.status, 'PASS');
    assert.equal((await stat(output)).mode & 0o777, 0o700);
    assert.equal((await stat(result.reportPath)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(result.reportPath, 'utf8')), result.report);

    await assert.rejects(
      writeTargetCanaryPreflight({
        config: validConfig(fixture),
        outputDirectory: output,
        workspaceRoot: workspace,
        dependencies: { nodeVersion: '22.18.0' },
      }),
      /EEXIST/,
    );
    await assert.rejects(
      writeTargetCanaryPreflight({
        config: validConfig(fixture),
        outputDirectory: path.join(workspace, 'evidence'),
        workspaceRoot: workspace,
      }),
      /outside the source workspace/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('CLI distinguishes blocked readiness from an invalid invocation', async () => {
  const fixture = await materialFixture();
  const configPath = path.join(fixture.root, 'target-canary-config.json');
  const output = path.join(fixture.root, 'cli-preflight');
  try {
    await rm(fixture.directorSigningKey);
    await writeFile(configPath, `${JSON.stringify(validConfig(fixture))}\n`, { mode: 0o600 });
    const blocked = spawnSync(process.execPath, [preflightScript, output, configPath], {
      encoding: 'utf8',
    });
    assert.equal(blocked.status, 1);
    assert.equal(JSON.parse(blocked.stdout).status, 'BLOCKED');
    assert.equal(
      JSON.parse(await readFile(path.join(output, 'target-canary-preflight.json'), 'utf8')).status,
      'BLOCKED',
    );

    const invalid = spawnSync(process.execPath, [preflightScript], { encoding: 'utf8' });
    assert.equal(invalid.status, 2);
    assert.match(invalid.stderr, /Usage:/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

function check(report, id) {
  const value = report.checks.find((item) => item.id === id);
  assert.notEqual(value, undefined, `Missing check ${id}.`);
  return value;
}

function reason(report, id) {
  return check(report, id).reason_code;
}

function validConfig(fixture) {
  return {
    schema_version: 2,
    execution_id: 'CHG-123-target-canary-01',
    environment: 'production-pilot',
    request_timeout_ms: 10_000,
    workload_token_ttl_seconds: 60,
    public: { origin: 'https://director.example.test', ca_path: null },
    oidc: {
      issuer: 'https://idp.example.test/tenant',
      ca_path: null,
      client_id: 'dirizhor-production',
      redirect_uri: 'https://director.example.test/api/v1/auth/oidc/callback',
      scopes: ['openid', 'profile', 'email'],
      token_endpoint_auth_method: 'client_secret_basic',
      id_token_signing_algorithm: 'RS256',
      require_rp_initiated_logout: true,
    },
    session: {
      cookie_name: '__Host-dirizhor_session',
      token_file: fixture.sessionToken,
      expected_project_ids: [projectId],
      browser_flow_evidence_ref: 'run:CHG-123/browser-login',
    },
    director_to_gateway: {
      origin: 'https://gateway.internal.test:8443',
      server_name: 'gateway.internal.test',
      ca_path: fixture.directorCa,
      client_certificate_path: fixture.directorCertificate,
      client_private_key_path: fixture.directorPrivateKey,
      workload_signing_key_id: 'director-key-current',
      workload_signing_private_key_file: fixture.directorSigningKey,
    },
    gateway_to_director: {
      origin: 'https://director.internal.test:8444',
      server_name: 'director.internal.test',
      ca_path: fixture.gatewayCa,
      client_certificate_path: fixture.gatewayCertificate,
      client_private_key_path: fixture.gatewayPrivateKey,
      workload_signing_key_id: 'gateway-key-current',
      workload_signing_private_key_file: fixture.gatewaySigningKey,
    },
  };
}

async function materialFixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-target-preflight-'));
  const paths = {
    root,
    publicCa: path.join(root, 'public-ca.pem'),
    oidcCa: path.join(root, 'oidc-ca.pem'),
    sessionToken: path.join(root, 'session-token'),
    directorCa: path.join(root, 'director-ca.pem'),
    directorCertificate: path.join(root, 'director-client.pem'),
    directorPrivateKey: path.join(root, 'director-client-key.pem'),
    directorSigningKey: path.join(root, 'director-signing-key'),
    gatewayCa: path.join(root, 'gateway-ca.pem'),
    gatewayCertificate: path.join(root, 'gateway-client.pem'),
    gatewayPrivateKey: path.join(root, 'gateway-client-key.pem'),
    gatewaySigningKey: path.join(root, 'gateway-signing-key'),
    secretValue: 'target-preflight-secret-must-not-appear',
  };
  for (const publicFile of [
    paths.publicCa,
    paths.oidcCa,
    paths.directorCa,
    paths.directorCertificate,
    paths.gatewayCa,
    paths.gatewayCertificate,
  ]) {
    await writeFile(publicFile, 'public-fixture\n', { mode: 0o644 });
  }
  for (const protectedFile of [
    paths.sessionToken,
    paths.directorPrivateKey,
    paths.directorSigningKey,
    paths.gatewayPrivateKey,
    paths.gatewaySigningKey,
  ]) {
    await writeFile(protectedFile, `${paths.secretValue}\n`, { mode: 0o600 });
  }
  return paths;
}
