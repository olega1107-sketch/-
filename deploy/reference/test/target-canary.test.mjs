import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import https from 'node:https';

import {
  CanaryTransportError,
  requestHttps,
  runTargetCanary,
  validateTargetCanaryConfig,
  writeTargetCanaryEvidence,
} from '../scripts/target-canary.mjs';

const projectId = '11111111-1111-4111-8111-111111111111';
const extraProjectId = '22222222-2222-4222-8222-222222222222';
const sessionToken = 's'.repeat(43);
const peerFingerprint = Array.from({ length: 32 }, () => 'AA').join(':');
const baselineHeaders = {
  'strict-transport-security': ['max-age=63072000; includeSubDomains'],
  'content-security-policy': [
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
  ],
  'referrer-policy': ['no-referrer'],
  'x-content-type-options': ['nosniff'],
  'x-frame-options': ['DENY'],
  'permissions-policy': ['camera=(), microphone=(), geolocation=()'],
};

test('config validator rejects unsafe origins, drift, and ambiguous project scope', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    assert.doesNotThrow(() => validateTargetCanaryConfig(config));
    assert.throws(
      () =>
        validateTargetCanaryConfig({
          ...config,
          public: { ...config.public, origin: 'http://director.example.test' },
        }),
      /absolute HTTPS URL/,
    );
    assert.throws(
      () =>
        validateTargetCanaryConfig({
          ...config,
          director_to_gateway: {
            ...config.director_to_gateway,
            server_name: 'other.example.test',
          },
        }),
      /exactly match/,
    );
    assert.throws(
      () =>
        validateTargetCanaryConfig({
          ...config,
          session: { ...config.session, expected_project_ids: [] },
        }),
      /1 through 100/,
    );
    assert.throws(
      () =>
        validateTargetCanaryConfig({
          ...config,
          oidc: {
            ...config.oidc,
            redirect_uri: 'https://wrong.example.test/api/v1/auth/oidc/callback',
          },
        }),
      /public origin and exact callback path/,
    );
    assert.throws(
      () => validateTargetCanaryConfig({ ...config, unsupported: true }),
      /missing or unsupported fields/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('HTTPS adapter verifies CA and SNI, presents the client identity, and records TLS evidence', async () => {
  const fixture = await materialFixture();
  const [certificate, privateKey] = await Promise.all([
    readFile(fixture.certificate),
    readFile(fixture.privateKey),
  ]);
  const server = https.createServer(
    {
      cert: certificate,
      key: privateKey,
      ca: certificate,
      requestCert: true,
      rejectUnauthorized: true,
    },
    (request, response) => {
      response
        .writeHead(request.socket.authorized ? 200 : 401, {
          'content-type': 'application/json',
        })
        .end(JSON.stringify({ authorized: request.socket.authorized }));
    },
  );
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address !== null && typeof address === 'object');
    const url = new URL(`https://127.0.0.1:${address.port}/probe`);
    const response = await requestHttps({
      url,
      method: 'GET',
      headers: { accept: 'application/json' },
      ca: certificate,
      cert: certificate,
      key: privateKey,
      servername: 'localhost',
      timeoutMs: 2_000,
      maxBodyBytes: 64 * 1024,
    });
    assert.equal(response.statusCode, 200);
    assert.deepEqual(JSON.parse(response.body), { authorized: true });
    assert.equal(response.tls.authorized, true);
    assert.match(response.tls.peerFingerprint256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);

    await assert.rejects(
      requestHttps({
        url,
        method: 'GET',
        headers: {},
        ca: certificate,
        servername: 'localhost',
        timeoutMs: 2_000,
      }),
      (error) => error instanceof CanaryTransportError,
    );
    await assert.rejects(
      requestHttps({
        url,
        method: 'GET',
        headers: {},
        ca: certificate,
        cert: certificate,
        key: privateKey,
        servername: 'wrong.example.test',
        timeoutMs: 2_000,
      }),
      (error) => error instanceof CanaryTransportError,
    );
  } finally {
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    });
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('runner proves edge, OIDC, both mTLS directions, and exact session scope without leaking secrets', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    const report = await runTargetCanary(config, dependencies(config));
    assert.equal(report.status, 'PASS');
    assert.equal(report.checks.length, 10);
    assert.ok(report.checks.every((check) => check.status === 'PASS'));
    assert.deepEqual(
      report.registry_updates.map((update) => [update.id, update.status]),
      [
        ['edge.external_contract', 'PASS'],
        ['mtls.live_director_to_gateway', 'PASS'],
        ['mtls.live_gateway_to_director', 'PASS'],
        ['workload_identity.live_director_to_gateway', 'PASS'],
        ['workload_identity.live_gateway_to_director', 'PASS'],
        ['oidc.discovery', 'PASS'],
      ],
    );
    assert.match(report.report_sha256, /^sha256:[0-9a-f]{64}$/);

    const serialized = JSON.stringify(report);
    for (const secret of [
      sessionToken,
      fixture.workloadSigningKeyAValue,
      fixture.workloadSigningKeyBValue,
    ]) {
      assert.equal(serialized.includes(secret), false);
    }
    assert.equal(serialized.includes(fixture.root), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('runner fails closed when project scope expands or Gateway accepts a missing bearer', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    const expanded = await runTargetCanary(
      config,
      dependencies(config, { extraProject: true }),
    );
    assert.equal(expanded.status, 'FAIL');
    assert.deepEqual(
      expanded.checks.find((check) => check.id === 'application.session_read').error,
      {
        code: 'project_scope_mismatch',
        message: 'Canary identity received an unexpected project set.',
      },
    );

    const bearerBypass = await runTargetCanary(
      config,
      dependencies(config, { gatewayAcceptsMissingBearer: true }),
    );
    assert.equal(bearerBypass.status, 'FAIL');
    assert.equal(
      bearerBypass.checks.find((check) => check.id === 'mtls.director_to_gateway').status,
      'FAIL',
    );

    const aliasedKeyConfig = validConfig(fixture);
    aliasedKeyConfig.director_to_gateway.client_private_key_path = fixture.certificate;
    const aliasedKey = await runTargetCanary(
      aliasedKeyConfig,
      dependencies(aliasedKeyConfig),
    );
    assert.deepEqual(
      aliasedKey.checks.find((check) => check.id === 'inputs.protected_files').error,
      {
        code: 'material_permissions',
        message:
          'director_to_gateway_client_private_key must use mode 0400, 0440, 0600, or 0640.',
      },
    );
    assert.deepEqual(
      bearerBypass.registry_updates.find(
        (update) => update.id === 'mtls.live_director_to_gateway',
      ).status,
      'FAIL',
    );

    const invalidBearerBypass = await runTargetCanary(
      config,
      dependencies(config, { gatewayAcceptsInvalidBearer: true }),
    );
    assert.deepEqual(
      invalidBearerBypass.checks.find(
        (check) => check.id === 'mtls.director_to_gateway',
      ).error,
      {
        code: 'gateway_invalid_bearer_accepted',
        message: 'Endpoint returned status 404; expected 401.',
      },
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('evidence writer requires a new external directory and enforces private modes', async () => {
  const fixture = await materialFixture();
  const workspace = path.join(fixture.root, 'workspace');
  const output = path.join(fixture.root, 'canary-evidence');
  await mkdir(workspace);
  try {
    const config = validConfig(fixture);
    const result = await writeTargetCanaryEvidence({
      config,
      outputDirectory: output,
      workspaceRoot: workspace,
      dependencies: dependencies(config),
    });
    assert.equal(result.report.status, 'PASS');
    assert.equal((await stat(output)).mode & 0o777, 0o700);
    assert.equal((await stat(result.reportPath)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(result.reportPath, 'utf8')), result.report);

    await assert.rejects(
      writeTargetCanaryEvidence({
        config,
        outputDirectory: output,
        workspaceRoot: workspace,
        dependencies: dependencies(config),
      }),
      /EEXIST/,
    );
    await assert.rejects(
      writeTargetCanaryEvidence({
        config,
        outputDirectory: path.join(workspace, 'evidence'),
        workspaceRoot: workspace,
        dependencies: dependencies(config),
      }),
      /outside the source workspace/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

function dependencies(config, behavior = {}) {
  let id = 0;
  return {
    randomUUID: () => {
      id += 1;
      return `${id.toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`;
    },
    lookup: async () => [{ address: '192.0.2.10', family: 4 }],
    request: syntheticRequest(config, behavior),
  };
}

function syntheticRequest(config, behavior) {
  const discovery = {
    issuer: config.oidc.issuer,
    authorization_endpoint: `${config.oidc.issuer}/authorize?tenant=fixture`,
    token_endpoint: `${config.oidc.issuer}/token`,
    jwks_uri: `${config.oidc.issuer}/jwks`,
    end_session_endpoint: `${config.oidc.issuer}/logout`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
    code_challenge_methods_supported: ['S256'],
    id_token_signing_alg_values_supported: ['RS256'],
    subject_types_supported: ['public'],
  };
  return async (request) => {
    const hostname = request.url.hostname;
    const pathname = request.url.pathname;
    if (hostname === new URL(config.oidc.issuer).hostname) {
      return response(200, { 'content-type': ['application/json'] }, discovery);
    }
    if (hostname === new URL(config.public.origin).hostname) {
      if (request.headers.host === 'canary-invalid.invalid') {
        throw new CanaryTransportError('ECONNRESET');
      }
      if (pathname === '/') {
        return response(
          200,
          {
            ...baselineHeaders,
            'cache-control': ['no-cache'],
            'content-type': ['text/html; charset=utf-8'],
          },
          '',
        );
      }
      if (pathname === '/health/live' || pathname === '/health/ready') {
        return response(404, baselineHeaders, '');
      }
      if (pathname === '/api/v1/auth/oidc/start') {
        const authorizationUrl = new URL(discovery.authorization_endpoint);
        authorizationUrl.searchParams.set('client_id', config.oidc.client_id);
        authorizationUrl.searchParams.set('redirect_uri', config.oidc.redirect_uri);
        authorizationUrl.searchParams.set('response_type', 'code');
        authorizationUrl.searchParams.set('scope', config.oidc.scopes.join(' '));
        authorizationUrl.searchParams.set('state', 'a'.repeat(43));
        authorizationUrl.searchParams.set('nonce', 'b'.repeat(43));
        authorizationUrl.searchParams.set('code_challenge', 'c'.repeat(43));
        authorizationUrl.searchParams.set('code_challenge_method', 'S256');
        return response(
          302,
          {
            ...baselineHeaders,
            'content-security-policy': [
              ...baselineHeaders['content-security-policy'],
              "default-src 'none'",
            ],
            'cache-control': ['no-store'],
            pragma: ['no-cache'],
            location: [authorizationUrl.href],
            'set-cookie': [
              `__Host-dirizhor_oidc=${'o'.repeat(43)}; Max-Age=600; Path=/; HttpOnly; Secure; SameSite=Lax; Priority=High`,
            ],
          },
          '',
        );
      }
      if (pathname === '/api/v1/projects') {
        if (request.headers.cookie === undefined) {
          return response(401, baselineHeaders, { error: { code: 'unauthorized' } });
        }
        const items = [{ id: projectId }];
        if (behavior.extraProject) {
          items.push({ id: extraProjectId });
        }
        return response(
          200,
          {
            ...baselineHeaders,
            'content-type': ['application/json'],
            'x-request-id': [request.headers['x-request-id']],
          },
          { items, next_cursor: null },
        );
      }
    }
    if (hostname === new URL(config.director_to_gateway.origin).hostname) {
      if (request.cert === undefined) {
        throw new CanaryTransportError('ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED');
      }
      if (request.headers.authorization === undefined) {
        return behavior.gatewayAcceptsMissingBearer
          ? response(404, {}, { error: { code: 'not_found' } })
          : response(401, {}, { error: { code: 'unauthorized_service' } });
      }
      if (
        request.headers.authorization === 'Bearer target-canary-invalid' &&
        behavior.gatewayAcceptsInvalidBearer
      ) {
        return response(404, {}, { error: { code: 'not_found' } });
      }
      if (!validWorkloadAuthorization(request.headers.authorization, 'director-api', 'agent-gateway')) {
        return behavior.gatewayAcceptsAllInvalidBearer
          ? response(404, {}, { error: { code: 'not_found' } })
          : response(401, {}, { error: { code: 'unauthorized_service' } });
      }
      return response(404, {}, { error: { code: 'not_found' } });
    }
    if (hostname === new URL(config.gateway_to_director.origin).hostname) {
      if (request.cert === undefined || request.headers.authorization === undefined) {
        return response(401, {}, { error: { code: 'unauthorized_service' } });
      }
      if (!validWorkloadAuthorization(request.headers.authorization, 'agent-gateway', 'director-api')) {
        return response(401, {}, { error: { code: 'unauthorized_service' } });
      }
      return response(403, {}, { error: { code: 'capability_invalid' } });
    }
    throw new Error('Unexpected synthetic request.');
  };
}

function response(statusCode, headers, body) {
  return {
    statusCode,
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
    tls: {
      authorized: true,
      protocol: 'TLSv1.3',
      peerFingerprint256: peerFingerprint,
    },
  };
}

function validConfig(fixture) {
  return {
    schema_version: 2,
    execution_id: 'CHG-123-target-canary-01',
    environment: 'production-pilot',
    request_timeout_ms: 10_000,
    workload_token_ttl_seconds: 60,
    public: {
      origin: 'https://director.example.test',
      ca_path: null,
    },
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
      ca_path: fixture.certificate,
      client_certificate_path: fixture.certificate,
      client_private_key_path: fixture.privateKey,
      workload_signing_key_id: 'director-key-current',
      workload_signing_private_key_file: fixture.workloadSigningKeyA,
    },
    gateway_to_director: {
      origin: 'https://director.internal.test:8444',
      server_name: 'director.internal.test',
      ca_path: fixture.certificate,
      client_certificate_path: fixture.certificate,
      client_private_key_path: fixture.privateKey,
      workload_signing_key_id: 'gateway-key-current',
      workload_signing_private_key_file: fixture.workloadSigningKeyB,
    },
  };
}

async function materialFixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-target-canary-'));
  const certificate = path.join(root, 'client.crt');
  const privateKey = path.join(root, 'client.key');
  const opensslConfig = path.join(root, 'openssl.cnf');
  await writeFile(
    opensslConfig,
    [
      '[req]',
      'distinguished_name = distinguished_name',
      'x509_extensions = leaf_extensions',
      'prompt = no',
      '[distinguished_name]',
      'CN = localhost',
      '[leaf_extensions]',
      'subjectAltName = DNS:localhost',
      'basicConstraints = critical,CA:TRUE',
      'keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign',
      'extendedKeyUsage = serverAuth,clientAuth',
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  execFileSync(
    '/usr/bin/openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-config',
      opensslConfig,
      '-days',
      '1',
      '-keyout',
      privateKey,
      '-out',
      certificate,
    ],
    { stdio: 'ignore' },
  );
  await chmod(certificate, 0o644);
  await chmod(privateKey, 0o600);
  const sessionTokenPath = path.join(root, 'session-token');
  const workloadSigningKeyAPath = path.join(root, 'workload-signing-key-a');
  const workloadSigningKeyBPath = path.join(root, 'workload-signing-key-b');
  const workloadSigningKeyAValue = signingKeyBase64();
  const workloadSigningKeyBValue = signingKeyBase64();
  await writeFile(sessionTokenPath, `${sessionToken}\n`, { mode: 0o600 });
  await writeFile(workloadSigningKeyAPath, `${workloadSigningKeyAValue}\n`, { mode: 0o600 });
  await writeFile(workloadSigningKeyBPath, `${workloadSigningKeyBValue}\n`, { mode: 0o600 });
  return {
    root,
    certificate,
    privateKey,
    sessionToken: sessionTokenPath,
    workloadSigningKeyA: workloadSigningKeyAPath,
    workloadSigningKeyB: workloadSigningKeyBPath,
    workloadSigningKeyAValue,
    workloadSigningKeyBValue,
  };
}

function signingKeyBase64() {
  return generateKeyPairSync('ed25519').privateKey
    .export({ format: 'der', type: 'pkcs8' })
    .toString('base64');
}

function validWorkloadAuthorization(authorization, issuer, audience) {
  const token = authorization?.match(/^Bearer ([A-Za-z0-9_.-]+)$/)?.[1];
  if (token === undefined) return false;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[1] === undefined) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    return (
      payload.v === 1 &&
      payload.iss === issuer &&
      payload.aud === audience &&
      Number.isSafeInteger(payload.iat) &&
      Number.isSafeInteger(payload.exp) &&
      payload.exp > now &&
      payload.iat <= now + 5 &&
      payload.exp - payload.iat <= 300
    );
  } catch {
    return false;
  }
}
