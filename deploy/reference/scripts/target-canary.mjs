#!/usr/bin/env node

import { X509Certificate, createHash, randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$/;
const hostnamePattern = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;
const evidenceReferencePattern = /^(?:alert|artifact|backup|change|dashboard|run|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const asymmetricAlgorithms = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);
const protectedModes = new Set([0o400, 0o440, 0o600, 0o640]);
const acceptedConnectionCloseCodes = new Set([
  'ECONNRESET',
  'EPIPE',
  'ERR_STREAM_PREMATURE_CLOSE',
]);
const acceptedClientCertificateRejectionCodes = new Set([
  ...acceptedConnectionCloseCodes,
  'EPROTO',
  'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
  'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED',
  'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
]);
const securityHeaders = Object.freeze({
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'content-security-policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
});

export class CanaryFailure extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CanaryFailure';
    this.code = code;
  }
}

export class CanaryTransportError extends Error {
  constructor(transportCode) {
    super('HTTPS request failed before a valid response.');
    this.name = 'CanaryTransportError';
    this.code = 'transport_error';
    this.transportCode = transportCode;
  }
}

export function validateTargetCanaryConfig(document) {
  assertObject(document, 'config');
  assertExactKeys(
    document,
    [
      'schema_version',
      'execution_id',
      'environment',
      'request_timeout_ms',
      'public',
      'oidc',
      'session',
      'director_to_gateway',
      'gateway_to_director',
    ],
    'config',
  );
  if (document.schema_version !== 1) {
    throw new Error('Target canary config schema_version must be 1.');
  }
  assertIdentifier(document.execution_id, 'execution_id');
  assertIdentifier(document.environment, 'environment');
  if (
    !Number.isSafeInteger(document.request_timeout_ms) ||
    document.request_timeout_ms < 1_000 ||
    document.request_timeout_ms > 30_000
  ) {
    throw new Error('request_timeout_ms must be an integer from 1000 through 30000.');
  }

  validatePublicConfig(document.public);
  validateOidcConfig(document.oidc);
  validateSessionConfig(document.session);
  validateServiceDirection(document.director_to_gateway, 'director_to_gateway');
  validateServiceDirection(document.gateway_to_director, 'gateway_to_director');
  validateCrossFieldConfig(document);
  return document;
}

export async function runTargetCanary(config, dependencies = {}) {
  validateTargetCanaryConfig(config);
  const runtime = {
    now: dependencies.now ?? (() => new Date()),
    monotonicNow: dependencies.monotonicNow ?? (() => Date.now()),
    lookup: dependencies.lookup ?? lookup,
    request: dependencies.request ?? requestHttps,
    readFile: dependencies.readFile ?? readFile,
    stat: dependencies.stat ?? stat,
    randomUUID: dependencies.randomUUID ?? randomUUID,
  };
  const startedAt = isoNow(runtime.now);
  const materialReader = createMaterialReader(runtime);
  const checks = [];
  const definitions = [
    ['inputs.protected_files', () => checkProtectedFiles(config, materialReader)],
    ['target.dns', () => checkDns(config, runtime)],
    ['edge.ui_contract', () => checkEdgeUi(config, runtime, materialReader)],
    ['edge.hidden_health', () => checkHiddenHealth(config, runtime, materialReader)],
    ['edge.host_rejection', () => checkHostRejection(config, runtime, materialReader)],
    ['oidc.discovery', () => checkOidcDiscovery(config, runtime, materialReader)],
    ['oidc.start_contract', () => checkOidcStart(config, runtime, materialReader)],
    [
      'mtls.director_to_gateway',
      () => checkDirectorToGateway(config, runtime, materialReader),
    ],
    [
      'mtls.gateway_to_director',
      () => checkGatewayToDirector(config, runtime, materialReader),
    ],
    ['application.session_read', () => checkSessionRead(config, runtime, materialReader)],
  ];

  for (const [id, execute] of definitions) {
    checks.push(await executeCheck(id, execute, runtime));
  }

  const completedAt = isoNow(runtime.now);
  const status = checks.every((check) => check.status === 'PASS') ? 'PASS' : 'FAIL';
  const evidenceRef = `run:${config.execution_id}/target-canary`;
  const report = {
    schema_version: 1,
    execution_id: config.execution_id,
    environment: config.environment,
    started_at: startedAt,
    completed_at: completedAt,
    status,
    evidence_ref: evidenceRef,
    checks,
    registry_updates: registryUpdates(checks, evidenceRef),
    external_evidence_refs: [config.session.browser_flow_evidence_ref],
    limitations: [
      'Does not inspect the running Nginx configuration or replace nginx -t.',
      'Does not replace certificate profile, expiry, SAN, EKU, and chain preflight.',
      'Does not complete corporate IdP MFA, callback replay, logout, or revoke-all checks.',
      'Does not execute the mutating primary application or failure-mode canaries.',
    ],
  };
  return {
    ...report,
    report_sha256: canonicalHash(report),
  };
}

export async function writeTargetCanaryEvidence({
  config,
  outputDirectory,
  workspaceRoot = defaultWorkspaceRoot,
  dependencies,
}) {
  validateTargetCanaryConfig(config);
  const resolvedOutput = path.resolve(outputDirectory);
  const resolvedWorkspace = path.resolve(workspaceRoot);
  if (isWithin(resolvedOutput, resolvedWorkspace)) {
    throw new Error('Target canary output directory must be outside the source workspace.');
  }
  await mkdir(resolvedOutput, { mode: 0o700 });
  await chmod(resolvedOutput, 0o700);
  const report = await runTargetCanary(config, dependencies);
  const reportPath = path.join(resolvedOutput, 'target-canary-evidence.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(reportPath, 0o600);
  return { report, reportPath };
}

export async function requestHttps(options) {
  return new Promise((resolve, reject) => {
    const requestOptions = {
      method: options.method,
      headers: options.headers,
      servername: options.servername ?? options.url.hostname,
      rejectUnauthorized: true,
      ...(options.ca === undefined ? {} : { ca: options.ca }),
      ...(options.cert === undefined ? {} : { cert: options.cert }),
      ...(options.key === undefined ? {} : { key: options.key }),
    };
    let settled = false;
    const request = https.request(options.url, requestOptions, (response) => {
      const socket = response.socket;
      if (socket === null || typeof socket.getPeerCertificate !== 'function') {
        settled = true;
        response.resume();
        reject(new CanaryTransportError('TLS_SOCKET_UNAVAILABLE'));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        if (options.captureBody === false || settled) {
          return;
        }
        size += chunk.length;
        if (size > (options.maxBodyBytes ?? 1024 * 1024)) {
          settled = true;
          request.destroy();
          reject(new CanaryTransportError('RESPONSE_BODY_TOO_LARGE'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('aborted', () => {
        if (!settled) {
          settled = true;
          reject(new CanaryTransportError('ERR_STREAM_PREMATURE_CLOSE'));
        }
      });
      response.on('error', (error) => {
        if (!settled) {
          settled = true;
          reject(
            new CanaryTransportError(
              typeof error.code === 'string' ? error.code : 'RESPONSE_STREAM_ERROR',
            ),
          );
        }
      });
      response.on('end', () => {
        if (settled) {
          return;
        }
        settled = true;
        const peer = socket.getPeerCertificate();
        resolve({
          statusCode: response.statusCode ?? 0,
          headers: normalizeHeaders(response.rawHeaders),
          body: options.captureBody === false ? '' : Buffer.concat(chunks).toString('utf8'),
          tls: {
            authorized: socket.authorized,
            protocol: socket.getProtocol(),
            peerFingerprint256:
              typeof peer.fingerprint256 === 'string' ? peer.fingerprint256 : null,
          },
        });
      });
    });
    request.setTimeout(options.timeoutMs, () => {
      request.destroy(new CanaryTransportError('ETIMEDOUT'));
    });
    request.on('error', (error) => {
      if (settled) {
        return;
      }
      settled = true;
      reject(
        error instanceof CanaryTransportError
          ? error
          : new CanaryTransportError(
              typeof error.code === 'string' ? error.code : 'UNKNOWN_TRANSPORT_ERROR',
            ),
      );
    });
    if (options.body !== undefined) {
      request.write(options.body);
    }
    request.end();
  });
}

async function executeCheck(id, execute, runtime) {
  const began = runtime.monotonicNow();
  try {
    const observations = await execute();
    return {
      id,
      status: 'PASS',
      observed_at: isoNow(runtime.now),
      duration_ms: duration(runtime.monotonicNow() - began),
      observations,
      error: null,
    };
  } catch (error) {
    const failure = reportedFailure(error);
    return {
      id,
      status: 'FAIL',
      observed_at: isoNow(runtime.now),
      duration_ms: duration(runtime.monotonicNow() - began),
      observations: null,
      error: failure,
    };
  }
}

async function checkProtectedFiles(config, reader) {
  const specifications = materialSpecifications(config);
  const files = [];
  for (const specification of specifications) {
    const material = await reader.read(specification);
    files.push({
      label: specification.label,
      mode: modeString(material.mode),
      protected: specification.protected,
    });
  }
  return { file_count: files.length, files };
}

async function checkDns(config, runtime) {
  const roles = [
    ['public', new URL(config.public.origin).hostname],
    ['oidc', new URL(config.oidc.issuer).hostname],
    ['gateway', new URL(config.director_to_gateway.origin).hostname],
    ['director', new URL(config.gateway_to_director.origin).hostname],
  ];
  const observations = [];
  for (const [role, hostname] of roles) {
    let answers;
    try {
      answers = await runtime.lookup(hostname, { all: true, verbatim: true });
    } catch {
      fail('dns_resolution_failed', `DNS resolution failed for the ${role} endpoint.`);
    }
    if (!Array.isArray(answers) || answers.length === 0) {
      fail('dns_no_answers', `DNS returned no addresses for the ${role} endpoint.`);
    }
    const families = [...new Set(answers.map((answer) => answer.family))].sort();
    if (families.some((family) => family !== 4 && family !== 6)) {
      fail('dns_invalid_answer', `DNS returned an unsupported address for the ${role} endpoint.`);
    }
    observations.push({ role, answer_count: answers.length, address_families: families });
  }
  return { endpoints: observations };
}

async function checkEdgeUi(config, runtime, reader) {
  const response = await publicRequest(config, runtime, reader, '/', {
    method: 'GET',
    headers: { accept: 'text/html' },
    captureBody: false,
  });
  assertStatus(response, 200, 'edge_ui_status');
  assertTls(response);
  assertSecurityHeaders(response);
  requireHeaderValue(response, 'cache-control', 'no-cache', 'edge_cache_policy');
  requireHeaderPrefix(response, 'content-type', 'text/html', 'edge_content_type');
  return { status_code: response.statusCode, tls: tlsObservation(response) };
}

async function checkHiddenHealth(config, runtime, reader) {
  const statuses = [];
  for (const pathname of ['/health/live', '/health/ready']) {
    const response = await publicRequest(config, runtime, reader, pathname, {
      method: 'GET',
      captureBody: false,
    });
    assertStatus(response, 404, 'edge_health_exposed');
    assertTls(response);
    assertSecurityHeaders(response);
    statuses.push({ route: pathname, status_code: response.statusCode });
  }
  return { routes: statuses };
}

async function checkHostRejection(config, runtime, reader) {
  const ca = await optionalMaterial(reader, config.public.ca_path, 'public_ca');
  try {
    await runtime.request({
      url: new URL('/', config.public.origin),
      method: 'GET',
      headers: commonHeaders({ host: 'canary-invalid.invalid' }),
      ca: ca?.content,
      servername: new URL(config.public.origin).hostname,
      timeoutMs: config.request_timeout_ms,
      captureBody: false,
    });
  } catch (error) {
    if (
      error instanceof CanaryTransportError &&
      acceptedConnectionCloseCodes.has(error.transportCode)
    ) {
      return { mismatched_host: 'connection_closed' };
    }
    throw error;
  }
  fail('edge_host_accepted', 'The edge returned an HTTP response for a mismatched Host.');
}

async function checkOidcDiscovery(config, runtime, reader) {
  const ca = await optionalMaterial(reader, config.oidc.ca_path, 'oidc_ca');
  const response = await runtime.request({
    url: oidcDiscoveryUrl(config.oidc.issuer),
    method: 'GET',
    headers: commonHeaders({ accept: 'application/json' }),
    ca: ca?.content,
    timeoutMs: config.request_timeout_ms,
    maxBodyBytes: 1024 * 1024,
  });
  assertStatus(response, 200, 'oidc_discovery_status');
  assertTls(response);
  requireHeaderPrefix(
    response,
    'content-type',
    'application/json',
    'oidc_discovery_content_type',
  );
  const metadata = jsonObject(response.body, 'oidc_discovery_json');
  assertOidcMetadata(metadata, config.oidc);
  return {
    exact_issuer: true,
    authorization_code: true,
    pkce_method: 'S256',
    token_endpoint_auth_method: config.oidc.token_endpoint_auth_method,
    id_token_signing_algorithm: config.oidc.id_token_signing_algorithm,
    rp_initiated_logout: typeof metadata.end_session_endpoint === 'string',
    tls: tlsObservation(response),
  };
}

async function checkOidcStart(config, runtime, reader) {
  const response = await publicRequest(
    config,
    runtime,
    reader,
    '/api/v1/auth/oidc/start',
    { method: 'GET', maxBodyBytes: 64 * 1024 },
  );
  assertStatus(response, 302, 'oidc_start_status');
  assertTls(response);
  assertSecurityHeaders(response);
  requireHeaderValue(response, 'cache-control', 'no-store', 'oidc_start_cache');
  requireHeaderValue(response, 'pragma', 'no-cache', 'oidc_start_cache');
  requireHeaderValue(response, 'referrer-policy', 'no-referrer', 'oidc_start_referrer');
  requireHeaderValue(response, 'content-security-policy', "default-src 'none'", 'oidc_start_csp');

  const location = singleHeader(response, 'location', 'oidc_start_location');
  const authorizationUrl = absoluteHttpsUrl(location, 'OIDC authorization redirect');
  const metadata = await fetchOidcMetadata(config, runtime, reader);
  const authorizationEndpoint = absoluteHttpsUrl(
    metadata.authorization_endpoint,
    'OIDC authorization endpoint',
  );
  if (
    authorizationUrl.origin !== authorizationEndpoint.origin ||
    authorizationUrl.pathname !== authorizationEndpoint.pathname
  ) {
    fail('oidc_wrong_authorization_endpoint', 'OIDC start redirected to an unexpected endpoint.');
  }
  assertEndpointQueryPreserved(authorizationEndpoint, authorizationUrl);
  requiredSearchParameter(authorizationUrl, 'client_id', config.oidc.client_id);
  requiredSearchParameter(authorizationUrl, 'redirect_uri', config.oidc.redirect_uri);
  requiredSearchParameter(authorizationUrl, 'response_type', 'code');
  requiredSearchParameter(authorizationUrl, 'code_challenge_method', 'S256');
  base64url43Parameter(authorizationUrl, 'state');
  base64url43Parameter(authorizationUrl, 'nonce');
  base64url43Parameter(authorizationUrl, 'code_challenge');
  if (authorizationUrl.searchParams.has('code_verifier')) {
    fail('oidc_pkce_verifier_exposed', 'OIDC start exposed the PKCE verifier.');
  }
  const scopes = requiredSingleSearchParameter(authorizationUrl, 'scope').split(' ');
  if (!sameStringSet(scopes, config.oidc.scopes)) {
    fail('oidc_scope_mismatch', 'OIDC start requested an unexpected scope set.');
  }
  assertOidcTransactionCookie(response);
  return {
    status_code: response.statusCode,
    authorization_endpoint_matched: true,
    state_nonce_pkce_present: true,
    transaction_cookie_protected: true,
  };
}

async function checkDirectorToGateway(config, runtime, reader) {
  const direction = config.director_to_gateway;
  const materials = await serviceMaterials(reader, direction, 'director_to_gateway');
  const agentRunId = runtime.randomUUID();
  const requestId = runtime.randomUUID();
  const pathname = `/internal/v1/agent-runs/${agentRunId}:cancel`;
  const body = JSON.stringify({
    protocol_version: '1.0',
    reason_code: 'service_shutdown',
    reason: 'target-canary-nonexistent-run',
    requested_at: isoNow(runtime.now),
  });
  const baseHeaders = {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(body)),
    'idempotency-key': agentRunId,
    'x-request-id': requestId,
  };
  const positive = await serviceRequest(config, runtime, direction, materials, pathname, {
    headers: { ...baseHeaders, authorization: `Bearer ${materials.bearer}` },
    body,
    includeClientIdentity: true,
  });
  assertStatusAndError(positive, 404, 'not_found', 'gateway_positive_contract');
  assertTls(positive);

  const missingBearer = await serviceRequest(
    config,
    runtime,
    direction,
    materials,
    pathname,
    { headers: baseHeaders, body, includeClientIdentity: true },
  );
  assertStatusAndError(
    missingBearer,
    401,
    'unauthorized_service',
    'gateway_bearer_not_required',
  );

  const invalidBearer = await serviceRequest(
    config,
    runtime,
    direction,
    materials,
    pathname,
    {
      headers: { ...baseHeaders, authorization: 'Bearer target-canary-invalid' },
      body,
      includeClientIdentity: true,
    },
  );
  assertStatusAndError(
    invalidBearer,
    401,
    'unauthorized_service',
    'gateway_invalid_bearer_accepted',
  );

  await expectTransportRejection(
    () =>
      serviceRequest(config, runtime, direction, materials, pathname, {
        headers: { ...baseHeaders, authorization: `Bearer ${materials.bearer}` },
        body,
        includeClientIdentity: false,
      }),
    acceptedClientCertificateRejectionCodes,
    'gateway_client_certificate_not_required',
  );
  return {
    authenticated_domain_response: { status_code: 404, error_code: 'not_found' },
    missing_bearer_rejected: true,
    invalid_bearer_rejected: true,
    missing_client_certificate_rejected: true,
    client_certificate_fingerprint_sha256: certificateFingerprint(materials.cert.content),
    server_tls: tlsObservation(positive),
  };
}

async function checkGatewayToDirector(config, runtime, reader) {
  const direction = config.gateway_to_director;
  const materials = await serviceMaterials(reader, direction, 'gateway_to_director');
  const agentRunId = runtime.randomUUID();
  const requestId = runtime.randomUUID();
  const pathname = `/internal/v1/agent-runs/${agentRunId}/context-bundle:redeem`;
  const body = JSON.stringify({
    protocol_version: '1.0',
    request_fingerprint: `sha256:${'0'.repeat(64)}`,
    expected_context_set_hash: `sha256:${'1'.repeat(64)}`,
  });
  const baseHeaders = {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(body)),
    'x-agent-capability': `target-canary-${agentRunId}`,
    'x-request-id': requestId,
  };
  const positive = await serviceRequest(config, runtime, direction, materials, pathname, {
    headers: { ...baseHeaders, authorization: `Bearer ${materials.bearer}` },
    body,
    includeClientIdentity: true,
  });
  assertStatusAndError(positive, 403, 'capability_invalid', 'director_positive_contract');
  assertTls(positive);

  const missingBearer = await serviceRequest(
    config,
    runtime,
    direction,
    materials,
    pathname,
    { headers: baseHeaders, body, includeClientIdentity: true },
  );
  assertStatusAndError(
    missingBearer,
    401,
    'unauthorized_service',
    'director_bearer_not_required',
  );

  const invalidBearer = await serviceRequest(
    config,
    runtime,
    direction,
    materials,
    pathname,
    {
      headers: { ...baseHeaders, authorization: 'Bearer target-canary-invalid' },
      body,
      includeClientIdentity: true,
    },
  );
  assertStatusAndError(
    invalidBearer,
    401,
    'unauthorized_service',
    'director_invalid_bearer_accepted',
  );

  const missingCertificate = await serviceRequest(
    config,
    runtime,
    direction,
    materials,
    pathname,
    {
      headers: { ...baseHeaders, authorization: `Bearer ${materials.bearer}` },
      body,
      includeClientIdentity: false,
    },
  );
  assertStatusAndError(
    missingCertificate,
    401,
    'unauthorized_service',
    'director_client_certificate_not_required',
  );
  return {
    authenticated_domain_response: { status_code: 403, error_code: 'capability_invalid' },
    missing_bearer_rejected: true,
    invalid_bearer_rejected: true,
    missing_client_certificate_rejected: true,
    client_certificate_fingerprint_sha256: certificateFingerprint(materials.cert.content),
    server_tls: tlsObservation(positive),
  };
}

async function checkSessionRead(config, runtime, reader) {
  const requestId = runtime.randomUUID();
  const unauthenticated = await publicRequest(
    config,
    runtime,
    reader,
    '/api/v1/projects?limit=100',
    { method: 'GET', headers: { 'x-request-id': requestId } },
  );
  assertPublicStatusAndError(
    unauthenticated,
    401,
    'unauthorized',
    'project_collection_public',
  );

  const tokenMaterial = await reader.read({
    label: 'session_token',
    path: config.session.token_file,
    protected: true,
    kind: 'session-token',
  });
  const token = secretText(tokenMaterial.content, 'session token');
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    fail('session_token_invalid', 'Session token does not match the opaque token contract.');
  }
  const authenticatedRequestId = runtime.randomUUID();
  const authenticated = await publicRequest(
    config,
    runtime,
    reader,
    '/api/v1/projects?limit=100',
    {
      method: 'GET',
      headers: {
        cookie: `${config.session.cookie_name}=${token}`,
        'x-request-id': authenticatedRequestId,
      },
    },
  );
  assertStatus(authenticated, 200, 'project_collection_status');
  assertTls(authenticated);
  assertSecurityHeaders(authenticated);
  requireHeaderPrefix(
    authenticated,
    'content-type',
    'application/json',
    'project_collection_content_type',
  );
  requireHeaderValue(
    authenticated,
    'x-request-id',
    authenticatedRequestId,
    'project_request_id',
  );
  const page = jsonObject(authenticated.body, 'project_collection_json');
  if (!Array.isArray(page.items) || !('next_cursor' in page)) {
    fail('project_collection_shape', 'Project collection response has an invalid shape.');
  }
  const observedIds = page.items.map((item) => {
    if (!isObject(item) || typeof item.id !== 'string' || !uuidPattern.test(item.id)) {
      fail('project_collection_shape', 'Project collection contains an invalid project.');
    }
    return item.id.toLowerCase();
  });
  if (page.next_cursor !== null) {
    fail('project_collection_incomplete', 'Project canary cannot prove the complete project set.');
  }
  const expectedIds = config.session.expected_project_ids.map((value) => value.toLowerCase());
  if (!sameStringSet(observedIds, expectedIds)) {
    fail('project_scope_mismatch', 'Canary identity received an unexpected project set.');
  }
  return {
    unauthenticated_request_rejected: true,
    authenticated_status_code: 200,
    expected_project_count: expectedIds.length,
    observed_project_count: observedIds.length,
    exact_project_set: true,
    browser_flow_evidence_ref: config.session.browser_flow_evidence_ref,
  };
}

async function publicRequest(config, runtime, reader, pathname, options) {
  const ca = await optionalMaterial(reader, config.public.ca_path, 'public_ca');
  return runtime.request({
    url: new URL(pathname, config.public.origin),
    method: options.method,
    headers: commonHeaders(options.headers),
    ca: ca?.content,
    timeoutMs: config.request_timeout_ms,
    captureBody: options.captureBody,
    maxBodyBytes: options.maxBodyBytes,
  });
}

async function serviceRequest(config, runtime, direction, materials, pathname, options) {
  return runtime.request({
    url: new URL(pathname, direction.origin),
    method: 'POST',
    headers: commonHeaders(options.headers),
    body: options.body,
    ca: materials.ca.content,
    ...(options.includeClientIdentity
      ? { cert: materials.cert.content, key: materials.key.content }
      : {}),
    servername: direction.server_name,
    timeoutMs: config.request_timeout_ms,
    maxBodyBytes: 256 * 1024,
  });
}

async function serviceMaterials(reader, direction, label) {
  const [ca, cert, key, bearerMaterial] = await Promise.all([
    reader.read({ label: `${label}_ca`, path: direction.ca_path, protected: false, kind: 'pem' }),
    reader.read({
      label: `${label}_client_certificate`,
      path: direction.client_certificate_path,
      protected: false,
      kind: 'pem',
    }),
    reader.read({
      label: `${label}_client_private_key`,
      path: direction.client_private_key_path,
      protected: true,
      kind: 'pem',
    }),
    reader.read({
      label: `${label}_bearer_token`,
      path: direction.bearer_token_file,
      protected: true,
      kind: 'secret',
    }),
  ]);
  const bearer = secretText(bearerMaterial.content, `${label} bearer token`);
  if (bearer.length > 4096 || /\s/.test(bearer)) {
    fail('service_token_invalid', 'Service bearer token violates the mounted-secret contract.');
  }
  return { ca, cert, key, bearer };
}

async function fetchOidcMetadata(config, runtime, reader) {
  const ca = await optionalMaterial(reader, config.oidc.ca_path, 'oidc_ca');
  const response = await runtime.request({
    url: oidcDiscoveryUrl(config.oidc.issuer),
    method: 'GET',
    headers: commonHeaders({ accept: 'application/json' }),
    ca: ca?.content,
    timeoutMs: config.request_timeout_ms,
    maxBodyBytes: 1024 * 1024,
  });
  assertStatus(response, 200, 'oidc_discovery_status');
  assertTls(response);
  requireHeaderPrefix(
    response,
    'content-type',
    'application/json',
    'oidc_discovery_content_type',
  );
  const metadata = jsonObject(response.body, 'oidc_discovery_json');
  assertOidcMetadata(metadata, config.oidc);
  return metadata;
}

function assertOidcMetadata(metadata, config) {
  if (metadata.issuer !== config.issuer) {
    fail('oidc_issuer_mismatch', 'OIDC discovery issuer does not exactly match configuration.');
  }
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    if (typeof metadata[key] !== 'string') {
      fail('oidc_endpoint_missing', `OIDC discovery is missing ${key}.`);
    }
    absoluteHttpsUrl(metadata[key], `OIDC ${key}`);
  }
  if (!arrayIncludes(metadata.response_types_supported, 'code')) {
    fail('oidc_code_flow_unsupported', 'OIDC provider does not advertise authorization code flow.');
  }
  if (
    metadata.grant_types_supported !== undefined &&
    !arrayIncludes(metadata.grant_types_supported, 'authorization_code')
  ) {
    fail('oidc_code_grant_unsupported', 'OIDC provider rejects the authorization code grant.');
  }
  const tokenMethods = metadata.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
  if (!arrayIncludes(tokenMethods, config.token_endpoint_auth_method)) {
    fail('oidc_token_auth_unsupported', 'OIDC token endpoint authentication is incompatible.');
  }
  if (!arrayIncludes(metadata.code_challenge_methods_supported, 'S256')) {
    fail('oidc_pkce_unsupported', 'OIDC provider does not advertise PKCE S256.');
  }
  if (
    !arrayIncludes(
      metadata.id_token_signing_alg_values_supported,
      config.id_token_signing_algorithm,
    )
  ) {
    fail('oidc_signing_algorithm_unsupported', 'OIDC ID Token algorithm is incompatible.');
  }
  if (
    !Array.isArray(metadata.subject_types_supported) ||
    !metadata.subject_types_supported.some((value) => value === 'public' || value === 'pairwise')
  ) {
    fail('oidc_subject_type_unsupported', 'OIDC provider has no supported subject type.');
  }
  if (config.require_rp_initiated_logout) {
    if (typeof metadata.end_session_endpoint !== 'string') {
      fail('oidc_logout_missing', 'OIDC provider does not advertise the required logout endpoint.');
    }
    absoluteHttpsUrl(metadata.end_session_endpoint, 'OIDC end_session_endpoint');
  } else if (typeof metadata.end_session_endpoint === 'string') {
    absoluteHttpsUrl(metadata.end_session_endpoint, 'OIDC end_session_endpoint');
  }
}

function assertOidcTransactionCookie(response) {
  const cookies = headerValues(response, 'set-cookie');
  const matchingCookies = cookies.filter((value) =>
    value.startsWith('__Host-dirizhor_oidc='),
  );
  if (matchingCookies.length !== 1) {
    fail('oidc_transaction_cookie_missing', 'OIDC start did not issue its transaction cookie.');
  }
  const cookie = matchingCookies[0];
  const parts = cookie.split(';').map((value) => value.trim());
  const token = parts[0].slice('__Host-dirizhor_oidc='.length);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    fail('oidc_transaction_cookie_invalid', 'OIDC transaction cookie value is invalid.');
  }
  const attributes = new Map();
  for (const part of parts.slice(1)) {
    const separator = part.indexOf('=');
    const name = (separator === -1 ? part : part.slice(0, separator)).toLowerCase();
    if (attributes.has(name)) {
      fail('oidc_transaction_cookie_unprotected', 'OIDC transaction cookie repeats an attribute.');
    }
    attributes.set(
      name,
      separator === -1 ? true : part.slice(separator + 1),
    );
  }
  if (
    attributes.get('secure') !== true ||
    attributes.get('httponly') !== true ||
    attributes.get('path') !== '/' ||
    String(attributes.get('samesite')).toLowerCase() !== 'lax' ||
    String(attributes.get('priority')).toLowerCase() !== 'high' ||
    attributes.has('domain')
  ) {
    fail('oidc_transaction_cookie_unprotected', 'OIDC transaction cookie flags are incomplete.');
  }
  const maxAge = Number(attributes.get('max-age'));
  if (!Number.isSafeInteger(maxAge) || maxAge < 60 || maxAge > 15 * 60) {
    fail('oidc_transaction_cookie_ttl', 'OIDC transaction cookie TTL is outside policy.');
  }
}

function assertStatusAndError(response, statusCode, errorCode, failureCode) {
  assertStatus(response, statusCode, failureCode);
  const payload = jsonObject(response.body, failureCode);
  if (!isObject(payload.error) || payload.error.code !== errorCode) {
    fail(failureCode, 'Internal service returned an unexpected protocol error.');
  }
}

function assertPublicStatusAndError(response, statusCode, errorCode, failureCode) {
  assertStatus(response, statusCode, failureCode);
  const payload = jsonObject(response.body, failureCode);
  if (!isObject(payload.error) || payload.error.code !== errorCode) {
    fail(failureCode, 'Public API returned an unexpected protocol error.');
  }
}

async function expectTransportRejection(execute, acceptedCodes, failureCode) {
  try {
    await execute();
  } catch (error) {
    if (error instanceof CanaryTransportError && acceptedCodes.has(error.transportCode)) {
      return;
    }
    throw error;
  }
  fail(failureCode, 'The endpoint accepted a request without the required client certificate.');
}

function assertStatus(response, expected, failureCode) {
  if (response.statusCode !== expected) {
    fail(failureCode, `Endpoint returned status ${response.statusCode}; expected ${expected}.`);
  }
}

function assertTls(response) {
  if (
    !isObject(response.tls) ||
    response.tls.authorized !== true ||
    !['TLSv1.2', 'TLSv1.3'].includes(response.tls.protocol) ||
    typeof response.tls.peerFingerprint256 !== 'string' ||
    !/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(response.tls.peerFingerprint256)
  ) {
    fail('tls_contract_failed', 'Endpoint did not prove an authorized TLS 1.2+ peer.');
  }
}

function tlsObservation(response) {
  return {
    protocol: response.tls.protocol,
    peer_certificate_fingerprint_sha256: normalizeFingerprint(
      response.tls.peerFingerprint256,
    ),
  };
}

function assertSecurityHeaders(response) {
  for (const [name, expected] of Object.entries(securityHeaders)) {
    requireHeaderValue(response, name, expected, 'edge_security_headers');
  }
}

function requireHeaderValue(response, name, expected, failureCode) {
  if (!headerValues(response, name).includes(expected)) {
    fail(failureCode, `Response header ${name} does not match the target contract.`);
  }
}

function requireHeaderPrefix(response, name, expectedPrefix, failureCode) {
  if (!headerValues(response, name).some((value) => value.startsWith(expectedPrefix))) {
    fail(failureCode, `Response header ${name} does not match the target contract.`);
  }
}

function singleHeader(response, name, failureCode) {
  const values = headerValues(response, name);
  if (values.length !== 1 || values[0].length === 0) {
    fail(failureCode, `Response header ${name} must occur exactly once.`);
  }
  return values[0];
}

function headerValues(response, name) {
  const value = response.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value : typeof value === 'string' ? [value] : [];
}

function commonHeaders(headers = {}) {
  return {
    'user-agent': 'dirizhor-target-canary/1',
    ...headers,
  };
}

function normalizeHeaders(rawHeaders) {
  const normalized = {};
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index].toLowerCase();
    const value = rawHeaders[index + 1];
    normalized[name] ??= [];
    normalized[name].push(value);
  }
  return normalized;
}

function createMaterialReader(runtime) {
  const cache = new Map();
  return {
    read(specification) {
      const key = `${specification.kind}:${specification.protected ? 'protected' : 'public'}:${specification.path}`;
      if (!cache.has(key)) {
        cache.set(key, readMaterial(specification, runtime));
      }
      return cache.get(key);
    },
  };
}

async function readMaterial(specification, runtime) {
  let metadata;
  let content;
  try {
    [metadata, content] = await Promise.all([
      runtime.stat(specification.path),
      runtime.readFile(specification.path),
    ]);
  } catch {
    fail('material_unreadable', `${specification.label} could not be read.`);
  }
  if (!metadata.isFile()) {
    fail('material_not_file', `${specification.label} is not a regular file.`);
  }
  const mode = metadata.mode & 0o777;
  if (specification.protected) {
    if (!protectedModes.has(mode)) {
      fail('material_permissions', `${specification.label} must use mode 0400, 0440, 0600, or 0640.`);
    }
  } else if ((mode & 0o022) !== 0) {
    fail('material_permissions', `${specification.label} must not be group- or world-writable.`);
  }
  if (!Buffer.isBuffer(content) || content.length === 0 || content.length > 1024 * 1024) {
    fail('material_size', `${specification.label} has an invalid size.`);
  }
  return { content, mode };
}

function materialSpecifications(config) {
  const specifications = [];
  if (config.public.ca_path !== null) {
    specifications.push({
      label: 'public_ca',
      path: config.public.ca_path,
      protected: false,
      kind: 'pem',
    });
  }
  if (config.oidc.ca_path !== null) {
    specifications.push({
      label: 'oidc_ca',
      path: config.oidc.ca_path,
      protected: false,
      kind: 'pem',
    });
  }
  specifications.push({
    label: 'session_token',
    path: config.session.token_file,
    protected: true,
    kind: 'session-token',
  });
  for (const [label, direction] of [
    ['director_to_gateway', config.director_to_gateway],
    ['gateway_to_director', config.gateway_to_director],
  ]) {
    specifications.push(
      { label: `${label}_ca`, path: direction.ca_path, protected: false, kind: 'pem' },
      {
        label: `${label}_client_certificate`,
        path: direction.client_certificate_path,
        protected: false,
        kind: 'pem',
      },
      {
        label: `${label}_client_private_key`,
        path: direction.client_private_key_path,
        protected: true,
        kind: 'pem',
      },
      {
        label: `${label}_bearer_token`,
        path: direction.bearer_token_file,
        protected: true,
        kind: 'secret',
      },
    );
  }
  return specifications;
}

async function optionalMaterial(reader, materialPath, label) {
  return materialPath === null
    ? undefined
    : reader.read({ label, path: materialPath, protected: false, kind: 'pem' });
}

function secretText(content, label) {
  let value = content.toString('utf8');
  if (value.endsWith('\n')) {
    value = value.slice(0, -1);
  }
  if (value.length === 0 || value.includes('\n') || value.includes('\r') || value.includes('\0')) {
    fail('secret_format', `${label} must contain exactly one non-empty line.`);
  }
  return value;
}

function certificateFingerprint(encodedCertificate) {
  try {
    return normalizeFingerprint(new X509Certificate(encodedCertificate).fingerprint256);
  } catch {
    fail('client_certificate_invalid', 'Client certificate is not a valid X.509 certificate.');
  }
}

function normalizeFingerprint(value) {
  return `sha256:${value.replaceAll(':', '').toLowerCase()}`;
}

function oidcDiscoveryUrl(issuer) {
  const url = new URL(issuer);
  url.pathname = `${url.pathname.replace(/\/$/, '')}/.well-known/openid-configuration`;
  url.search = '';
  url.hash = '';
  return url;
}

function requiredSearchParameter(url, name, expected) {
  const value = requiredSingleSearchParameter(url, name);
  if (value !== expected) {
    fail('oidc_authorization_parameter', `OIDC authorization parameter ${name} is invalid.`);
  }
}

function assertEndpointQueryPreserved(endpoint, authorizationUrl) {
  for (const name of new Set(endpoint.searchParams.keys())) {
    const expected = endpoint.searchParams.getAll(name);
    const actual = authorizationUrl.searchParams.getAll(name);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      fail(
        'oidc_authorization_endpoint_query',
        'OIDC start did not preserve the configured authorization endpoint query.',
      );
    }
  }
}

function requiredSingleSearchParameter(url, name) {
  const values = url.searchParams.getAll(name);
  if (values.length !== 1 || values[0].length === 0) {
    fail('oidc_authorization_parameter', `OIDC authorization parameter ${name} is missing or repeated.`);
  }
  return values[0];
}

function base64url43Parameter(url, name) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(requiredSingleSearchParameter(url, name))) {
    fail('oidc_authorization_parameter', `OIDC authorization parameter ${name} is invalid.`);
  }
}

function absoluteHttpsUrl(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    fail('https_url_invalid', `${name} is not an absolute URL.`);
  }
  if (
    url.protocol !== 'https:' ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.hash.length > 0
  ) {
    fail('https_url_invalid', `${name} must use HTTPS without credentials or fragment.`);
  }
  return url;
}

function jsonObject(value, failureCode) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    fail(failureCode, 'Endpoint returned malformed JSON.');
  }
  if (!isObject(parsed)) {
    fail(failureCode, 'Endpoint returned a non-object JSON document.');
  }
  return parsed;
}

function registryUpdates(checks, evidenceRef) {
  const byId = new Map(checks.map((check) => [check.id, check]));
  const mappings = [
    ['edge.external_contract', ['edge.ui_contract', 'edge.hidden_health', 'edge.host_rejection']],
    ['mtls.live_director_to_gateway', ['mtls.director_to_gateway']],
    ['mtls.live_gateway_to_director', ['mtls.gateway_to_director']],
    ['oidc.discovery', ['oidc.discovery']],
  ];
  return mappings.map(([id, required]) => {
    const passed = required.every((checkId) => byId.get(checkId)?.status === 'PASS');
    const observed = required
      .map((checkId) => byId.get(checkId)?.observed_at)
      .filter((value) => typeof value === 'string')
      .sort()
      .at(-1);
    return {
      id,
      status: passed ? 'PASS' : 'FAIL',
      observed_at: observed ?? null,
      evidence_refs: [evidenceRef],
    };
  });
}

function reportedFailure(error) {
  if (error instanceof CanaryFailure) {
    return { code: error.code, message: error.message };
  }
  if (error instanceof CanaryTransportError) {
    return {
      code: error.code,
      message: `HTTPS transport failed (${error.transportCode}).`,
    };
  }
  return { code: 'unexpected_error', message: 'Canary check failed unexpectedly.' };
}

function fail(code, message) {
  throw new CanaryFailure(code, message);
}

function validatePublicConfig(value) {
  assertObject(value, 'public');
  assertExactKeys(value, ['origin', 'ca_path'], 'public');
  exactHttpsOrigin(value.origin, 'public.origin');
  nullableAbsolutePath(value.ca_path, 'public.ca_path');
}

function validateOidcConfig(value) {
  assertObject(value, 'oidc');
  assertExactKeys(
    value,
    [
      'issuer',
      'ca_path',
      'client_id',
      'redirect_uri',
      'scopes',
      'token_endpoint_auth_method',
      'id_token_signing_algorithm',
      'require_rp_initiated_logout',
    ],
    'oidc',
  );
  httpsUrl(value.issuer, 'oidc.issuer', false);
  nullableAbsolutePath(value.ca_path, 'oidc.ca_path');
  assertIdentifier(value.client_id, 'oidc.client_id');
  httpsUrl(value.redirect_uri, 'oidc.redirect_uri', false);
  if (!Array.isArray(value.scopes) || !value.scopes.includes('openid') || !sameStringSet(value.scopes, [...new Set(value.scopes)])) {
    throw new Error('oidc.scopes must be a unique non-empty scope list containing openid.');
  }
  if (
    value.scopes.some(
      (scope) => typeof scope !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(scope),
    )
  ) {
    throw new Error('oidc.scopes contains an invalid scope.');
  }
  if (!['client_secret_basic', 'client_secret_post'].includes(value.token_endpoint_auth_method)) {
    throw new Error('oidc.token_endpoint_auth_method is unsupported.');
  }
  if (!asymmetricAlgorithms.has(value.id_token_signing_algorithm)) {
    throw new Error('oidc.id_token_signing_algorithm must be asymmetric.');
  }
  if (typeof value.require_rp_initiated_logout !== 'boolean') {
    throw new Error('oidc.require_rp_initiated_logout must be boolean.');
  }
}

function validateSessionConfig(value) {
  assertObject(value, 'session');
  assertExactKeys(
    value,
    ['cookie_name', 'token_file', 'expected_project_ids', 'browser_flow_evidence_ref'],
    'session',
  );
  if (value.cookie_name !== '__Host-dirizhor_session') {
    throw new Error('session.cookie_name must match the protected Director cookie.');
  }
  absolutePath(value.token_file, 'session.token_file');
  if (
    !Array.isArray(value.expected_project_ids) ||
    value.expected_project_ids.length === 0 ||
    value.expected_project_ids.length > 100 ||
    value.expected_project_ids.some((projectId) => typeof projectId !== 'string' || !uuidPattern.test(projectId)) ||
    new Set(value.expected_project_ids.map((projectId) => projectId.toLowerCase())).size !==
      value.expected_project_ids.length
  ) {
    throw new Error('session.expected_project_ids must contain 1 through 100 unique UUIDs.');
  }
  if (
    typeof value.browser_flow_evidence_ref !== 'string' ||
    !evidenceReferencePattern.test(value.browser_flow_evidence_ref)
  ) {
    throw new Error('session.browser_flow_evidence_ref must be an opaque evidence reference.');
  }
}

function validateServiceDirection(value, name) {
  assertObject(value, name);
  assertExactKeys(
    value,
    [
      'origin',
      'server_name',
      'ca_path',
      'client_certificate_path',
      'client_private_key_path',
      'bearer_token_file',
    ],
    name,
  );
  const origin = exactHttpsOrigin(value.origin, `${name}.origin`);
  if (
    typeof value.server_name !== 'string' ||
    !hostnamePattern.test(value.server_name) ||
    net.isIP(value.server_name) !== 0 ||
    value.server_name.toLowerCase() !== origin.hostname.toLowerCase()
  ) {
    throw new Error(`${name}.server_name must exactly match the DNS origin hostname.`);
  }
  for (const key of [
    'ca_path',
    'client_certificate_path',
    'client_private_key_path',
    'bearer_token_file',
  ]) {
    absolutePath(value[key], `${name}.${key}`);
  }
}

function validateCrossFieldConfig(config) {
  const publicOrigin = new URL(config.public.origin);
  const redirectUri = new URL(config.oidc.redirect_uri);
  if (
    redirectUri.origin !== publicOrigin.origin ||
    redirectUri.pathname !== '/api/v1/auth/oidc/callback'
  ) {
    throw new Error('oidc.redirect_uri must use the public origin and exact callback path.');
  }
  if (
    config.session.browser_flow_evidence_ref ===
    `run:${config.execution_id}/target-canary`
  ) {
    throw new Error('Browser flow evidence must be external to the target canary report.');
  }
}

function exactHttpsOrigin(value, name) {
  const url = httpsUrl(value, name, true);
  if (net.isIP(url.hostname) !== 0) {
    throw new Error(`${name} must use a DNS hostname.`);
  }
  return url;
}

function httpsUrl(value, name, exactOrigin) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL.`);
  }
  if (
    url.protocol !== 'https:' ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0 ||
    (exactOrigin && url.pathname !== '/')
  ) {
    throw new Error(`${name} must be an absolute HTTPS URL.`);
  }
  return url;
}

function nullableAbsolutePath(value, name) {
  if (value !== null) {
    absolutePath(value, name);
  }
}

function absolutePath(value, name) {
  if (
    typeof value !== 'string' ||
    !path.isAbsolute(value) ||
    value.includes('\0') ||
    value.includes('\n') ||
    value.includes('\r')
  ) {
    throw new Error(`${name} must be an absolute file path.`);
  }
}

function assertIdentifier(value, name) {
  if (
    typeof value !== 'string' ||
    !identifierPattern.test(value) ||
    value.startsWith('replace-')
  ) {
    throw new Error(`${name} must be an opaque identifier.`);
  }
}

function assertObject(value, name) {
  if (!isObject(value)) {
    throw new Error(`${name} must be an object.`);
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertExactKeys(value, expected, name) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(sortedExpected)) {
    throw new Error(`${name} contains missing or unsupported fields.`);
  }
}

function arrayIncludes(value, expected) {
  return Array.isArray(value) && value.includes(expected);
}

function sameStringSet(left, right) {
  if (
    !Array.isArray(left) ||
    !Array.isArray(right) ||
    left.some((value) => typeof value !== 'string') ||
    right.some((value) => typeof value !== 'string')
  ) {
    return false;
  }
  return (
    new Set(left).size === left.length &&
    new Set(right).size === right.length &&
    [...left].sort().join('\0') === [...right].sort().join('\0')
  );
}

function modeString(mode) {
  return mode.toString(8).padStart(4, '0');
}

function duration(value) {
  return Number.isFinite(value) && value > 0 ? Math.round(value) : 0;
}

function isoNow(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error('Canary clock returned an invalid time.');
  }
  return value.toISOString();
}

function canonicalHash(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex')}`;
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (isObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function isWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function main(argv) {
  if (argv.length !== 2) {
    throw new Error(
      'Usage: node scripts/target-canary.mjs <new-output-directory> <config.json>',
    );
  }
  let config;
  try {
    config = JSON.parse(await readFile(argv[1], 'utf8'));
  } catch {
    throw new Error('Target canary config could not be read.');
  }
  const result = await writeTargetCanaryEvidence({
    config,
    outputDirectory: argv[0],
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        status: result.report.status,
        execution_id: result.report.execution_id,
        report_sha256: result.report.report_sha256,
        pass: result.report.checks.filter((check) => check.status === 'PASS').length,
        fail: result.report.checks.filter((check) => check.status === 'FAIL').length,
        evidence_file: path.basename(result.reportPath),
      },
      null,
      2,
    )}\n`,
  );
  process.exitCode = result.report.status === 'PASS' ? 0 : 1;
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : 'Target canary failed.';
    process.stderr.write(`Target canary failed: ${message}\n`);
    process.exitCode = 2;
  });
}
