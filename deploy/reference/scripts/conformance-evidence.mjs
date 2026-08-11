import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultRegistryPath = path.resolve(
  scriptDirectory,
  '../conformance/checks-v2.json',
);
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$/;
const ownerPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/;
const hostnamePattern = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const evidenceReferencePattern = /^(?:alert|artifact|backup|change|dashboard|run|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const statuses = new Set(['PASS', 'FAIL', 'NOT_RUN']);
const zeroDigest = `sha256:${'0'.repeat(64)}`;

export async function loadRegistry(registryPath = defaultRegistryPath) {
  let document;
  try {
    document = JSON.parse(await readFile(registryPath, 'utf8'));
  } catch {
    throw new Error('The conformance registry could not be read.');
  }
  assertObject(document, 'registry');
  assertExactKeys(document, ['registry_version', 'checks'], 'registry');
  if (document.registry_version !== 2 || !Array.isArray(document.checks)) {
    throw new Error('The conformance registry has an unsupported shape.');
  }
  const ids = new Set();
  for (const check of document.checks) {
    assertObject(check, 'registry check');
    assertExactKeys(check, ['id', 'category', 'stop_ship'], 'registry check');
    if (
      !identifierPattern.test(check.id) ||
      !identifierPattern.test(check.category) ||
      check.stop_ship !== true ||
      ids.has(check.id)
    ) {
      throw new Error('The conformance registry contains an invalid check.');
    }
    ids.add(check.id);
  }
  if (ids.size === 0) {
    throw new Error('The conformance registry is empty.');
  }
  return document;
}

export function validateEvidence(document, registry) {
  assertObject(document, 'evidence');
  assertExactKeys(
    document,
    [
      'schema_version',
      'registry_version',
      'execution_id',
      'environment',
      'started_at',
      'completed_at',
      'artifacts',
      'target',
      'recovery',
      'owners',
      'checks',
    ],
    'evidence',
  );
  if (document.schema_version !== 1 || document.registry_version !== registry.registry_version) {
    throw new Error('Evidence and registry versions are incompatible.');
  }
  assertIdentifier(document.execution_id, 'execution_id');
  assertIdentifier(document.environment, 'environment');
  const startedAt = timestamp(document.started_at, 'started_at');
  const completedAt = timestamp(document.completed_at, 'completed_at');
  if (completedAt < startedAt) {
    throw new Error('Evidence completion precedes its start.');
  }

  validateArtifacts(document.artifacts);
  validateTarget(document.target);
  validateRecovery(document.recovery);
  validateOwners(document.owners);

  if (!Array.isArray(document.checks)) {
    throw new Error('Evidence checks must be an array.');
  }
  const registryById = new Map(registry.checks.map((check) => [check.id, check]));
  const seen = new Set();
  const counts = { PASS: 0, FAIL: 0, NOT_RUN: 0 };
  const normalizedChecks = [];
  for (const check of document.checks) {
    assertObject(check, 'evidence check');
    assertExactKeys(
      check,
      ['id', 'status', 'observed_at', 'evidence_refs'],
      'evidence check',
    );
    if (
      typeof check.id !== 'string' ||
      !registryById.has(check.id) ||
      seen.has(check.id)
    ) {
      throw new Error('Evidence contains an unknown or duplicate check.');
    }
    if (!statuses.has(check.status)) {
      throw new Error('Evidence contains an unsupported check status.');
    }
    if (!Array.isArray(check.evidence_refs) || check.evidence_refs.length > 8) {
      throw new Error('Evidence references have an unsupported shape.');
    }
    if (check.status === 'NOT_RUN') {
      if (check.observed_at !== null || check.evidence_refs.length !== 0) {
        throw new Error('NOT_RUN checks cannot claim observations or evidence.');
      }
    } else {
      const observedAt = timestamp(check.observed_at, 'observed_at');
      if (
        observedAt < startedAt ||
        observedAt > completedAt ||
        check.evidence_refs.length === 0
      ) {
        throw new Error('Executed checks require timely evidence references.');
      }
      const uniqueReferences = new Set(check.evidence_refs);
      if (
        uniqueReferences.size !== check.evidence_refs.length ||
        check.evidence_refs.some(
          (reference) =>
            typeof reference !== 'string' ||
            !evidenceReferencePattern.test(reference),
        )
      ) {
        throw new Error('Evidence references must be unique opaque identifiers.');
      }
    }
    seen.add(check.id);
    counts[check.status] += 1;
    normalizedChecks.push({ id: check.id, status: check.status });
  }
  if (seen.size !== registryById.size) {
    throw new Error('Evidence does not cover every required check.');
  }

  normalizedChecks.sort((left, right) => left.id.localeCompare(right.id));
  const gateStatus = counts.PASS === registryById.size ? 'PASS' : 'BLOCKED';
  return {
    schema_version: document.schema_version,
    registry_version: document.registry_version,
    execution_id: document.execution_id,
    environment: document.environment,
    gate_status: gateStatus,
    counts: {
      pass: counts.PASS,
      fail: counts.FAIL,
      not_run: counts.NOT_RUN,
      required: registryById.size,
    },
    checks: normalizedChecks,
    report_sha256: canonicalHash({
      ...document,
      checks: [...document.checks].sort((left, right) => left.id.localeCompare(right.id)),
    }),
  };
}

function validateArtifacts(artifacts) {
  assertObject(artifacts, 'artifacts');
  const keys = [
    'director_image_digest',
    'gateway_image_digest',
    'ui_artifact_digest',
    'migration_manifest_digest',
  ];
  assertExactKeys(artifacts, keys, 'artifacts');
  if (
    keys.some(
      (key) => !digestPattern.test(artifacts[key]) || artifacts[key] === zeroDigest,
    )
  ) {
    throw new Error('Every release artifact requires a SHA-256 digest.');
  }
}

function validateTarget(target) {
  assertObject(target, 'target');
  assertExactKeys(
    target,
    [
      'public_origin',
      'director_internal_dns',
      'gateway_internal_dns',
      'postgresql_provider',
      'postgresql_version',
      'oidc_issuer',
      'oidc_client_id',
    ],
    'target',
  );
  httpsUrl(target.public_origin, 'public_origin', true);
  httpsUrl(target.oidc_issuer, 'oidc_issuer', false);
  if (
    !hostnamePattern.test(target.director_internal_dns) ||
    !hostnamePattern.test(target.gateway_internal_dns)
  ) {
    throw new Error('Internal service DNS names are invalid.');
  }
  for (const key of ['postgresql_provider', 'postgresql_version', 'oidc_client_id']) {
    assertIdentifier(target[key], key);
  }
}

function validateRecovery(recovery) {
  assertObject(recovery, 'recovery');
  assertExactKeys(
    recovery,
    ['approved_rpo_seconds', 'approved_rto_seconds', 'recovery_set_id'],
    'recovery',
  );
  for (const key of ['approved_rpo_seconds', 'approved_rto_seconds']) {
    if (!Number.isSafeInteger(recovery[key]) || recovery[key] < 1) {
      throw new Error('Approved RPO and RTO must be positive integer seconds.');
    }
  }
  assertIdentifier(recovery.recovery_set_id, 'recovery_set_id');
}

function validateOwners(owners) {
  assertObject(owners, 'owners');
  const keys = ['rollout', 'rollback', 'restore', 'reviewer'];
  assertExactKeys(owners, keys, 'owners');
  if (keys.some((key) => !ownerPattern.test(owners[key]))) {
    throw new Error('Owner identifiers are invalid.');
  }
  if (owners.reviewer === owners.rollout) {
    throw new Error('Evidence reviewer must be independent from rollout owner.');
  }
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
    url.hostname === 'example.com' ||
    url.hostname.endsWith('.example.com') ||
    (exactOrigin && url.pathname !== '/')
  ) {
    throw new Error(`${name} must be an absolute HTTPS URL.`);
  }
}

function timestamp(value, name) {
  if (typeof value !== 'string') {
    throw new Error(`${name} must be an ISO-8601 timestamp.`);
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error(`${name} must be an ISO-8601 timestamp.`);
  }
  return parsed.getTime();
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
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be an object.`);
  }
}

function assertExactKeys(value, expected, name) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(sortedExpected)) {
    throw new Error(`${name} contains missing or unsupported fields.`);
  }
}

function canonicalHash(value) {
  const digest = createHash('sha256');
  digest.update(JSON.stringify(canonicalize(value)));
  return `sha256:${digest.digest('hex')}`;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

async function main() {
  if (process.argv.length !== 3) {
    process.stderr.write('Usage: node scripts/conformance-evidence.mjs <evidence.json>\n');
    process.exitCode = 2;
    return;
  }
  try {
    const [registry, evidence] = await Promise.all([
      loadRegistry(),
      readFile(process.argv[2], 'utf8').then(JSON.parse),
    ]);
    const manifest = validateEvidence(evidence, registry);
    process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
    if (manifest.gate_status !== 'PASS') process.exitCode = 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown validation error.';
    process.stderr.write(`Conformance evidence is invalid: ${message}\n`);
    process.exitCode = 2;
  }
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  await main();
}
