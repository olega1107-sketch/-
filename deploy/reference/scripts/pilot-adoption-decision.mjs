import { createHash } from 'node:crypto';
import { chmod, lstat, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const profileId = 'dirizhor-pilot-single-replica-recreate-v1';
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$/;
const ownerPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/;
const commitPattern = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const evidenceReferencePattern =
  /^(?:alert|artifact|change|dashboard|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const riskReferencePattern = /^(?:change|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const operationalReferencePattern =
  /^(?:artifact|change|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const decisionStatuses = new Set(['DRAFT', 'APPROVED', 'REJECTED']);
const zeroCommits = new Set(['0'.repeat(40), '0'.repeat(64)]);

export function validatePilotAdoptionDecision(document) {
  assertObject(document, 'pilot adoption decision');
  assertExactKeys(
    document,
    [
      'schema_version',
      'decision_id',
      'environment',
      'profile_id',
      'architecture_commit',
      'owners',
      'availability',
      'recovery',
      'alerts',
      'profile_risks',
      'approval',
    ],
    'pilot adoption decision',
  );
  if (document.schema_version !== 1) {
    throw new Error('Pilot adoption decision schema version is unsupported.');
  }
  assertIdentifier(document.decision_id, 'decision_id');
  assertIdentifier(document.environment, 'environment');
  if (document.profile_id !== profileId) {
    throw new Error('Pilot adoption decision targets an unsupported deployment profile.');
  }
  if (
    typeof document.architecture_commit !== 'string' ||
    !commitPattern.test(document.architecture_commit) ||
    zeroCommits.has(document.architecture_commit)
  ) {
    throw new Error('Pilot adoption decision requires a full non-zero Git commit.');
  }

  const owners = validateOwners(document.owners);
  const availability = validateAvailability(document.availability);
  const recovery = validateRecovery(document.recovery);
  const alerts = validateAlerts(
    document.alerts,
    availability,
    recovery,
  );
  const profileRisks = validateProfileRisks(document.profile_risks);
  const approval = validateApproval(document.approval);

  const blockingReasons = [];
  if (approval.status !== 'APPROVED') {
    blockingReasons.push('adoption_not_approved');
  }
  for (const [key, reason] of [
    ['director_single_replica_accepted', 'director_single_replica_risk_not_accepted'],
    ['gateway_single_replica_accepted', 'gateway_single_replica_risk_not_accepted'],
    ['recreate_rollout_outage_accepted', 'recreate_outage_risk_not_accepted'],
  ]) {
    if (!profileRisks[key]) blockingReasons.push(reason);
  }
  if (profileRisks.risk_acceptance_ref === null) {
    blockingReasons.push('profile_risk_evidence_missing');
  } else if (
    approval.status === 'APPROVED' &&
    !approval.evidence_refs.includes(profileRisks.risk_acceptance_ref)
  ) {
    throw new Error('Approved adoption evidence must include the profile risk reference.');
  }
  if (
    approval.status === 'APPROVED' &&
    !approval.evidence_refs.includes(availability.maintenance_window_ref)
  ) {
    throw new Error('Approved adoption evidence must include the maintenance window.');
  }

  return {
    schema_version: 1,
    decision_id: document.decision_id,
    environment: document.environment,
    profile_id: document.profile_id,
    architecture_commit: document.architecture_commit,
    gate_status: blockingReasons.length === 0 ? 'PASS' : 'BLOCKED',
    blocking_reasons: blockingReasons.sort(),
    owners,
    availability: {
      ...availability,
      error_budget_seconds: availabilityErrorBudgetSeconds(availability),
    },
    recovery,
    alerts,
    approval: {
      status: approval.status,
      decided_at: approval.decided_at,
      evidence_reference_count: approval.evidence_refs.length,
    },
    report_sha256: canonicalHash(document),
  };
}

function validateOwners(owners) {
  assertObject(owners, 'adoption owners');
  const keys = [
    'decision',
    'service',
    'backup',
    'restore',
    'incident',
    'failover',
    'alerts',
    'reviewer',
  ];
  assertExactKeys(owners, keys, 'adoption owners');
  for (const key of keys) assertOwner(owners[key], key);
  if (
    keys
      .filter((key) => key !== 'reviewer')
      .some((key) => owners[key] === owners.reviewer)
  ) {
    throw new Error('Adoption reviewer must be independent from operational owners.');
  }
  return { ...owners };
}

function validateAvailability(availability) {
  assertObject(availability, 'availability decision');
  assertExactKeys(
    availability,
    [
      'slo_target_basis_points',
      'measurement_window_days',
      'maximum_planned_outage_seconds',
      'maximum_unplanned_outage_seconds',
      'planned_maintenance_counts_against_slo',
      'maintenance_window_ref',
    ],
    'availability decision',
  );
  integerInRange(
    availability.slo_target_basis_points,
    1,
    9_999,
    'SLO target basis points',
  );
  integerInRange(
    availability.measurement_window_days,
    1,
    366,
    'SLO measurement window days',
  );
  const windowSeconds = availability.measurement_window_days * 86_400;
  integerInRange(
    availability.maximum_planned_outage_seconds,
    1,
    windowSeconds,
    'maximum planned outage',
  );
  integerInRange(
    availability.maximum_unplanned_outage_seconds,
    1,
    windowSeconds,
    'maximum unplanned outage',
  );
  if (typeof availability.planned_maintenance_counts_against_slo !== 'boolean') {
    throw new Error('Planned maintenance SLO treatment must be explicit.');
  }
  if (
    typeof availability.maintenance_window_ref !== 'string' ||
    !operationalReferencePattern.test(availability.maintenance_window_ref)
  ) {
    throw new Error('Maintenance window requires an opaque artifact, change or ticket reference.');
  }
  const errorBudgetSeconds = availabilityErrorBudgetSeconds(availability);
  if (availability.maximum_unplanned_outage_seconds > errorBudgetSeconds) {
    throw new Error('Maximum unplanned outage exceeds the SLO error budget.');
  }
  if (
    availability.planned_maintenance_counts_against_slo &&
    availability.maximum_planned_outage_seconds > errorBudgetSeconds
  ) {
    throw new Error('Maximum planned outage exceeds the counted SLO error budget.');
  }
  return { ...availability };
}

function validateRecovery(recovery) {
  assertObject(recovery, 'recovery decision');
  const secondKeys = [
    'postgresql_rpo_seconds',
    'document_store_rpo_seconds',
    'full_restore_rto_seconds',
    'failover_rto_seconds',
    'maximum_restore_drill_age_seconds',
  ];
  assertExactKeys(
    recovery,
    [...secondKeys, 'backup_retention_days'],
    'recovery decision',
  );
  for (const key of secondKeys) {
    integerInRange(recovery[key], 1, 31_622_400, key);
  }
  if (recovery.failover_rto_seconds > recovery.full_restore_rto_seconds) {
    throw new Error('Failover RTO cannot exceed the full restore RTO.');
  }
  integerInRange(
    recovery.backup_retention_days,
    1,
    3_650,
    'backup retention days',
  );
  return { ...recovery };
}

function validateAlerts(alerts, availability, recovery) {
  assertObject(alerts, 'alert decision');
  const keys = [
    'readiness_failure_seconds',
    'http_error_rate_basis_points',
    'http_error_rate_window_seconds',
    'http_latency_p95_ms',
    'postgresql_wal_archive_lag_seconds',
    'document_store_backup_age_seconds',
    'restore_drill_age_seconds',
  ];
  assertExactKeys(alerts, keys, 'alert decision');
  integerInRange(
    alerts.readiness_failure_seconds,
    1,
    availability.maximum_unplanned_outage_seconds,
    'readiness alert threshold',
  );
  integerInRange(
    alerts.http_error_rate_basis_points,
    1,
    10_000,
    'HTTP error-rate threshold',
  );
  integerInRange(
    alerts.http_error_rate_window_seconds,
    1,
    availability.maximum_unplanned_outage_seconds,
    'HTTP error-rate window',
  );
  integerInRange(
    alerts.http_latency_p95_ms,
    1,
    3_600_000,
    'HTTP p95 latency threshold',
  );
  integerInRange(
    alerts.postgresql_wal_archive_lag_seconds,
    1,
    recovery.postgresql_rpo_seconds,
    'PostgreSQL WAL archive lag threshold',
  );
  integerInRange(
    alerts.document_store_backup_age_seconds,
    1,
    recovery.document_store_rpo_seconds,
    'Document Store backup age threshold',
  );
  integerInRange(
    alerts.restore_drill_age_seconds,
    1,
    recovery.maximum_restore_drill_age_seconds,
    'restore drill age threshold',
  );
  return { ...alerts };
}

function validateProfileRisks(risks) {
  assertObject(risks, 'profile risks');
  const booleanKeys = [
    'director_single_replica_accepted',
    'gateway_single_replica_accepted',
    'recreate_rollout_outage_accepted',
  ];
  assertExactKeys(
    risks,
    [...booleanKeys, 'risk_acceptance_ref'],
    'profile risks',
  );
  for (const key of booleanKeys) {
    if (typeof risks[key] !== 'boolean') {
      throw new Error('Profile risk acceptance values must be boolean.');
    }
  }
  if (
    risks.risk_acceptance_ref !== null &&
    (typeof risks.risk_acceptance_ref !== 'string' ||
      !riskReferencePattern.test(risks.risk_acceptance_ref))
  ) {
    throw new Error('Profile risk acceptance requires an opaque change or ticket reference.');
  }
  return { ...risks };
}

function validateApproval(approval) {
  assertObject(approval, 'adoption approval');
  assertExactKeys(
    approval,
    ['status', 'decided_at', 'evidence_refs'],
    'adoption approval',
  );
  if (!decisionStatuses.has(approval.status)) {
    throw new Error('Adoption approval status is unsupported.');
  }
  if (!Array.isArray(approval.evidence_refs) || approval.evidence_refs.length > 8) {
    throw new Error('Adoption approval evidence references are invalid.');
  }
  const unique = new Set(approval.evidence_refs);
  if (
    unique.size !== approval.evidence_refs.length ||
    approval.evidence_refs.some(
      (reference) =>
        typeof reference !== 'string' ||
        !evidenceReferencePattern.test(reference),
    )
  ) {
    throw new Error('Adoption approval evidence must use unique opaque references.');
  }
  if (approval.status === 'DRAFT') {
    if (approval.decided_at !== null || approval.evidence_refs.length !== 0) {
      throw new Error('Draft adoption cannot claim decision evidence.');
    }
  } else {
    timestamp(approval.decided_at, 'adoption decided_at');
    const hasDecisionEvidence = approval.evidence_refs.some((reference) =>
      /^(?:change|ticket):/.test(reference),
    );
    if (!hasDecisionEvidence) {
      throw new Error('Decided adoption requires opaque approval evidence.');
    }
    if (
      approval.status === 'APPROVED' &&
      (approval.evidence_refs.length < 3 ||
        !approval.evidence_refs.some((reference) => reference.startsWith('alert:')) ||
        !approval.evidence_refs.some((reference) => reference.startsWith('dashboard:')))
    ) {
      throw new Error(
        'Decided adoption requires approval, alert-policy and dashboard evidence.',
      );
    }
  }
  return {
    status: approval.status,
    decided_at: approval.decided_at,
    evidence_refs: [...approval.evidence_refs],
  };
}

function availabilityErrorBudgetSeconds(availability) {
  const windowSeconds = availability.measurement_window_days * 86_400;
  return Math.floor(
    (windowSeconds * (10_000 - availability.slo_target_basis_points)) / 10_000,
  );
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

function assertOwner(value, name) {
  if (
    typeof value !== 'string' ||
    !ownerPattern.test(value) ||
    value.startsWith('replace-')
  ) {
    throw new Error(`${name} must be an opaque owner identifier.`);
  }
}

function integerInRange(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} is outside the supported range.`);
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
  if (process.argv.length < 3 || process.argv.length > 4) {
    process.stderr.write(
      'Usage: node scripts/pilot-adoption-decision.mjs <decision.json> [new-report.json]\n',
    );
    process.exitCode = 2;
    return;
  }
  try {
    const document = JSON.parse(await readFile(process.argv[2], 'utf8'));
    const report = validatePilotAdoptionDecision(document);
    if (process.argv[3] !== undefined) {
      await writePrivateReport(process.argv[3], report);
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (report.gate_status !== 'PASS') process.exitCode = 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown decision error.';
    process.stderr.write(`Pilot adoption decision is invalid: ${message}\n`);
    process.exitCode = 2;
  }
}

async function writePrivateReport(filePath, report) {
  const output = path.resolve(filePath);
  if (insidePath(defaultWorkspaceRoot, output)) {
    throw new Error('Pilot adoption report must be stored outside the source workspace.');
  }
  const parent = await lstat(path.dirname(output)).catch(() => undefined);
  if (
    parent === undefined ||
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    (parent.mode & 0o077) !== 0
  ) {
    throw new Error('Pilot adoption report requires a protected parent directory.');
  }
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(output, 0o600);
}

function insidePath(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative.length === 0 || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  await main();
}
