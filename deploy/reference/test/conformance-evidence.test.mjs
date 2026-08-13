import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  loadRegistry,
  validateEvidence,
} from '../scripts/conformance-evidence.mjs';

const registry = await loadRegistry();
const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const cliPath = path.resolve(testDirectory, '../scripts/conformance-evidence.mjs');

test('complete evidence passes with a deterministic manifest hash', () => {
  const evidence = completeEvidence();
  const first = validateEvidence(evidence, registry);
  const second = validateEvidence(structuredClone(evidence), registry);

  assert.equal(registry.registry_version, 3);
  assert.ok(
    registry.checks.some((check) => check.id === 'operations.adoption_decisions'),
  );
  assert.equal(first.gate_status, 'PASS');
  assert.deepEqual(first.counts, {
    pass: registry.checks.length,
    fail: 0,
    not_run: 0,
    required: registry.checks.length,
  });
  assert.match(first.report_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(first.report_sha256, second.report_sha256);

  const reversed = structuredClone(evidence);
  reversed.checks.reverse();
  assert.equal(
    first.report_sha256,
    validateEvidence(reversed, registry).report_sha256,
  );
});

test('FAIL and NOT_RUN both block the gate', () => {
  const evidence = completeEvidence();
  evidence.checks[0] = {
    ...evidence.checks[0],
    status: 'FAIL',
  };
  evidence.checks[1] = {
    id: evidence.checks[1].id,
    status: 'NOT_RUN',
    observed_at: null,
    evidence_refs: [],
  };

  const manifest = validateEvidence(evidence, registry);
  assert.equal(manifest.gate_status, 'BLOCKED');
  assert.equal(manifest.counts.fail, 1);
  assert.equal(manifest.counts.not_run, 1);
});

test('missing, duplicate, and unknown checks are rejected', () => {
  const missing = completeEvidence();
  missing.checks.pop();
  assert.throws(() => validateEvidence(missing, registry), /every required check/);

  const duplicate = completeEvidence();
  duplicate.checks[1] = structuredClone(duplicate.checks[0]);
  assert.throws(() => validateEvidence(duplicate, registry), /unknown or duplicate/);

  const unknown = completeEvidence();
  unknown.checks[0].id = 'unknown.check';
  assert.throws(() => validateEvidence(unknown, registry), /unknown or duplicate/);
});

test('inline URLs and unsupported fields cannot enter evidence references', () => {
  const unsafeReference = completeEvidence();
  unsafeReference.checks[0].evidence_refs = ['https://records.invalid/log'];
  assert.throws(() => validateEvidence(unsafeReference, registry), /opaque identifiers/);

  const unsupportedField = completeEvidence();
  unsupportedField.checks[0].notes = 'raw operator notes are not allowed';
  assert.throws(() => validateEvidence(unsupportedField, registry), /unsupported fields/);
});

test('executed checks require observations and evidence', () => {
  const missingReference = completeEvidence();
  missingReference.checks[0].evidence_refs = [];
  assert.throws(() => validateEvidence(missingReference, registry), /timely evidence/);

  const futureObservation = completeEvidence();
  futureObservation.checks[0].observed_at = '2026-08-10T12:30:01.000Z';
  assert.throws(() => validateEvidence(futureObservation, registry), /timely evidence/);

  const staleObservation = completeEvidence();
  staleObservation.checks[0].observed_at = '2026-08-10T11:59:59.000Z';
  assert.throws(() => validateEvidence(staleObservation, registry), /timely evidence/);
});

test('reviewer must be independent from rollout owner', () => {
  const evidence = completeEvidence();
  evidence.owners.reviewer = evidence.owners.rollout;
  assert.throws(() => validateEvidence(evidence, registry), /independent/);
});

test('adoption PASS cannot be asserted for a blocked embedded decision', () => {
  const evidence = completeEvidence();
  evidence.adoption_decision.approval = {
    status: 'DRAFT',
    decided_at: null,
    evidence_refs: [],
  };
  assert.throws(
    () => validateEvidence(evidence, registry),
    /cannot pass a blocked decision/,
  );

  const blocked = completeEvidence();
  blocked.adoption_decision.approval = {
    status: 'DRAFT',
    decided_at: null,
    evidence_refs: [],
  };
  const adoptionCheck = blocked.checks.find(
    (check) => check.id === 'operations.adoption_decisions',
  );
  adoptionCheck.status = 'NOT_RUN';
  adoptionCheck.observed_at = null;
  adoptionCheck.evidence_refs = [];
  const report = validateEvidence(blocked, registry);
  assert.equal(report.gate_status, 'BLOCKED');
  assert.equal(report.adoption_decision.gate_status, 'BLOCKED');
});

test('adoption PASS requires an artifact reference to its validated report', () => {
  const evidence = completeEvidence();
  const adoptionCheck = evidence.checks.find(
    (check) => check.id === 'operations.adoption_decisions',
  );
  adoptionCheck.evidence_refs = ['change:ADOPTION-2026-001'];
  assert.throws(
    () => validateEvidence(evidence, registry),
    /validated report artifact/,
  );
});

test('embedded adoption must match target environment, recovery and restore owner', () => {
  const environment = completeEvidence();
  environment.adoption_decision.environment = 'different-pilot';
  assert.throws(
    () => validateEvidence(environment, registry),
    /environment differs/,
  );

  const recovery = completeEvidence();
  recovery.recovery.approved_rpo_seconds = 300;
  assert.throws(
    () => validateEvidence(recovery, registry),
    /recovery objectives differ/,
  );

  const restoreOwner = completeEvidence();
  restoreOwner.owners.restore = 'different-restore-owner';
  assert.throws(
    () => validateEvidence(restoreOwner, registry),
    /restore owner differs/,
  );
});

test('pilot adoption must be approved before target execution', () => {
  const evidence = completeEvidence();
  evidence.adoption_decision.approval.decided_at = '2026-08-10T12:00:01.000Z';
  assert.throws(
    () => validateEvidence(evidence, registry),
    /approved before target execution/,
  );
});

test('CLI exits zero only for a complete PASS report', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'dirizhor-evidence-test-'));
  try {
    const reportPath = path.join(directory, 'evidence.json');
    const passing = completeEvidence();
    writeFileSync(reportPath, JSON.stringify(passing), { mode: 0o600 });
    const passResult = spawnSync(process.execPath, [cliPath, reportPath], {
      encoding: 'utf8',
    });
    assert.equal(passResult.status, 0);
    assert.match(passResult.stdout, /"gate_status": "PASS"/);

    passing.checks[0] = {
      id: passing.checks[0].id,
      status: 'NOT_RUN',
      observed_at: null,
      evidence_refs: [],
    };
    writeFileSync(reportPath, JSON.stringify(passing), { mode: 0o600 });
    const blockedResult = spawnSync(process.execPath, [cliPath, reportPath], {
      encoding: 'utf8',
    });
    assert.equal(blockedResult.status, 1);
    assert.match(blockedResult.stdout, /"gate_status": "BLOCKED"/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function completeEvidence() {
  return {
    schema_version: 1,
    registry_version: registry.registry_version,
    execution_id: 'CHG-2026-0001',
    environment: 'pilot-eu-1',
    started_at: '2026-08-10T12:00:00.000Z',
    completed_at: '2026-08-10T12:30:00.000Z',
    artifacts: {
      director_image_digest: digest('1'),
      gateway_image_digest: digest('2'),
      ui_artifact_digest: digest('3'),
      migration_manifest_digest: digest('4'),
    },
    target: {
      public_origin: 'https://director.corp.invalid',
      director_internal_dns: 'director.internal',
      gateway_internal_dns: 'gateway.internal',
      postgresql_provider: 'managed-postgresql',
      postgresql_version: '15.8',
      oidc_issuer: 'https://idp.corp.invalid/tenant',
      oidc_client_id: 'dirizhor-pilot',
    },
    recovery: {
      approved_rpo_seconds: 3_600,
      approved_rto_seconds: 3_600,
      recovery_set_id: 'recovery-set-2026-08-10',
    },
    adoption_decision: approvedAdoptionDecision(),
    owners: {
      rollout: 'platform-owner',
      rollback: 'release-owner',
      restore: 'restore-owner',
      reviewer: 'security-reviewer',
    },
    checks: registry.checks.map((check) => ({
      id: check.id,
      status: 'PASS',
      observed_at: '2026-08-10T12:20:00.000Z',
      evidence_refs: [
        check.id === 'operations.adoption_decisions'
          ? 'artifact:ADOPTION-2026-001/report'
          : `change:CHG-2026-0001/${check.id}`,
      ],
    })),
  };
}

function approvedAdoptionDecision() {
  return {
    schema_version: 1,
    decision_id: 'ADOPTION-2026-001',
    environment: 'pilot-eu-1',
    profile_id: 'dirizhor-pilot-single-replica-recreate-v1',
    architecture_commit: '1'.repeat(40),
    owners: {
      decision: 'technology-owner',
      service: 'service-owner',
      backup: 'backup-owner',
      restore: 'restore-owner',
      incident: 'incident-owner',
      failover: 'failover-owner',
      alerts: 'observability-owner',
      reviewer: 'independent-reviewer',
    },
    availability: {
      slo_target_basis_points: 9_950,
      measurement_window_days: 30,
      maximum_planned_outage_seconds: 1_800,
      maximum_unplanned_outage_seconds: 900,
      planned_maintenance_counts_against_slo: true,
      maintenance_window_ref: 'ticket:MAINTENANCE-WINDOW-001',
    },
    recovery: {
      postgresql_rpo_seconds: 300,
      document_store_rpo_seconds: 3_600,
      full_restore_rto_seconds: 3_600,
      failover_rto_seconds: 900,
      maximum_restore_drill_age_seconds: 2_592_000,
      backup_retention_days: 35,
    },
    alerts: {
      readiness_failure_seconds: 60,
      http_error_rate_basis_points: 100,
      http_error_rate_window_seconds: 300,
      http_latency_p95_ms: 2_000,
      postgresql_wal_archive_lag_seconds: 60,
      document_store_backup_age_seconds: 1_800,
      restore_drill_age_seconds: 2_419_200,
    },
    profile_risks: {
      director_single_replica_accepted: true,
      gateway_single_replica_accepted: true,
      recreate_rollout_outage_accepted: true,
      risk_acceptance_ref: 'ticket:RISK-2026-001',
    },
    approval: {
      status: 'APPROVED',
      decided_at: '2026-08-10T11:00:00.000Z',
      evidence_refs: [
        'change:ADOPTION-2026-001',
        'ticket:RISK-2026-001',
        'ticket:MAINTENANCE-WINDOW-001',
        'alert:DIRIZHOR-PILOT-V1',
        'dashboard:DIRIZHOR-SLO-V1',
      ],
    },
  };
}

function digest(character) {
  return `sha256:${character.repeat(64)}`;
}
