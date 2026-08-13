import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { validatePilotAdoptionDecision } from '../scripts/pilot-adoption-decision.mjs';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const cliPath = path.resolve(
  testDirectory,
  '../scripts/pilot-adoption-decision.mjs',
);

test('approved adoption passes with a deterministic error budget and report hash', () => {
  const decision = approvedDecision();
  const first = validatePilotAdoptionDecision(decision);
  const second = validatePilotAdoptionDecision(structuredClone(decision));

  assert.equal(first.gate_status, 'PASS');
  assert.deepEqual(first.blocking_reasons, []);
  assert.equal(first.availability.error_budget_seconds, 12_960);
  assert.equal(first.approval.evidence_reference_count, 5);
  assert.match(first.report_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(first.report_sha256, second.report_sha256);
});

test('draft and rejected decisions remain explicitly BLOCKED', () => {
  const draft = approvedDecision();
  draft.approval = { status: 'DRAFT', decided_at: null, evidence_refs: [] };
  draft.profile_risks = {
    director_single_replica_accepted: false,
    gateway_single_replica_accepted: false,
    recreate_rollout_outage_accepted: false,
    risk_acceptance_ref: null,
  };
  const draftReport = validatePilotAdoptionDecision(draft);
  assert.equal(draftReport.gate_status, 'BLOCKED');
  assert.deepEqual(draftReport.blocking_reasons, [
    'adoption_not_approved',
    'director_single_replica_risk_not_accepted',
    'gateway_single_replica_risk_not_accepted',
    'profile_risk_evidence_missing',
    'recreate_outage_risk_not_accepted',
  ]);

  const rejected = approvedDecision();
  rejected.approval = {
    status: 'REJECTED',
    decided_at: '2026-08-13T08:00:00.000Z',
    evidence_refs: ['ticket:ADOPTION-REJECTED'],
  };
  const rejectedReport = validatePilotAdoptionDecision(rejected);
  assert.equal(rejectedReport.gate_status, 'BLOCKED');
  assert.deepEqual(rejectedReport.blocking_reasons, ['adoption_not_approved']);
});

test('availability outage limits cannot exceed the declared SLO budget', () => {
  const unplanned = approvedDecision();
  unplanned.availability.maximum_unplanned_outage_seconds = 12_961;
  assert.throws(
    () => validatePilotAdoptionDecision(unplanned),
    /unplanned outage exceeds the SLO error budget/,
  );

  const planned = approvedDecision();
  planned.availability.maximum_planned_outage_seconds = 12_961;
  assert.throws(
    () => validatePilotAdoptionDecision(planned),
    /planned outage exceeds the counted SLO error budget/,
  );

  planned.availability.planned_maintenance_counts_against_slo = false;
  assert.equal(validatePilotAdoptionDecision(planned).gate_status, 'PASS');
});

test('alert thresholds must fire within outage and recovery objectives', () => {
  const readiness = approvedDecision();
  readiness.alerts.readiness_failure_seconds = 901;
  assert.throws(
    () => validatePilotAdoptionDecision(readiness),
    /readiness alert threshold.*supported range/,
  );

  const walLag = approvedDecision();
  walLag.alerts.postgresql_wal_archive_lag_seconds = 301;
  assert.throws(
    () => validatePilotAdoptionDecision(walLag),
    /WAL archive lag threshold.*supported range/,
  );

  const restoreDrill = approvedDecision();
  restoreDrill.alerts.restore_drill_age_seconds = 2_592_001;
  assert.throws(
    () => validatePilotAdoptionDecision(restoreDrill),
    /restore drill age threshold.*supported range/,
  );
});

test('failover objective cannot be slower than a full restore', () => {
  const decision = approvedDecision();
  decision.recovery.failover_rto_seconds = 3_601;
  assert.throws(
    () => validatePilotAdoptionDecision(decision),
    /Failover RTO cannot exceed the full restore RTO/,
  );
});

test('reviewer identity and evidence references are fail-closed', () => {
  const reviewer = approvedDecision();
  reviewer.owners.reviewer = reviewer.owners.service;
  assert.throws(
    () => validatePilotAdoptionDecision(reviewer),
    /reviewer must be independent/,
  );

  const inlineUrl = approvedDecision();
  inlineUrl.approval.evidence_refs[0] = 'https://records.invalid/approval';
  assert.throws(
    () => validatePilotAdoptionDecision(inlineUrl),
    /unique opaque references/,
  );

  const unsupported = approvedDecision();
  unsupported.alerts.raw_notes = 'call someone';
  assert.throws(
    () => validatePilotAdoptionDecision(unsupported),
    /missing or unsupported fields/,
  );
});

test('APPROVED requires decision, alert, dashboard, risk and maintenance evidence', () => {
  const missingDashboard = approvedDecision();
  missingDashboard.approval.evidence_refs = missingDashboard.approval.evidence_refs
    .filter((reference) => !reference.startsWith('dashboard:'));
  assert.throws(
    () => validatePilotAdoptionDecision(missingDashboard),
    /alert-policy and dashboard evidence/,
  );

  const missingRisk = approvedDecision();
  missingRisk.approval.evidence_refs = missingRisk.approval.evidence_refs
    .filter((reference) => reference !== missingRisk.profile_risks.risk_acceptance_ref);
  assert.throws(
    () => validatePilotAdoptionDecision(missingRisk),
    /must include the profile risk reference/,
  );

  const missingWindow = approvedDecision();
  missingWindow.approval.evidence_refs = missingWindow.approval.evidence_refs
    .filter(
      (reference) =>
        reference !== missingWindow.availability.maintenance_window_ref,
    );
  assert.throws(
    () => validatePilotAdoptionDecision(missingWindow),
    /must include the maintenance window/,
  );
});

test('CLI distinguishes PASS, BLOCKED and invalid decisions', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'dirizhor-adoption-test-'));
  try {
    const decisionPath = path.join(directory, 'decision.json');
    const reportPath = path.join(directory, 'report.json');
    const decision = approvedDecision();
    writeFileSync(decisionPath, JSON.stringify(decision), { mode: 0o600 });
    const passing = spawnSync(process.execPath, [cliPath, decisionPath, reportPath], {
      encoding: 'utf8',
    });
    assert.equal(passing.status, 0);
    assert.match(passing.stdout, /"gate_status": "PASS"/);
    assert.equal(statSync(reportPath).mode & 0o777, 0o600);

    const reused = spawnSync(process.execPath, [cliPath, decisionPath, reportPath], {
      encoding: 'utf8',
    });
    assert.equal(reused.status, 2);
    assert.match(reused.stderr, /EEXIST/);

    decision.approval = { status: 'DRAFT', decided_at: null, evidence_refs: [] };
    writeFileSync(decisionPath, JSON.stringify(decision), { mode: 0o600 });
    const blocked = spawnSync(process.execPath, [cliPath, decisionPath], {
      encoding: 'utf8',
    });
    assert.equal(blocked.status, 1);
    assert.match(blocked.stdout, /"gate_status": "BLOCKED"/);

    decision.availability.slo_target_basis_points = 10_000;
    writeFileSync(decisionPath, JSON.stringify(decision), { mode: 0o600 });
    const invalid = spawnSync(process.execPath, [cliPath, decisionPath], {
      encoding: 'utf8',
    });
    assert.equal(invalid.status, 2);
    assert.match(invalid.stderr, /outside the supported range/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('report writer requires a new external file in a protected directory', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'dirizhor-adoption-output-'));
  try {
    const decisionPath = path.join(directory, 'decision.json');
    writeFileSync(decisionPath, JSON.stringify(approvedDecision()), { mode: 0o600 });
    const publicDirectory = path.join(directory, 'public');
    mkdirSync(publicDirectory, { mode: 0o755 });
    chmodSync(publicDirectory, 0o755);
    const publicReport = path.join(publicDirectory, 'report.json');
    const publicResult = spawnSync(
      process.execPath,
      [cliPath, decisionPath, publicReport],
      { encoding: 'utf8' },
    );
    assert.equal(publicResult.status, 2);
    assert.match(publicResult.stderr, /protected parent directory/);

    const workspaceReport = path.join(testDirectory, 'adoption-report-unsafe.json');
    const workspaceResult = spawnSync(
      process.execPath,
      [cliPath, decisionPath, workspaceReport],
      { encoding: 'utf8' },
    );
    assert.equal(workspaceResult.status, 2);
    assert.match(workspaceResult.stderr, /outside the source workspace/);
    assert.equal(existsSync(workspaceReport), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function approvedDecision() {
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
      decided_at: '2026-08-13T08:00:00.000Z',
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
