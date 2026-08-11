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
      approved_rpo_seconds: 300,
      approved_rto_seconds: 1800,
      recovery_set_id: 'recovery-set-2026-08-10',
    },
    owners: {
      rollout: 'platform-owner',
      rollback: 'release-owner',
      restore: 'database-owner',
      reviewer: 'security-reviewer',
    },
    checks: registry.checks.map((check) => ({
      id: check.id,
      status: 'PASS',
      observed_at: '2026-08-10T12:20:00.000Z',
      evidence_refs: [`change:CHG-2026-0001/${check.id}`],
    })),
  };
}

function digest(character) {
  return `sha256:${character.repeat(64)}`;
}
