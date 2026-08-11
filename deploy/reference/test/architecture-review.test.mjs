import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  requiredReviewTracks,
  validateArchitectureReview,
} from '../scripts/architecture-review.mjs';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const cliPath = path.resolve(testDirectory, '../scripts/architecture-review.mjs');

test('complete architecture review passes with a deterministic hash', () => {
  const review = completeReview();
  const first = validateArchitectureReview(review);
  const second = validateArchitectureReview(structuredClone(review));

  assert.equal(first.gate_status, 'PASS');
  assert.equal(first.counts.tracks_complete, requiredReviewTracks.length);
  assert.equal(first.counts.open_blocking, 0);
  assert.match(first.report_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(first.report_sha256, second.report_sha256);

  review.tracks.reverse();
  review.findings.reverse();
  assert.equal(
    first.report_sha256,
    validateArchitectureReview(review).report_sha256,
  );
});

test('incomplete tracks and open blocking or major findings block the gate', () => {
  const review = completeReview();
  review.completed_at = null;
  review.tracks[0] = {
    ...review.tracks[0],
    status: 'IN_REVIEW',
    completed_at: null,
    evidence_ref: null,
  };
  review.findings = [openFinding('ARCH-2', 'blocking'), openFinding('ARCH-3', 'major')];
  review.final_review = { status: 'NOT_RUN', reviewed_at: null, evidence_ref: null };

  const report = validateArchitectureReview(review);
  assert.equal(report.gate_status, 'BLOCKED');
  assert.deepEqual(report.blocking_reasons, [
    'blocking_findings_open',
    'final_review_not_approved',
    'major_findings_open',
    'review_not_completed',
    'tracks_incomplete',
  ]);
});

test('unassigned review plan is valid and reports explicit blockers', () => {
  const review = completeReview();
  review.completed_at = null;
  review.owners = { decision_owner: null, final_reviewer: null };
  review.tracks = review.tracks.map((track) => ({
    ...track,
    reviewer: null,
    status: 'NOT_STARTED',
    completed_at: null,
    evidence_ref: null,
  }));
  review.findings = [];
  review.final_review = { status: 'NOT_RUN', reviewed_at: null, evidence_ref: null };

  const report = validateArchitectureReview(review);
  assert.equal(report.gate_status, 'BLOCKED');
  assert.equal(report.counts.tracks_assigned, 0);
  assert.equal(report.counts.tracks_complete, 0);
  assert.deepEqual(report.blocking_reasons, [
    'final_review_not_approved',
    'owners_unassigned',
    'review_not_completed',
    'tracks_incomplete',
    'tracks_unassigned',
  ]);
});

test('open minor findings are reported without blocking an approved review', () => {
  const review = completeReview();
  review.findings = [openFinding('ARCH-2', 'minor')];

  const report = validateArchitectureReview(review);
  assert.equal(report.gate_status, 'PASS');
  assert.equal(report.counts.open_minor, 1);
});

test('resolved and accepted findings require the declared decision owner', () => {
  const missingEvidence = completeReview();
  missingEvidence.findings[0].evidence_ref = null;
  assert.throws(
    () => validateArchitectureReview(missingEvidence),
    /decision owner and evidence/,
  );

  const wrongOwner = completeReview();
  wrongOwner.findings[0].status = 'ACCEPTED_RISK';
  wrongOwner.findings[0].decision_owner = 'different-owner';
  assert.throws(
    () => validateArchitectureReview(wrongOwner),
    /decision owner and evidence/,
  );
});

test('missing, duplicate, and unknown review tracks are rejected', () => {
  const missing = completeReview();
  missing.tracks.pop();
  assert.throws(() => validateArchitectureReview(missing), /every required track/);

  const duplicate = completeReview();
  duplicate.tracks[1].id = duplicate.tracks[0].id;
  assert.throws(() => validateArchitectureReview(duplicate), /unknown or duplicate/);

  const unknown = completeReview();
  unknown.tracks[0].id = 'finance';
  assert.throws(() => validateArchitectureReview(unknown), /unknown or duplicate/);
});

test('final reviewer must be independent from all review participants', () => {
  const decisionOwner = completeReview();
  decisionOwner.owners.final_reviewer = decisionOwner.owners.decision_owner;
  assert.throws(() => validateArchitectureReview(decisionOwner), /independent/);

  const trackReviewer = completeReview();
  trackReviewer.owners.final_reviewer = trackReviewer.tracks[0].reviewer;
  assert.throws(() => validateArchitectureReview(trackReviewer), /independent/);
});

test('active and completed tracks require an assigned reviewer', () => {
  const active = completeReview();
  active.completed_at = null;
  active.tracks[0] = {
    ...active.tracks[0],
    reviewer: null,
    status: 'IN_REVIEW',
    completed_at: null,
    evidence_ref: null,
  };
  active.final_review = { status: 'NOT_RUN', reviewed_at: null, evidence_ref: null };
  assert.throws(() => validateArchitectureReview(active), /assigned reviewer/);

  const complete = completeReview();
  complete.tracks[0].reviewer = null;
  assert.throws(() => validateArchitectureReview(complete), /timely opaque evidence/);
});

test('unsupported fields and invalid temporal evidence are rejected', () => {
  const unsupported = completeReview();
  unsupported.notes = 'not part of the evidence contract';
  assert.throws(() => validateArchitectureReview(unsupported), /unsupported fields/);

  const staleTrack = completeReview();
  staleTrack.tracks[0].completed_at = '2026-08-10T11:59:59.000Z';
  assert.throws(() => validateArchitectureReview(staleTrack), /timely opaque evidence/);

  const placeholderDigest = completeReview();
  placeholderDigest.baseline.preflight_report_sha256 = `sha256:${'0'.repeat(64)}`;
  assert.throws(
    () => validateArchitectureReview(placeholderDigest),
    /requires a SHA-256 digest/,
  );

  const unsafeTag = completeReview();
  unsafeTag.baseline.tag = 'architecture..review';
  assert.throws(() => validateArchitectureReview(unsafeTag), /tag is invalid/);
});

test('CLI verifies the annotated tag and fails closed on a commit mismatch', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dirizhor-architecture-review-'));
  try {
    execFileSync('git', ['init', '--quiet'], { cwd: root });
    writeFileSync(path.join(root, 'README.md'), 'review baseline\n');
    execFileSync('git', ['add', '.'], { cwd: root });
    execFileSync(
      'git',
      [
        '-c',
        'user.name=Review Test',
        '-c',
        'user.email=review@example.test',
        'commit',
        '--quiet',
        '-m',
        'baseline',
      ],
      { cwd: root },
    );
    execFileSync(
      'git',
      [
        '-c',
        'user.name=Review Test',
        '-c',
        'user.email=review@example.test',
        'tag',
        '-a',
        'architecture-review-test',
        '-m',
        'baseline',
      ],
      { cwd: root },
    );
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
    }).trim();
    const reportPath = path.join(root, 'review.json');
    const review = completeReview(commit, 'architecture-review-test');
    writeFileSync(reportPath, JSON.stringify(review), { mode: 0o600 });

    const passing = spawnSync(process.execPath, [cliPath, reportPath], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(passing.status, 0);
    assert.match(passing.stdout, /"baseline_tag_verified": true/);

    review.baseline.commit = 'f'.repeat(40);
    writeFileSync(reportPath, JSON.stringify(review), { mode: 0o600 });
    const mismatch = spawnSync(process.execPath, [cliPath, reportPath], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(mismatch.status, 2);
    assert.match(mismatch.stderr, /does not resolve to the declared commit/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function completeReview(
  commit = 'a'.repeat(40),
  tag = 'architecture-review-v1',
) {
  return {
    schema_version: 1,
    review_id: 'ARCH-2026-0001',
    baseline: {
      commit,
      tag,
      preflight_report_sha256: `sha256:${'b'.repeat(64)}`,
    },
    started_at: '2026-08-10T12:00:00.000Z',
    completed_at: '2026-08-10T12:30:00.000Z',
    owners: {
      decision_owner: 'architecture-owner',
      final_reviewer: 'independent-reviewer',
    },
    tracks: requiredReviewTracks.map((id) => ({
      id,
      reviewer: `${id}-reviewer`,
      status: 'COMPLETE',
      completed_at: '2026-08-10T12:20:00.000Z',
      evidence_ref: `ticket:ARCH-2026-0001/${id}`,
    })),
    findings: [
      {
        id: 'ARCH-1',
        track_id: 'security',
        type: 'security_risk',
        severity: 'major',
        status: 'RESOLVED',
        location: 'docs/dirizhor/auth-rbac-v1.md:100',
        consequence: 'Authorization boundary would be ambiguous.',
        resolution: 'The boundary and denial behavior were made explicit.',
        decision_owner: 'architecture-owner',
        evidence_ref: 'ticket:ARCH-1',
      },
    ],
    final_review: {
      status: 'APPROVED',
      reviewed_at: '2026-08-10T12:25:00.000Z',
      evidence_ref: 'ticket:ARCH-2026-0001/final',
    },
  };
}

function openFinding(id, severity) {
  return {
    id,
    track_id: 'security',
    type: 'security_risk',
    severity,
    status: 'OPEN',
    location: 'docs/dirizhor/auth-rbac-v1.md:100',
    consequence: 'Authorization boundary remains ambiguous.',
    resolution: null,
    decision_owner: null,
    evidence_ref: null,
  };
}
