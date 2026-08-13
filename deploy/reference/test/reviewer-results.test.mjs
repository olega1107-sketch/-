import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { requiredReviewTracks } from '../scripts/architecture-review.mjs';
import {
  applyReviewerResults,
  validateReviewerResult,
  writeProgressReview,
} from '../scripts/reviewer-results.mjs';

test('reviewer results complete clear tracks and retain blocked tracks in review', () => {
  const merged = applyReviewerResults(assignedReview(), [ownerResult(), productResult()]);

  assert.equal(merged.report.gate_status, 'BLOCKED');
  assert.equal(merged.report.counts.tracks_assigned, 6);
  assert.equal(merged.report.counts.tracks_complete, 2);
  assert.equal(merged.accepted_results.length, 2);
  assert.deepEqual(
    merged.review.tracks
      .filter((track) => track.status === 'COMPLETE')
      .map((track) => track.id)
      .sort(),
    ['application_api', 'product_domain'],
  );
  assert.equal(
    merged.review.tracks.find((track) => track.id === 'security').status,
    'IN_REVIEW',
  );
});

test('results must match the exact baseline, reviewer, and complete assignment set', () => {
  const wrongBaseline = productResult();
  wrongBaseline.baseline_commit = 'f'.repeat(40);
  assert.throws(
    () => applyReviewerResults(assignedReview(), [wrongBaseline]),
    /exact review baseline/,
  );

  const partial = productResult();
  partial.tracks.pop();
  assert.throws(
    () => applyReviewerResults(assignedReview(), [partial]),
    /every track assigned/,
  );

  const wrongReviewer = productResult();
  wrongReviewer.reviewer = 'unassigned-reviewer';
  assert.throws(
    () => applyReviewerResults(assignedReview(), [wrongReviewer]),
    /every track assigned/,
  );
});

test('open blocking or major findings prevent a COMPLETE track', () => {
  const result = productResult();
  const security = result.tracks.find((track) => track.id === 'security');
  security.status = 'COMPLETE';
  assert.throws(
    () => applyReviewerResults(assignedReview(), [result]),
    /open blocking or major finding/,
  );
});

test('confirmed findings must be open and belong to the submitted track', () => {
  const wrongTrack = ownerResult();
  wrongTrack.tracks[0].confirmed_finding_ids = ['IPR-SRE-001'];
  assert.throws(
    () => applyReviewerResults(assignedReview(), [wrongTrack]),
    /inapplicable open finding/,
  );

  const unknown = productResult();
  unknown.tracks[2].confirmed_finding_ids = ['IPR-UNKNOWN-001'];
  assert.throws(
    () => applyReviewerResults(assignedReview(), [unknown]),
    /inapplicable open finding/,
  );
});

test('strict result schema rejects placeholders, zero digest, and unsupported fields', () => {
  const placeholder = productResult();
  placeholder.reviewer = 'replace-reviewer';
  assert.throws(() => validateReviewerResult(placeholder), /opaque owner identifier/);

  const zeroDigest = productResult();
  zeroDigest.source_sha256 = `sha256:${'0'.repeat(64)}`;
  assert.throws(() => validateReviewerResult(zeroDigest), /source file SHA-256/);

  const unsupported = productResult();
  unsupported.notes = 'not part of the contract';
  assert.throws(() => validateReviewerResult(unsupported), /unsupported fields/);
});

test('writer creates a private progress review and never overwrites it', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-reviewer-results-'));
  const output = path.join(root, 'progress-review.json');
  try {
    const merged = await writeProgressReview({
      review: assignedReview(),
      results: [ownerResult(), productResult()],
      outputPath: output,
    });
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(output, 'utf8')), merged.review);
    await assert.rejects(
      writeProgressReview({
        review: assignedReview(),
        results: [ownerResult(), productResult()],
        outputPath: output,
      }),
      /EEXIST/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function productResult() {
  return {
    schema_version: 1,
    review_id: 'ARCH-REVIEW-2026-001',
    baseline_commit: 'a'.repeat(40),
    reviewer: 'product-reviewer',
    submitted_at: '2026-08-13T12:20:00.000Z',
    source_sha256: `sha256:${'c'.repeat(64)}`,
    tracks: [
      resultTrack('product_domain', 'COMPLETE', 'artifact:product-review', []),
      resultTrack('application_api', 'COMPLETE', 'artifact:api-review', []),
      resultTrack('security', 'BLOCKED', 'ticket:security-review', ['IPR-SECURITY-001']),
    ],
  };
}

function ownerResult() {
  return {
    schema_version: 1,
    review_id: 'ARCH-REVIEW-2026-001',
    baseline_commit: 'a'.repeat(40),
    reviewer: 'architecture-owner',
    submitted_at: '2026-08-13T12:10:00.000Z',
    source_sha256: `sha256:${'d'.repeat(64)}`,
    tracks: [
      resultTrack('data', 'BLOCKED', 'ticket:data-review', ['IPR-DATA-001']),
      resultTrack('platform_sre', 'BLOCKED', 'ticket:sre-review', ['IPR-SRE-001']),
      resultTrack('engineering', 'BLOCKED', 'artifact:engineering-review', ['IPR-ENGINEERING-001']),
    ],
  };
}

function resultTrack(id, status, evidenceRef, confirmedFindingIds) {
  return {
    id,
    status,
    evidence_ref: evidenceRef,
    confirmed_finding_ids: confirmedFindingIds,
    conclusion: `${id} review conclusion`,
  };
}

function assignedReview() {
  const reviewers = {
    product_domain: 'product-reviewer',
    application_api: 'product-reviewer',
    security: 'product-reviewer',
    data: 'architecture-owner',
    platform_sre: 'architecture-owner',
    engineering: 'architecture-owner',
  };
  return {
    schema_version: 1,
    review_id: 'ARCH-REVIEW-2026-001',
    baseline: {
      commit: 'a'.repeat(40),
      tag: 'architecture-review-v1',
      preflight_report_sha256: `sha256:${'b'.repeat(64)}`,
    },
    started_at: '2026-08-13T10:00:00.000Z',
    completed_at: null,
    owners: {
      decision_owner: 'architecture-owner',
      final_reviewer: 'independent-final-reviewer',
    },
    tracks: requiredReviewTracks.map((id) => ({
      id,
      reviewer: reviewers[id],
      status: 'IN_REVIEW',
      completed_at: null,
      evidence_ref: null,
    })),
    findings: [
      openFinding('IPR-SECURITY-001', 'security', 'blocking'),
      openFinding('IPR-DATA-001', 'data', 'major'),
      openFinding('IPR-SRE-001', 'platform_sre', 'major'),
      openFinding('IPR-ENGINEERING-001', 'engineering', 'major'),
    ],
    final_review: { status: 'NOT_RUN', reviewed_at: null, evidence_ref: null },
  };
}

function openFinding(id, trackId, severity) {
  return {
    id,
    track_id: trackId,
    type: 'operability',
    severity,
    status: 'OPEN',
    location: 'docs/example.md:1',
    consequence: 'Target evidence is not available.',
    resolution: null,
    decision_owner: null,
    evidence_ref: null,
  };
}
