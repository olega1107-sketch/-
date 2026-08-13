import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { requiredReviewTracks } from '../scripts/architecture-review.mjs';
import {
  applyReviewerAssignments,
  validateReviewerAssignments,
  writeAssignedReview,
} from '../scripts/reviewer-assignments.mjs';

test('assignments move every unassigned track into review without approving the gate', () => {
  const result = applyReviewerAssignments(reviewPlan(), assignmentDocument());

  assert.equal(result.report.gate_status, 'BLOCKED');
  assert.equal(result.report.counts.tracks_assigned, 6);
  assert.equal(result.report.counts.tracks_complete, 0);
  assert.ok(result.review.tracks.every((track) => track.status === 'IN_REVIEW'));
  assert.equal(result.review.owners.decision_owner, 'architecture-owner');
  assert.equal(result.review.owners.final_reviewer, 'independent-final-reviewer');
});

test('one reviewer may cover multiple tracks but final reviewer stays independent', () => {
  const assignments = assignmentDocument();
  assignments.tracks.product_domain = 'cross-domain-reviewer';
  assignments.tracks.application_api = 'cross-domain-reviewer';
  assert.doesNotThrow(() => validateReviewerAssignments(assignments));

  assignments.final_reviewer = 'cross-domain-reviewer';
  assert.throws(
    () => validateReviewerAssignments(assignments),
    /must be independent/,
  );
});

test('assignments reject placeholders, missing tracks, extra fields, and reused plans', () => {
  const placeholder = assignmentDocument();
  placeholder.decision_owner = 'replace-owner';
  assert.throws(
    () => validateReviewerAssignments(placeholder),
    /non-placeholder opaque identifier/,
  );

  const missing = assignmentDocument();
  delete missing.tracks.security;
  assert.throws(() => validateReviewerAssignments(missing), /missing or unsupported fields/);

  const extra = assignmentDocument();
  extra.unsupported = true;
  assert.throws(() => validateReviewerAssignments(extra), /missing or unsupported fields/);

  const reused = reviewPlan();
  reused.owners.decision_owner = 'existing-owner';
  assert.throws(
    () => applyReviewerAssignments(reused, assignmentDocument()),
    /unassigned review plan/,
  );
});

test('writer creates a private new review and never overwrites it', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-reviewer-assignments-'));
  const output = path.join(root, 'assigned-review.json');
  try {
    const result = await writeAssignedReview({
      review: reviewPlan(),
      assignments: assignmentDocument(),
      outputPath: output,
    });
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(output, 'utf8')), result.review);
    await assert.rejects(
      writeAssignedReview({
        review: reviewPlan(),
        assignments: assignmentDocument(),
        outputPath: output,
      }),
      /EEXIST/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function assignmentDocument() {
  return {
    schema_version: 1,
    decision_owner: 'architecture-owner',
    final_reviewer: 'independent-final-reviewer',
    tracks: Object.fromEntries(
      requiredReviewTracks.map((id) => [id, `${id}-reviewer`]),
    ),
  };
}

function reviewPlan() {
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
    owners: { decision_owner: null, final_reviewer: null },
    tracks: requiredReviewTracks.map((id) => ({
      id,
      reviewer: null,
      status: 'NOT_STARTED',
      completed_at: null,
      evidence_ref: null,
    })),
    findings: [],
    final_review: { status: 'NOT_RUN', reviewed_at: null, evidence_ref: null },
  };
}
