#!/usr/bin/env node

import { chmod, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  requiredReviewTracks,
  validateArchitectureReview,
} from './architecture-review.mjs';

const ownerPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/;

export function applyReviewerAssignments(review, assignments) {
  validateArchitectureReview(review);
  validateReviewerAssignments(assignments);
  if (
    review.completed_at !== null ||
    review.final_review.status !== 'NOT_RUN' ||
    review.owners.decision_owner !== null ||
    review.owners.final_reviewer !== null ||
    review.tracks.some(
      (track) =>
        track.reviewer !== null ||
        track.status !== 'NOT_STARTED' ||
        track.completed_at !== null ||
        track.evidence_ref !== null,
    )
  ) {
    throw new Error('Reviewer assignments require an unassigned review plan.');
  }

  const updated = {
    ...review,
    owners: {
      decision_owner: assignments.decision_owner,
      final_reviewer: assignments.final_reviewer,
    },
    tracks: review.tracks.map((track) => ({
      ...track,
      reviewer: assignments.tracks[track.id],
      status: 'IN_REVIEW',
    })),
  };
  const report = validateArchitectureReview(updated);
  if (report.counts.tracks_assigned !== requiredReviewTracks.length) {
    throw new Error('Reviewer assignments did not assign every required track.');
  }
  return { review: updated, report };
}

export function validateReviewerAssignments(assignments) {
  assertObject(assignments, 'reviewer assignments');
  assertExactKeys(
    assignments,
    ['schema_version', 'decision_owner', 'final_reviewer', 'tracks'],
    'reviewer assignments',
  );
  if (assignments.schema_version !== 1) {
    throw new Error('Reviewer assignments schema version is unsupported.');
  }
  owner(assignments.decision_owner, 'decision_owner');
  owner(assignments.final_reviewer, 'final_reviewer');
  assertObject(assignments.tracks, 'reviewer assignment tracks');
  assertExactKeys(assignments.tracks, requiredReviewTracks, 'reviewer assignment tracks');
  for (const id of requiredReviewTracks) owner(assignments.tracks[id], `${id} reviewer`);

  if (
    assignments.final_reviewer === assignments.decision_owner ||
    Object.values(assignments.tracks).includes(assignments.final_reviewer)
  ) {
    throw new Error('Final reviewer must be independent from all assigned review owners.');
  }
  return assignments;
}

export async function writeAssignedReview({ review, assignments, outputPath }) {
  if (typeof outputPath !== 'string' || outputPath.length === 0) {
    throw new Error('A new assigned review output path is required.');
  }
  const { review: updated, report } = applyReviewerAssignments(review, assignments);
  const resolvedOutput = path.resolve(outputPath);
  await writeFile(resolvedOutput, `${JSON.stringify(updated, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(resolvedOutput, 0o600);
  return { review: updated, report, outputPath: resolvedOutput };
}

function owner(value, name) {
  if (
    typeof value !== 'string' ||
    !ownerPattern.test(value) ||
    value.startsWith('replace-')
  ) {
    throw new Error(`${name} must be a non-placeholder opaque identifier.`);
  }
}

function assertObject(value, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be an object.`);
  }
}

function assertExactKeys(value, expected, name) {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${name} contains missing or unsupported fields.`);
  }
}

async function main(argv) {
  if (argv.length !== 3) {
    throw new Error(
      'Usage: node scripts/reviewer-assignments.mjs <review.json> <assignments.json> <new-assigned-review.json>',
    );
  }
  let review;
  let assignments;
  try {
    [review, assignments] = await Promise.all([
      readFile(path.resolve(argv[0]), 'utf8').then(JSON.parse),
      readFile(path.resolve(argv[1]), 'utf8').then(JSON.parse),
    ]);
  } catch {
    throw new Error('Reviewer assignment inputs could not be read.');
  }
  const result = await writeAssignedReview({
    review,
    assignments,
    outputPath: argv[2],
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        review_id: result.review.review_id,
        gate_status: result.report.gate_status,
        assigned_tracks: result.report.counts.tracks_assigned,
        required_tracks: result.report.counts.tracks_required,
        output_file: path.basename(result.outputPath),
      },
      null,
      2,
    )}\n`,
  );
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : 'Reviewer assignment failed.';
    process.stderr.write(`Reviewer assignment failed: ${message}\n`);
    process.exitCode = 2;
  });
}
