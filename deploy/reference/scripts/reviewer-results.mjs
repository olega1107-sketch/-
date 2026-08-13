#!/usr/bin/env node

import { chmod, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  requiredReviewTracks,
  validateArchitectureReview,
} from './architecture-review.mjs';

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$/;
const ownerPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/;
const commitPattern = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const evidenceReferencePattern = /^(?:artifact|change|run|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const resultStatuses = new Set(['COMPLETE', 'BLOCKED']);
const blockingSeverities = new Set(['blocking', 'major']);

export function validateReviewerResult(result) {
  assertObject(result, 'reviewer result');
  assertExactKeys(
    result,
    [
      'schema_version',
      'review_id',
      'baseline_commit',
      'reviewer',
      'submitted_at',
      'source_sha256',
      'tracks',
    ],
    'reviewer result',
  );
  if (result.schema_version !== 1) {
    throw new Error('Reviewer result schema version is unsupported.');
  }
  identifier(result.review_id, 'review_id');
  if (!commitPattern.test(result.baseline_commit)) {
    throw new Error('Reviewer result requires a full lowercase baseline commit.');
  }
  owner(result.reviewer, 'reviewer');
  timestamp(result.submitted_at, 'submitted_at');
  if (
    !digestPattern.test(result.source_sha256) ||
    result.source_sha256 === `sha256:${'0'.repeat(64)}`
  ) {
    throw new Error('Reviewer result requires a source file SHA-256 digest.');
  }
  if (!Array.isArray(result.tracks) || result.tracks.length === 0) {
    throw new Error('Reviewer result requires at least one track.');
  }
  const required = new Set(requiredReviewTracks);
  const seen = new Set();
  for (const track of result.tracks) {
    assertObject(track, 'reviewer result track');
    assertExactKeys(
      track,
      ['id', 'status', 'evidence_ref', 'confirmed_finding_ids', 'conclusion'],
      'reviewer result track',
    );
    if (!required.has(track.id) || seen.has(track.id)) {
      throw new Error('Reviewer result contains an unknown or duplicate track.');
    }
    if (!resultStatuses.has(track.status)) {
      throw new Error('Reviewer result track status is unsupported.');
    }
    if (!validEvidenceReference(track.evidence_ref)) {
      throw new Error('Reviewer result track requires an opaque evidence reference.');
    }
    boundedText(track.conclusion, 'reviewer result conclusion', 2000);
    if (
      !Array.isArray(track.confirmed_finding_ids) ||
      track.confirmed_finding_ids.length > 50
    ) {
      throw new Error('Reviewer result finding IDs must be a bounded array.');
    }
    const findingIds = new Set();
    for (const findingId of track.confirmed_finding_ids) {
      identifier(findingId, 'confirmed finding ID');
      if (findingIds.has(findingId)) {
        throw new Error('Reviewer result contains a duplicate finding ID.');
      }
      findingIds.add(findingId);
    }
    seen.add(track.id);
  }
  return result;
}

export function applyReviewerResults(review, results) {
  validateArchitectureReview(review);
  if (!Array.isArray(results) || results.length === 0 || results.length > 6) {
    throw new Error('One to six reviewer results are required.');
  }
  if (review.completed_at !== null || review.final_review.status !== 'NOT_RUN') {
    throw new Error('Reviewer results require an active review before final decision.');
  }

  const startedAt = timestamp(review.started_at, 'review started_at');
  const trackById = new Map(review.tracks.map((track) => [track.id, track]));
  const findingById = new Map(review.findings.map((finding) => [finding.id, finding]));
  const acceptedReviewers = new Set();
  const resultByTrack = new Map();

  for (const result of results) {
    validateReviewerResult(result);
    if (
      result.review_id !== review.review_id ||
      result.baseline_commit !== review.baseline.commit
    ) {
      throw new Error('Reviewer result does not match the exact review baseline.');
    }
    if (timestamp(result.submitted_at, 'submitted_at') < startedAt) {
      throw new Error('Reviewer result predates the review.');
    }
    if (acceptedReviewers.has(result.reviewer)) {
      throw new Error('A reviewer result may be applied only once per operation.');
    }

    const assignedTrackIds = review.tracks
      .filter((track) => track.reviewer === result.reviewer)
      .map((track) => track.id)
      .sort();
    const submittedTrackIds = result.tracks.map((track) => track.id).sort();
    if (
      assignedTrackIds.length === 0 ||
      JSON.stringify(assignedTrackIds) !== JSON.stringify(submittedTrackIds)
    ) {
      throw new Error('Reviewer result must contain every track assigned to that reviewer.');
    }

    for (const resultTrack of result.tracks) {
      const currentTrack = trackById.get(resultTrack.id);
      if (
        currentTrack === undefined ||
        currentTrack.reviewer !== result.reviewer ||
        currentTrack.status !== 'IN_REVIEW'
      ) {
        throw new Error('Reviewer result requires an assigned IN_REVIEW track.');
      }
      for (const findingId of resultTrack.confirmed_finding_ids) {
        const finding = findingById.get(findingId);
        if (
          finding === undefined ||
          finding.track_id !== resultTrack.id ||
          finding.status !== 'OPEN'
        ) {
          throw new Error('Reviewer result references an unknown or inapplicable open finding.');
        }
      }
      if (resultTrack.status === 'COMPLETE') {
        const openBlocker = review.findings.some(
          (finding) =>
            finding.track_id === resultTrack.id &&
            finding.status === 'OPEN' &&
            blockingSeverities.has(finding.severity),
        );
        if (openBlocker) {
          throw new Error('A track with an open blocking or major finding cannot be completed.');
        }
      }
      if (resultByTrack.has(resultTrack.id)) {
        throw new Error('A review track result may be applied only once.');
      }
      resultByTrack.set(resultTrack.id, { result, track: resultTrack });
    }
    acceptedReviewers.add(result.reviewer);
  }

  const updated = {
    ...review,
    tracks: review.tracks.map((track) => {
      const accepted = resultByTrack.get(track.id);
      if (accepted === undefined || accepted.track.status === 'BLOCKED') return track;
      return {
        ...track,
        status: 'COMPLETE',
        completed_at: accepted.result.submitted_at,
        evidence_ref: accepted.track.evidence_ref,
      };
    }),
  };
  const report = validateArchitectureReview(updated);
  return {
    review: updated,
    report,
    accepted_results: results.map((result) => ({
      reviewer: result.reviewer,
      submitted_at: result.submitted_at,
      source_sha256: result.source_sha256,
      tracks: result.tracks.map(({ id, status }) => ({ id, status })),
    })),
  };
}

export async function writeProgressReview({ review, results, outputPath }) {
  if (typeof outputPath !== 'string' || outputPath.length === 0) {
    throw new Error('A new progress review output path is required.');
  }
  const merged = applyReviewerResults(review, results);
  const resolvedOutput = path.resolve(outputPath);
  await writeFile(resolvedOutput, `${JSON.stringify(merged.review, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(resolvedOutput, 0o600);
  return { ...merged, outputPath: resolvedOutput };
}

function validEvidenceReference(value) {
  return typeof value === 'string' && evidenceReferencePattern.test(value);
}

function identifier(value, name) {
  if (
    typeof value !== 'string' ||
    !identifierPattern.test(value) ||
    value.startsWith('replace-')
  ) {
    throw new Error(`${name} must be an opaque identifier.`);
  }
}

function owner(value, name) {
  if (
    typeof value !== 'string' ||
    !ownerPattern.test(value) ||
    value.startsWith('replace-')
  ) {
    throw new Error(`${name} must be an opaque owner identifier.`);
  }
}

function boundedText(value, name, maximumLength) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${name} must be bounded single-line text.`);
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
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${name} contains missing or unsupported fields.`);
  }
}

async function main(argv) {
  if (argv.length < 3) {
    throw new Error(
      'Usage: node scripts/reviewer-results.mjs <review.json> <new-progress-review.json> <result.json> [result.json...]',
    );
  }
  let review;
  let results;
  try {
    review = JSON.parse(await readFile(path.resolve(argv[0]), 'utf8'));
    results = await Promise.all(
      argv.slice(2).map((input) =>
        readFile(path.resolve(input), 'utf8').then(JSON.parse),
      ),
    );
  } catch {
    throw new Error('Reviewer result inputs could not be read.');
  }
  const merged = await writeProgressReview({
    review,
    results,
    outputPath: argv[1],
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        review_id: merged.review.review_id,
        gate_status: merged.report.gate_status,
        accepted_reviewers: merged.accepted_results.length,
        submitted_tracks: merged.accepted_results.reduce(
          (count, result) => count + result.tracks.length,
          0,
        ),
        completed_tracks: merged.report.counts.tracks_complete,
        required_tracks: merged.report.counts.tracks_required,
        output_file: path.basename(merged.outputPath),
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
    const message = error instanceof Error ? error.message : 'Reviewer result intake failed.';
    process.stderr.write(`Reviewer result intake failed: ${message}\n`);
    process.exitCode = 2;
  });
}
