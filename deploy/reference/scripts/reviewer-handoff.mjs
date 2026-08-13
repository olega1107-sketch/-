#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  requiredReviewTracks,
  validateArchitectureReview,
  verifyBaselineTag,
} from './architecture-review.mjs';
import { gitSourceManifest } from './git-source-manifest.mjs';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const defaultRegistryPath = path.resolve(
  scriptDirectory,
  '../conformance/reviewer-tracks-v1.json',
);
const safePathPattern = /^[A-Za-z0-9._/-]+$/;

export function buildReviewerHandoff(review, registry) {
  const reviewReport = validateArchitectureReview(review);
  const tracks = validateRegistry(registry);
  const reviewTracks = new Map(review.tracks.map((track) => [track.id, track]));
  const findings = new Map(
    requiredReviewTracks.map((id) => [
      id,
      review.findings
        .filter((finding) => finding.track_id === id)
        .sort((left, right) => left.id.localeCompare(right.id))
        .map((finding) => ({
          id: finding.id,
          type: finding.type,
          severity: finding.severity,
          status: finding.status,
          location: finding.location,
          consequence: finding.consequence,
        })),
    ]),
  );
  const packetTracks = tracks.map((definition) => {
    const assignment = reviewTracks.get(definition.id);
    return {
      ...definition,
      reviewer: assignment.reviewer,
      assignment_status: assignment.reviewer === null ? 'UNASSIGNED' : 'ASSIGNED',
      review_status: assignment.status,
      findings: findings.get(definition.id),
    };
  });
  const packet = {
    schema_version: 1,
    review_id: review.review_id,
    baseline: { ...review.baseline },
    decision_owner: review.owners.decision_owner,
    final_reviewer: review.owners.final_reviewer,
    gate_status_at_generation: reviewReport.gate_status,
    assignments_complete: packetTracks.every(
      (track) => track.assignment_status === 'ASSIGNED',
    ),
    tracks: packetTracks,
    final_review_requirements: [
      'Final reviewer is independent from the decision owner and every track reviewer.',
      'Every track is COMPLETE with an opaque evidence reference.',
      'No blocking or major finding remains OPEN.',
      'The annotated baseline tag resolves to the declared commit.',
      'The architecture review gate returns PASS.',
    ],
  };
  return { ...packet, packet_sha256: canonicalHash(packet) };
}

export async function writeReviewerHandoff({
  review,
  registry,
  outputDirectory,
  workspaceRoot = defaultWorkspaceRoot,
  verifyTag = true,
}) {
  const root = path.resolve(workspaceRoot);
  const output = path.resolve(outputDirectory);
  if (isWithin(output, root)) {
    throw new Error('Reviewer handoff output must be outside the source workspace.');
  }
  const packet = buildReviewerHandoff(review, registry);
  if (verifyTag) verifyBaselineTag(review.baseline, { workspaceRoot: root });
  const source = await gitSourceManifest(root);
  if (source.headCommit !== review.baseline.commit) {
    throw new Error('Reviewer handoff workspace HEAD must match the review baseline.');
  }
  const trackedPaths = new Set(source.files.map((file) => file.path));
  if (packet.tracks.some((track) => track.documents.some((document) => !trackedPaths.has(document)))) {
    throw new Error('Reviewer handoff references a document outside the tracked baseline.');
  }
  await mkdir(output, { mode: 0o700 });
  await chmod(output, 0o700);
  const packetPath = path.join(output, 'reviewer-packet.json');
  await writePrivate(packetPath, `${JSON.stringify(packet, null, 2)}\n`);
  const briefPaths = [];
  for (const track of packet.tracks) {
    const briefPath = path.join(output, `${track.id}.md`);
    await writePrivate(briefPath, trackBrief(packet, track));
    briefPaths.push(briefPath);
  }
  return { packet, packetPath, briefPaths };
}

function validateRegistry(registry) {
  assertObject(registry, 'reviewer track registry');
  assertExactKeys(registry, ['schema_version', 'tracks'], 'reviewer track registry');
  if (registry.schema_version !== 1 || !Array.isArray(registry.tracks)) {
    throw new Error('Reviewer track registry schema is unsupported.');
  }
  const required = new Set(requiredReviewTracks);
  const seen = new Set();
  const tracks = registry.tracks.map((track) => {
    assertObject(track, 'reviewer track definition');
    assertExactKeys(
      track,
      ['id', 'title', 'objective', 'documents', 'questions', 'completion_requirements'],
      'reviewer track definition',
    );
    if (!required.has(track.id) || seen.has(track.id)) {
      throw new Error('Reviewer track registry contains an unknown or duplicate track.');
    }
    boundedText(track.title, 'track title', 100);
    boundedText(track.objective, 'track objective', 500);
    stringList(track.questions, 'track questions', 1, 20, 500);
    stringList(track.completion_requirements, 'completion requirements', 1, 20, 500);
    stringList(track.documents, 'track documents', 1, 50, 300);
    if (
      track.documents.some(
        (document) =>
          !safePathPattern.test(document) ||
          path.posix.isAbsolute(document) ||
          path.posix.normalize(document) !== document ||
          document.startsWith('../'),
      )
    ) {
      throw new Error('Reviewer track registry contains an unsafe document path.');
    }
    seen.add(track.id);
    return { ...track };
  });
  if (seen.size !== required.size) {
    throw new Error('Reviewer track registry must contain all required tracks.');
  }
  return tracks.sort((left, right) => left.id.localeCompare(right.id));
}

function trackBrief(packet, track) {
  const lines = [
    `# ${track.title} review brief`,
    '',
    `Review: \`${packet.review_id}\``,
    `Baseline commit: \`${packet.baseline.commit}\``,
    `Baseline tag: \`${packet.baseline.tag}\``,
    `Reviewer: ${track.reviewer === null ? '**UNASSIGNED**' : `\`${track.reviewer}\``}`,
    `Track status: \`${track.review_status}\``,
    '',
    '## Objective',
    '',
    track.objective,
    '',
    '## Required documents',
    '',
    ...track.documents.map((document) => `- \`${document}\``),
    '',
    '## Review questions',
    '',
    ...track.questions.map((question, index) => `${index + 1}. ${question}`),
    '',
    '## Known findings',
    '',
    ...(track.findings.length === 0
      ? ['No findings are currently assigned to this track.']
      : track.findings.flatMap((finding) => [
          `- **${finding.id}** \`${finding.severity}/${finding.status}\` at \`${finding.location}\``,
          `  ${finding.consequence}`,
        ])),
    '',
    '## Completion requirements',
    '',
    ...track.completion_requirements.map((requirement) => `- ${requirement}`),
    '',
    'Do not include credentials, private evidence contents or personal data in findings.',
    '',
  ];
  return `${lines.join('\n')}\n`;
}

async function writePrivate(filePath, contents) {
  await writeFile(filePath, contents, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(filePath, 0o600);
}

function stringList(value, name, minimum, maximum, maximumLength) {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > maximum ||
    new Set(value).size !== value.length
  ) {
    throw new Error(`${name} must be a bounded unique list.`);
  }
  for (const item of value) boundedText(item, name, maximumLength);
}

function boundedText(value, name, maximumLength) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${name} must contain bounded single-line text.`);
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

function canonicalHash(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex')}`;
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

function isWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function main(argv) {
  if (argv.length !== 2) {
    throw new Error(
      'Usage: node scripts/reviewer-handoff.mjs <new-output-directory> <review.json>',
    );
  }
  let review;
  let registry;
  try {
    [review, registry] = await Promise.all([
      readFile(path.resolve(argv[1]), 'utf8').then(JSON.parse),
      readFile(defaultRegistryPath, 'utf8').then(JSON.parse),
    ]);
  } catch {
    throw new Error('Reviewer handoff inputs could not be read.');
  }
  const result = await writeReviewerHandoff({
    review,
    registry,
    outputDirectory: argv[0],
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        review_id: result.packet.review_id,
        baseline_commit: result.packet.baseline.commit,
        assignments_complete: result.packet.assignments_complete,
        assigned_tracks: result.packet.tracks.filter(
          (track) => track.assignment_status === 'ASSIGNED',
        ).length,
        required_tracks: result.packet.tracks.length,
        packet_sha256: result.packet.packet_sha256,
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
    const message = error instanceof Error ? error.message : 'Reviewer handoff failed.';
    process.stderr.write(`Reviewer handoff failed: ${message}\n`);
    process.exitCode = 2;
  });
}
