import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$/;
const ownerPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/;
const commitPattern = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const tagPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const evidenceReferencePattern = /^(?:artifact|change|run|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const zeroDigest = `sha256:${'0'.repeat(64)}`;
const trackStatuses = new Set(['NOT_STARTED', 'IN_REVIEW', 'COMPLETE']);
const findingTypes = new Set([
  'contradiction',
  'missing_decision',
  'security_risk',
  'operability',
  'terminology',
  'editorial',
]);
const findingSeverities = new Set(['blocking', 'major', 'minor']);
const findingStatuses = new Set(['OPEN', 'RESOLVED', 'ACCEPTED_RISK']);
const finalStatuses = new Set(['NOT_RUN', 'APPROVED', 'REJECTED']);

export const requiredReviewTracks = Object.freeze([
  'product_domain',
  'application_api',
  'security',
  'data',
  'platform_sre',
  'engineering',
]);

export function validateArchitectureReview(document) {
  assertObject(document, 'review');
  assertExactKeys(
    document,
    [
      'schema_version',
      'review_id',
      'baseline',
      'started_at',
      'completed_at',
      'owners',
      'tracks',
      'findings',
      'final_review',
    ],
    'review',
  );
  if (document.schema_version !== 1) {
    throw new Error('The architecture review schema version is unsupported.');
  }
  assertIdentifier(document.review_id, 'review_id');
  const startedAt = timestamp(document.started_at, 'started_at');
  const completedAt = nullableTimestamp(document.completed_at, 'completed_at');
  if (completedAt !== null && completedAt < startedAt) {
    throw new Error('Review completion precedes its start.');
  }

  validateBaseline(document.baseline);
  validateOwners(document.owners);
  const tracks = validateTracks(document.tracks, startedAt, completedAt);
  const findings = validateFindings(document.findings, document.owners.decision_owner);
  const finalReview = validateFinalReview(
    document.final_review,
    startedAt,
    completedAt,
    document.owners.final_reviewer,
  );

  const trackReviewers = new Set(
    tracks.map((track) => track.reviewer).filter((reviewer) => reviewer !== null),
  );
  if (
    document.owners.final_reviewer !== null &&
    (document.owners.final_reviewer === document.owners.decision_owner ||
      trackReviewers.has(document.owners.final_reviewer))
  ) {
    throw new Error('Final reviewer must be independent from review and decision owners.');
  }

  const openBlocking = findings.filter(
    (finding) => finding.status === 'OPEN' && finding.severity === 'blocking',
  ).length;
  const openMajor = findings.filter(
    (finding) => finding.status === 'OPEN' && finding.severity === 'major',
  ).length;
  const openMinor = findings.filter(
    (finding) => finding.status === 'OPEN' && finding.severity === 'minor',
  ).length;
  const tracksComplete = tracks.filter((track) => track.status === 'COMPLETE').length;
  const tracksAssigned = tracks.filter((track) => track.reviewer !== null).length;
  const blockingReasons = [];
  if (
    document.owners.decision_owner === null ||
    document.owners.final_reviewer === null
  ) {
    blockingReasons.push('owners_unassigned');
  }
  if (tracksAssigned !== requiredReviewTracks.length) {
    blockingReasons.push('tracks_unassigned');
  }
  if (tracksComplete !== requiredReviewTracks.length) {
    blockingReasons.push('tracks_incomplete');
  }
  if (openBlocking > 0) blockingReasons.push('blocking_findings_open');
  if (openMajor > 0) blockingReasons.push('major_findings_open');
  if (completedAt === null) blockingReasons.push('review_not_completed');
  if (finalReview.status !== 'APPROVED') blockingReasons.push('final_review_not_approved');

  const normalizedDocument = {
    ...document,
    tracks: [...document.tracks].sort((left, right) => left.id.localeCompare(right.id)),
    findings: [...document.findings].sort((left, right) => left.id.localeCompare(right.id)),
  };
  return {
    schema_version: document.schema_version,
    review_id: document.review_id,
    baseline: { ...document.baseline },
    owners: { ...document.owners },
    gate_status: blockingReasons.length === 0 ? 'PASS' : 'BLOCKED',
    counts: {
      tracks_assigned: tracksAssigned,
      tracks_complete: tracksComplete,
      tracks_required: requiredReviewTracks.length,
      findings_total: findings.length,
      open_blocking: openBlocking,
      open_major: openMajor,
      open_minor: openMinor,
      accepted_risks: findings.filter((finding) => finding.status === 'ACCEPTED_RISK').length,
    },
    blocking_reasons: blockingReasons.sort(),
    tracks: tracks.map(({ id, status }) => ({ id, status })),
    findings: findings.map(({ id, severity, status }) => ({ id, severity, status })),
    report_sha256: canonicalHash(normalizedDocument),
  };
}

export function verifyBaselineTag(
  baseline,
  { workspaceRoot = defaultWorkspaceRoot, gitCommand = runGit } = {},
) {
  validateBaseline(baseline);
  const root = path.resolve(workspaceRoot);
  const reference = `refs/tags/${baseline.tag}`;
  const type = gitCommand(root, ['cat-file', '-t', reference]);
  if (type.stdout.trim() !== 'tag') {
    throw new Error('Architecture review baseline requires an annotated Git tag.');
  }
  const resolved = gitCommand(root, ['rev-list', '-n', '1', reference]).stdout.trim();
  if (resolved !== baseline.commit) {
    throw new Error('Architecture review tag does not resolve to the declared commit.');
  }
  return { tag: baseline.tag, commit: resolved };
}

function validateBaseline(baseline) {
  assertObject(baseline, 'baseline');
  assertExactKeys(
    baseline,
    ['commit', 'tag', 'preflight_report_sha256'],
    'baseline',
  );
  if (!commitPattern.test(baseline.commit)) {
    throw new Error('Baseline commit must be a full lowercase Git object ID.');
  }
  if (
    !tagPattern.test(baseline.tag) ||
    baseline.tag.includes('..') ||
    baseline.tag.endsWith('.') ||
    baseline.tag.endsWith('.lock')
  ) {
    throw new Error('Baseline tag is invalid.');
  }
  if (
    !digestPattern.test(baseline.preflight_report_sha256) ||
    baseline.preflight_report_sha256 === zeroDigest
  ) {
    throw new Error('Baseline preflight report requires a SHA-256 digest.');
  }
}

function validateOwners(owners) {
  assertObject(owners, 'owners');
  assertExactKeys(owners, ['decision_owner', 'final_reviewer'], 'owners');
  for (const key of ['decision_owner', 'final_reviewer']) {
    if (owners[key] === null) continue;
    if (
      typeof owners[key] !== 'string' ||
      !ownerPattern.test(owners[key]) ||
      owners[key].startsWith('replace-')
    ) {
      throw new Error(`${key} must be an opaque owner identifier.`);
    }
  }
}

function validateTracks(tracks, startedAt, completedAt) {
  if (!Array.isArray(tracks)) {
    throw new Error('Review tracks must be an array.');
  }
  const required = new Set(requiredReviewTracks);
  const seen = new Set();
  const normalized = [];
  for (const track of tracks) {
    assertObject(track, 'review track');
    assertExactKeys(
      track,
      ['id', 'reviewer', 'status', 'completed_at', 'evidence_ref'],
      'review track',
    );
    if (!required.has(track.id) || seen.has(track.id)) {
      throw new Error('Review contains an unknown or duplicate track.');
    }
    if (
      track.reviewer !== null &&
      (typeof track.reviewer !== 'string' ||
        !ownerPattern.test(track.reviewer) ||
        track.reviewer.startsWith('replace-'))
    ) {
      throw new Error('Review track requires an opaque reviewer identifier.');
    }
    if (!trackStatuses.has(track.status)) {
      throw new Error('Review track contains an unsupported status.');
    }
    if (track.status === 'COMPLETE') {
      const completed = timestamp(track.completed_at, 'track completed_at');
      if (
        track.reviewer === null ||
        completed < startedAt ||
        (completedAt !== null && completed > completedAt) ||
        !validEvidenceReference(track.evidence_ref)
      ) {
        throw new Error('Completed review track requires timely opaque evidence.');
      }
    } else if (track.status === 'IN_REVIEW' && track.reviewer === null) {
      throw new Error('Active review track requires an assigned reviewer.');
    } else if (track.completed_at !== null || track.evidence_ref !== null) {
      throw new Error('Incomplete review track cannot claim completion evidence.');
    }
    seen.add(track.id);
    normalized.push(track);
  }
  if (seen.size !== required.size) {
    throw new Error('Review must contain every required track exactly once.');
  }
  return normalized.sort((left, right) => left.id.localeCompare(right.id));
}

function validateFindings(findings, decisionOwner) {
  if (!Array.isArray(findings) || findings.length > 500) {
    throw new Error('Review findings must be a bounded array.');
  }
  const trackIds = new Set(requiredReviewTracks);
  const seen = new Set();
  const normalized = [];
  for (const finding of findings) {
    assertObject(finding, 'review finding');
    assertExactKeys(
      finding,
      [
        'id',
        'track_id',
        'type',
        'severity',
        'status',
        'location',
        'consequence',
        'resolution',
        'decision_owner',
        'evidence_ref',
      ],
      'review finding',
    );
    if (!identifierPattern.test(finding.id) || seen.has(finding.id)) {
      throw new Error('Review finding ID is invalid or duplicated.');
    }
    if (!trackIds.has(finding.track_id)) {
      throw new Error('Review finding references an unknown track.');
    }
    if (
      !findingTypes.has(finding.type) ||
      !findingSeverities.has(finding.severity) ||
      !findingStatuses.has(finding.status)
    ) {
      throw new Error('Review finding classification is unsupported.');
    }
    boundedText(finding.location, 'finding location', 512);
    boundedText(finding.consequence, 'finding consequence', 2000);
    if (finding.status === 'OPEN') {
      if (
        finding.resolution !== null ||
        finding.decision_owner !== null ||
        finding.evidence_ref !== null
      ) {
        throw new Error('Open finding cannot claim a resolution decision.');
      }
    } else {
      boundedText(finding.resolution, 'finding resolution', 4000);
      if (
        finding.decision_owner !== decisionOwner ||
        !validEvidenceReference(finding.evidence_ref)
      ) {
        throw new Error('Closed finding requires the declared decision owner and evidence.');
      }
    }
    seen.add(finding.id);
    normalized.push(finding);
  }
  return normalized.sort((left, right) => left.id.localeCompare(right.id));
}

function validateFinalReview(finalReview, startedAt, completedAt, finalReviewer) {
  assertObject(finalReview, 'final_review');
  assertExactKeys(finalReview, ['status', 'reviewed_at', 'evidence_ref'], 'final_review');
  if (!finalStatuses.has(finalReview.status)) {
    throw new Error('Final review contains an unsupported status.');
  }
  if (finalReview.status === 'NOT_RUN') {
    if (finalReview.reviewed_at !== null || finalReview.evidence_ref !== null) {
      throw new Error('NOT_RUN final review cannot claim evidence.');
    }
    if (completedAt !== null) {
      throw new Error('Completed review requires a final review decision.');
    }
    return finalReview;
  }
  const reviewedAt = timestamp(finalReview.reviewed_at, 'final reviewed_at');
  if (
    finalReviewer === null ||
    completedAt === null ||
    reviewedAt < startedAt ||
    reviewedAt > completedAt ||
    !validEvidenceReference(finalReview.evidence_ref)
  ) {
    throw new Error('Final review decision requires timely opaque evidence.');
  }
  return finalReview;
}

function validEvidenceReference(value) {
  return typeof value === 'string' && evidenceReferencePattern.test(value);
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

function nullableTimestamp(value, name) {
  return value === null ? null : timestamp(value, name);
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

function assertIdentifier(value, name) {
  if (
    typeof value !== 'string' ||
    !identifierPattern.test(value) ||
    value.startsWith('replace-')
  ) {
    throw new Error(`${name} must be an opaque identifier.`);
  }
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

function runGit(root, args) {
  const result = spawnSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error !== undefined || result.status !== 0) {
    throw new Error('Architecture review baseline could not be resolved in Git.');
  }
  return { stdout: result.stdout ?? '' };
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

async function main(argv) {
  if (argv.length !== 1) {
    throw new Error(
      'Usage: node deploy/reference/scripts/architecture-review.mjs <review.json>',
    );
  }
  const document = JSON.parse(await readFile(path.resolve(argv[0]), 'utf8'));
  const report = validateArchitectureReview(document);
  verifyBaselineTag(document.baseline, { workspaceRoot: process.cwd() });
  process.stdout.write(
    `${JSON.stringify({ ...report, baseline_tag_verified: true }, null, 2)}\n`,
  );
  process.exitCode = report.gate_status === 'PASS' ? 0 : 1;
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : 'Unknown validation error.';
    process.stderr.write(`Architecture review is invalid: ${message}\n`);
    process.exitCode = 2;
  });
}
