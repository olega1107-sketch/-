import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { requiredReviewTracks } from '../scripts/architecture-review.mjs';
import {
  buildReviewerHandoff,
  writeReviewerHandoff,
} from '../scripts/reviewer-handoff.mjs';

test('packet builder creates six deterministic briefs and keeps findings track-scoped', () => {
  const review = reviewDocument();
  const registry = registryDocument();
  const packet = buildReviewerHandoff(review, registry);

  assert.equal(packet.assignments_complete, false);
  assert.equal(packet.tracks.length, 6);
  assert.deepEqual(packet.tracks.map((track) => track.id), [...requiredReviewTracks].sort());
  assert.equal(
    packet.tracks.find((track) => track.id === 'security').findings.length,
    1,
  );
  assert.equal(
    packet.tracks.find((track) => track.id === 'data').findings.length,
    0,
  );
  assert.match(packet.packet_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(packet).includes('secret-value'), false);
});

test('packet reports complete assignments without treating an incomplete review as approved', () => {
  const review = reviewDocument();
  review.owners = {
    decision_owner: 'architecture-owner',
    final_reviewer: 'independent-final-reviewer',
  };
  review.tracks = review.tracks.map((track) => ({
    ...track,
    reviewer: `${track.id}-reviewer`,
    status: 'IN_REVIEW',
  }));
  const packet = buildReviewerHandoff(review, registryDocument());

  assert.equal(packet.assignments_complete, true);
  assert.equal(packet.gate_status_at_generation, 'BLOCKED');
  assert.ok(packet.tracks.every((track) => track.assignment_status === 'ASSIGNED'));
});

test('registry rejects missing tracks, duplicate paths, and unsafe documents', () => {
  const missing = registryDocument();
  missing.tracks.pop();
  assert.throws(
    () => buildReviewerHandoff(reviewDocument(), missing),
    /must contain all required tracks/,
  );

  const duplicate = registryDocument();
  duplicate.tracks[0].documents.push(duplicate.tracks[0].documents[0]);
  assert.throws(
    () => buildReviewerHandoff(reviewDocument(), duplicate),
    /bounded unique list/,
  );

  const unsafe = registryDocument();
  unsafe.tracks[0].documents = ['../private-review.md'];
  assert.throws(
    () => buildReviewerHandoff(reviewDocument(), unsafe),
    /unsafe document path/,
  );
});

test('writer requires exact clean baseline and creates private non-overwriting files', async () => {
  const fixture = await repositoryFixture();
  const output = path.join(fixture.root, 'reviewer-packet');
  try {
    const review = reviewDocument(fixture.commit);
    const registry = registryDocument();
    const result = await writeReviewerHandoff({
      review,
      registry,
      outputDirectory: output,
      workspaceRoot: fixture.workspace,
      verifyTag: false,
    });

    assert.equal((await stat(output)).mode & 0o777, 0o700);
    assert.equal((await stat(result.packetPath)).mode & 0o777, 0o600);
    assert.equal(result.briefPaths.length, 6);
    assert.ok(
      (await readFile(path.join(output, 'security.md'), 'utf8')).includes(
        'SECURITY-OPEN-1',
      ),
    );
    for (const briefPath of result.briefPaths) {
      assert.equal((await stat(briefPath)).mode & 0o777, 0o600);
    }
    await assert.rejects(
      writeReviewerHandoff({
        review,
        registry,
        outputDirectory: output,
        workspaceRoot: fixture.workspace,
        verifyTag: false,
      }),
      /EEXIST/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('writer blocks dirty, wrong-commit, and missing-document workspaces', async () => {
  const dirty = await repositoryFixture();
  try {
    await writeFile(path.join(dirty.workspace, 'untracked.txt'), 'untracked\n');
    await assert.rejects(
      writeReviewerHandoff({
        review: reviewDocument(dirty.commit),
        registry: registryDocument(),
        outputDirectory: path.join(dirty.root, 'dirty-output'),
        workspaceRoot: dirty.workspace,
        verifyTag: false,
      }),
      /clean Git snapshot/,
    );
  } finally {
    await rm(dirty.root, { recursive: true, force: true });
  }

  const wrongCommit = await repositoryFixture();
  try {
    await assert.rejects(
      writeReviewerHandoff({
        review: reviewDocument('f'.repeat(40)),
        registry: registryDocument(),
        outputDirectory: path.join(wrongCommit.root, 'wrong-output'),
        workspaceRoot: wrongCommit.workspace,
        verifyTag: false,
      }),
      /HEAD must match/,
    );
  } finally {
    await rm(wrongCommit.root, { recursive: true, force: true });
  }

  const missingDocument = await repositoryFixture();
  try {
    const registry = registryDocument();
    registry.tracks[0].documents = ['docs/missing.md'];
    await assert.rejects(
      writeReviewerHandoff({
        review: reviewDocument(missingDocument.commit),
        registry,
        outputDirectory: path.join(missingDocument.root, 'missing-output'),
        workspaceRoot: missingDocument.workspace,
        verifyTag: false,
      }),
      /outside the tracked baseline/,
    );
  } finally {
    await rm(missingDocument.root, { recursive: true, force: true });
  }
});

function reviewDocument(commit = 'a'.repeat(40)) {
  return {
    schema_version: 1,
    review_id: 'ARCH-REVIEW-2026-001',
    baseline: {
      commit,
      tag: 'architecture-review-v1',
      preflight_report_sha256: `sha256:${'b'.repeat(64)}`,
    },
    started_at: '2026-08-13T09:00:00.000Z',
    completed_at: null,
    owners: { decision_owner: null, final_reviewer: null },
    tracks: requiredReviewTracks.map((id) => ({
      id,
      reviewer: null,
      status: 'NOT_STARTED',
      completed_at: null,
      evidence_ref: null,
    })),
    findings: [
      {
        id: 'SECURITY-OPEN-1',
        track_id: 'security',
        type: 'security_risk',
        severity: 'blocking',
        status: 'OPEN',
        location: 'docs/security.md:1',
        consequence: 'A target security boundary still requires evidence.',
        resolution: null,
        decision_owner: null,
        evidence_ref: null,
      },
    ],
    final_review: { status: 'NOT_RUN', reviewed_at: null, evidence_ref: null },
  };
}

function registryDocument() {
  return {
    schema_version: 1,
    tracks: requiredReviewTracks.map((id) => ({
      id,
      title: `${id} title`,
      objective: `${id} objective`,
      documents: [`docs/${id}.md`],
      questions: [`Does ${id} satisfy its contract?`],
      completion_requirements: [`Complete ${id} with evidence.`],
    })),
  };
}

async function repositoryFixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-reviewer-handoff-'));
  const workspace = path.join(root, 'workspace');
  await mkdir(path.join(workspace, 'docs'), { recursive: true });
  for (const id of requiredReviewTracks) {
    await writeFile(path.join(workspace, `docs/${id}.md`), `${id}\n`);
  }
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: workspace });
  execFileSync('git', ['config', 'user.name', 'Reviewer Fixture'], { cwd: workspace });
  execFileSync('git', ['config', 'user.email', 'reviewer@example.invalid'], {
    cwd: workspace,
  });
  execFileSync('git', ['add', '--all'], { cwd: workspace });
  execFileSync('git', ['commit', '-q', '-m', 'reviewer fixture'], { cwd: workspace });
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: workspace,
    encoding: 'utf8',
  }).trim();
  return { root, workspace, commit };
}
