import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  collectReleaseEvidence,
  releaseProfiles,
} from '../scripts/release-evidence.mjs';
import { verifyReleaseEvidence } from '../scripts/release-evidence-verify.mjs';

test('verifier accepts a complete private collection and reports evidence-only scope', async () => {
  const fixture = await completeFixture();
  try {
    const report = await verifyReleaseEvidence({
      evidenceDirectory: fixture.evidence,
    });

    assert.equal(report.release_gate, 'PASS');
    assert.equal(report.verification_scope, 'evidence_integrity');
    assert.equal(report.source.workspace_match, 'NOT_RUN');
    assert.equal(report.evidence_file_count, 10);
    assert.equal(report.checks.length, 4);
    assert.ok(report.checks.every((check) => check.status === 'PASS'));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier matches source, package metadata and every artifact to the builder workspace', async () => {
  const fixture = await completeFixture();
  try {
    const report = await verifyReleaseEvidence({
      evidenceDirectory: fixture.evidence,
      workspaceRoot: fixture.workspace,
    });

    assert.equal(report.verification_scope, 'evidence_and_workspace');
    assert.equal(report.source.workspace_match, 'PASS');
    assert.ok(
      report.workspace.profiles.every((profile) => profile.artifact_match === 'PASS'),
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('workspace verification excludes ignored private files from both source scopes', async () => {
  const fixture = await completeFixture();
  try {
    const privateDirectory = path.join(fixture.workspace, 'review-output');
    const profilePrivateDirectory = path.join(
      fixture.workspace,
      'deploy/reference/private',
    );
    await mkdir(privateDirectory);
    await mkdir(profilePrivateDirectory);
    await writeFile(path.join(privateDirectory, 'review.json'), '{"private":true}\n');
    await writeFile(path.join(profilePrivateDirectory, 'note.txt'), 'private\n');

    const report = await verifyReleaseEvidence({
      evidenceDirectory: fixture.evidence,
      workspaceRoot: fixture.workspace,
    });
    assert.equal(report.source.workspace_match, 'PASS');
    assert.equal(
      report.workspace.profiles.find((profile) => profile.id === 'release.deployment')
        .artifact_match,
      'PASS',
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier rejects changed logs and unexpected evidence files', async () => {
  const changedLog = await completeFixture();
  try {
    await writeFile(
      path.join(changedLog.evidence, 'release-director.log'),
      'tampered\n',
    );
    await assert.rejects(
      verifyReleaseEvidence({ evidenceDirectory: changedLog.evidence }),
      /log hash mismatch/,
    );
  } finally {
    await rm(changedLog.root, { recursive: true, force: true });
  }

  const extraFile = await completeFixture();
  try {
    const unexpected = path.join(extraFile.evidence, 'unexpected.txt');
    await writeFile(unexpected, 'unexpected\n', { mode: 0o600 });
    await assert.rejects(
      verifyReleaseEvidence({ evidenceDirectory: extraFile.evidence }),
      /missing, extra or unsupported files/,
    );
  } finally {
    await rm(extraFile.root, { recursive: true, force: true });
  }
});

test('verifier rejects evidence that grants group or other access', async () => {
  const fixture = await completeFixture();
  try {
    await chmod(path.join(fixture.evidence, 'source-manifest.json'), 0o644);
    await assert.rejects(
      verifyReleaseEvidence({ evidenceDirectory: fixture.evidence }),
      /must not grant group or other access/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('workspace matching rejects source and build artifact drift', async () => {
  const sourceDrift = await completeFixture();
  try {
    await writeFile(
      path.join(sourceDrift.workspace, 'deploy/reference/tooling.mjs'),
      'export const ready = false;\n',
    );
    await assert.rejects(
      verifyReleaseEvidence({
        evidenceDirectory: sourceDrift.evidence,
        workspaceRoot: sourceDrift.workspace,
      }),
      /clean Git snapshot/,
    );
  } finally {
    await rm(sourceDrift.root, { recursive: true, force: true });
  }

  const artifactDrift = await completeFixture();
  try {
    await writeFile(
      path.join(artifactDrift.workspace, 'director/reference/dist/index.js'),
      'export const ready = false;\n',
    );
    await assert.rejects(
      verifyReleaseEvidence({
        evidenceDirectory: artifactDrift.evidence,
        workspaceRoot: artifactDrift.workspace,
      }),
      /artifact does not match.*release\.director/,
    );
  } finally {
    await rm(artifactDrift.root, { recursive: true, force: true });
  }
});

test('valid evidence with a failed profile remains BLOCKED', async () => {
  const fixture = await completeFixture({ failDirectorCheck: true });
  try {
    const report = await verifyReleaseEvidence({
      evidenceDirectory: fixture.evidence,
    });

    assert.equal(report.release_gate, 'BLOCKED');
    assert.equal(
      report.checks.find((check) => check.id === 'release.director').status,
      'FAIL',
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('manifest edits are rejected by the canonical collection hash', async () => {
  const fixture = await completeFixture();
  try {
    const manifestPath = path.join(fixture.evidence, 'release-evidence.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    manifest.checks[0].commands[0].duration_ms += 1;
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await assert.rejects(
      verifyReleaseEvidence({ evidenceDirectory: fixture.evidence }),
      /collection hash mismatch/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function completeFixture({ failDirectorCheck = false } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-release-verify-'));
  const workspace = path.join(root, 'workspace');
  const evidence = path.join(root, 'evidence');
  for (const packageDirectory of [
    'director/reference',
    'gateway/reference',
    'ui/reference',
  ]) {
    const absolute = path.join(workspace, packageDirectory);
    await mkdir(absolute, { recursive: true });
    await Promise.all([
      writeFile(
        path.join(absolute, 'package.json'),
        '{"private":true,"packageManager":"pnpm@11.16.0"}\n',
      ),
      writeFile(path.join(absolute, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n'),
    ]);
  }
  await writeFile(
    path.join(workspace, '.gitignore'),
    ['dist/', 'review-output/', 'deploy/reference/private/', ''].join('\n'),
  );
  await mkdir(path.join(workspace, 'deploy/reference'), { recursive: true });
  await writeFile(
    path.join(workspace, 'deploy/reference/tooling.mjs'),
    'export const ready = true;\n',
  );
  initializeWorkspace(workspace);

  await collectReleaseEvidence({
    workspaceRoot: workspace,
    outputDirectory: evidence,
    executionId: failDirectorCheck ? 'CHG-VERIFY-FAIL' : 'CHG-VERIFY-PASS',
    profiles: releaseProfiles,
    runner: async (program, arguments_, options) => {
      if (
        failDirectorCheck &&
        options.cwd.endsWith(path.join('director', 'reference')) &&
        arguments_[0] === 'check'
      ) {
        return {
          exitCode: 1,
          durationMs: 1,
          stdout: '',
          stderr: 'synthetic failure\n',
        };
      }
      if (arguments_[0] === 'build') {
        const dist = path.join(options.cwd, 'dist');
        await mkdir(dist, { recursive: true });
        await writeFile(path.join(dist, 'index.js'), 'export const ready = true;\n');
      }
      return {
        exitCode: 0,
        durationMs: 1,
        stdout: arguments_[0] === '--version' ? '11.16.0\n' : 'ok\n',
        stderr: '',
      };
    },
  });
  return { root, workspace, evidence };
}

function initializeWorkspace(workspace) {
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: workspace });
  execFileSync('git', ['config', 'user.name', 'Release Fixture'], { cwd: workspace });
  execFileSync('git', ['config', 'user.email', 'release-fixture@example.invalid'], {
    cwd: workspace,
  });
  execFileSync('git', ['add', '--all'], { cwd: workspace });
  execFileSync('git', ['commit', '-q', '-m', 'initial release fixture'], {
    cwd: workspace,
  });
}
