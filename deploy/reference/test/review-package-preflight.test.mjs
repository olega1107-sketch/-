import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  inspectReviewPackage,
  requiredReviewFiles,
} from '../scripts/review-package-preflight.mjs';

test('clean committed review package passes with a bounded manifest', async () => {
  const root = await reviewFixture();
  try {
    const report = await inspectReviewPackage({ workspaceRoot: root });
    assert.equal(report.status, 'PASS');
    assert.equal(report.head_commit.length, 40);
    assert.equal(report.tracked_file_count, requiredReviewFiles.length);
    assert.ok(report.checks.every((check) => check.status === 'PASS'));
    assert.deepEqual(report.issues, []);
    assert.match(report.report_sha256, /^sha256:[0-9a-f]{64}$/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('dirty or untracked worktree blocks a reproducible review snapshot', async () => {
  const root = await reviewFixture();
  try {
    await writeFile(path.join(root, 'notes.txt'), 'uncommitted review note\n');
    const report = await inspectReviewPackage({ workspaceRoot: root });
    assert.equal(report.status, 'FAIL');
    assert.ok(report.issues.some((issue) => issue.code === 'git_worktree_dirty'));
    assert.equal(
      report.checks.find((check) => check.id === 'git.clean_snapshot').status,
      'FAIL',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('tracked secret material and forbidden credential files fail closed', async () => {
  const root = await reviewFixture();
  try {
    const keyMarker = ['-----BEGIN', 'PRIVATE KEY-----'].join(' ');
    await writeFile(path.join(root, 'review.pem'), `${keyMarker}\nnot-a-real-key\n`);
    commitAll(root, 'add forbidden material');
    const report = await inspectReviewPackage({ workspaceRoot: root });
    assert.equal(report.status, 'FAIL');
    assert.ok(
      report.issues.some(
        (issue) => issue.code === 'forbidden_tracked_path' && issue.path === 'review.pem',
      ),
    );
    assert.ok(
      report.issues.some(
        (issue) => issue.code === 'private_key_material' && issue.path === 'review.pem',
      ),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('broken local Markdown links block the review package', async () => {
  const root = await reviewFixture();
  try {
    await writeFile(path.join(root, 'README.md'), '[Missing](docs/dirizhor/missing.md)\n');
    commitAll(root, 'break local link');
    const report = await inspectReviewPackage({ workspaceRoot: root });
    assert.equal(report.status, 'FAIL');
    assert.ok(
      report.issues.some(
        (issue) =>
          issue.code === 'markdown_local_link_missing' && issue.path === 'README.md',
      ),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

async function reviewFixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-review-package-'));
  for (const relativePath of requiredReviewFiles) {
    const absolutePath = path.join(root, ...relativePath.split('/'));
    await mkdir(path.dirname(absolutePath), { recursive: true });
    const content =
      relativePath === 'README.md'
        ? '[Context](docs/dirizhor/context.md)\n[Docs](docs/dirizhor/)\n'
        : relativePath === '.gitignore'
          ? 'node_modules/\n'
          : `${relativePath}\n`;
    await writeFile(absolutePath, content);
  }
  execFileSync('git', ['init', '--quiet'], { cwd: root });
  commitAll(root, 'initial review package');
  return root;
}

function commitAll(root, message) {
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
      message,
    ],
    { cwd: root },
  );
}
