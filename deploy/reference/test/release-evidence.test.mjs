import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { collectReleaseEvidence, releaseProfiles } from '../scripts/release-evidence.mjs';

test('default profiles make the complete deployment suite a source-hashed release gate', () => {
  const profile = releaseProfiles.find((candidate) => candidate.id === 'release.deployment');
  assert.deepEqual(profile, {
    id: 'release.deployment',
    directory: 'deploy/reference',
    artifact_kind: 'source',
    commands: [['node', ['--test', 'test/*.test.mjs']]],
  });
});

test('collector writes private PASS evidence and hashes build output', async () => {
  const fixture = await fixtureWorkspace();
  try {
    const output = path.join(fixture.root, 'evidence-pass');
    const manifest = await collectReleaseEvidence({
      workspaceRoot: fixture.workspace,
      outputDirectory: output,
      executionId: 'CHG-2026-1001',
      profiles: [fixture.profile],
      runner: successfulRunner,
    });

    assert.equal(manifest.checks[0].status, 'PASS');
    assert.equal(manifest.checks[0].artifact.build_file_count, 1);
    assert.match(manifest.checks[0].artifact.build_tree_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.match(manifest.collection_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.equal(manifest.toolchain.pnpm_version, '11.18.0');
    assert.equal(manifest.source.file_count, 4);
    assert.match(manifest.source.tree_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.equal((await stat(output)).mode & 0o777, 0o700);
    for (const file of [
      'release-director.log',
      'release-director-artifact.json',
      'release-evidence.json',
      'source-manifest.json',
    ]) {
      assert.equal((await stat(path.join(output, file))).mode & 0o777, 0o600);
    }
    const log = await readFile(path.join(output, 'release-director.log'), 'utf8');
    assert.match(log, /pnpm build/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('collector prepares every build package before running cross-package checks', async () => {
  const fixture = await fixtureWorkspace();
  try {
    const gatewayDirectory = path.join(fixture.workspace, 'gateway/reference');
    await mkdir(gatewayDirectory, { recursive: true });
    await Promise.all([
      writeFile(
        path.join(gatewayDirectory, 'package.json'),
        '{"private":true,"packageManager":"pnpm@11.18.0"}\n',
      ),
      writeFile(path.join(gatewayDirectory, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n'),
    ]);
    commitWorkspace(fixture.workspace, 'add gateway fixture');
    const calls = [];
    const profiles = [
      {
        ...fixture.profile,
        preparation_commands: [['pnpm', ['install']]],
      },
      {
        id: 'release.gateway',
        directory: 'gateway/reference',
        artifact_kind: 'build',
        preparation_commands: [['pnpm', ['install']]],
        commands: [
          ['pnpm', ['check']],
          ['pnpm', ['build']],
        ],
      },
    ];
    const output = path.join(fixture.root, 'evidence-prepared');
    const manifest = await collectReleaseEvidence({
      workspaceRoot: fixture.workspace,
      outputDirectory: output,
      executionId: 'CHG-2026-1008',
      profiles,
      runner: async (program, arguments_, options) => {
        calls.push(
          `${path.relative(fixture.workspace, options.cwd)}:${program}:${arguments_[0]}`,
        );
        return successfulRunner(program, arguments_, options);
      },
    });

    assert.deepEqual(calls, [
      ':pnpm:--version',
      'director/reference:pnpm:install',
      'gateway/reference:pnpm:install',
      'director/reference:pnpm:check',
      'director/reference:pnpm:build',
      'gateway/reference:pnpm:check',
      'gateway/reference:pnpm:build',
    ]);
    assert.ok(manifest.checks.every((check) => check.status === 'PASS'));
    assert.equal(manifest.checks[0].commands[0].arguments[0], 'install');
    assert.equal(manifest.checks[1].commands[0].arguments[0], 'install');
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('collector rejects a builder with a different pnpm version', async () => {
  const fixture = await fixtureWorkspace();
  try {
    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: fixture.workspace,
        outputDirectory: path.join(fixture.root, 'evidence-wrong-pnpm'),
        executionId: 'CHG-2026-1009',
        profiles: [fixture.profile],
        runner: async (program, arguments_, options) => {
          if (program === 'pnpm' && arguments_[0] === '--version') {
            return {
              exitCode: 0,
              durationMs: 1,
              stdout: '11.19.0\n',
              stderr: '',
            };
          }
          return successfulRunner(program, arguments_, options);
        },
      }),
      /requires pnpm 11\.18\.0/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('failed command creates FAIL evidence without an artifact claim', async () => {
  const fixture = await fixtureWorkspace();
  try {
    const output = path.join(fixture.root, 'evidence-fail');
    let calls = 0;
    const manifest = await collectReleaseEvidence({
      workspaceRoot: fixture.workspace,
      outputDirectory: output,
      executionId: 'CHG-2026-1002',
      profiles: [fixture.profile],
      runner: async (program, arguments_, options) => {
        calls += 1;
        if (calls === 1) return successfulRunner(program, arguments_, options);
        return {
          exitCode: 1,
          durationMs: 2,
          stdout: '',
          stderr: 'synthetic failure\n',
        };
      },
    });

    assert.equal(manifest.checks[0].status, 'FAIL');
    assert.equal(manifest.checks[0].artifact, null);
    assert.equal(manifest.checks[0].commands.length, 1);
    assert.equal(calls, 2);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('source profile writes a private tooling artifact without package metadata or dist', async () => {
  const fixture = await fixtureWorkspace();
  try {
    const output = path.join(fixture.root, 'evidence-source');
    const manifest = await collectReleaseEvidence({
      workspaceRoot: fixture.workspace,
      outputDirectory: output,
      executionId: 'CHG-2026-1007',
      profiles: [fixture.sourceProfile],
      runner: successfulRunner,
    });

    const check = manifest.checks[0];
    assert.equal(check.id, 'release.deployment');
    assert.equal(check.status, 'PASS');
    assert.equal(check.artifact.artifact_kind, 'source');
    assert.equal(check.artifact.source_file_count, 1);
    assert.match(check.artifact.source_tree_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.equal(
      (await stat(path.join(output, 'release-deployment-artifact.json'))).mode & 0o777,
      0o600,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('collector rejects reused output directories and escaping package paths', async () => {
  const fixture = await fixtureWorkspace();
  try {
    const existing = path.join(fixture.root, 'existing');
    await mkdir(existing);
    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: fixture.workspace,
        outputDirectory: existing,
        executionId: 'CHG-2026-1003',
        profiles: [fixture.profile],
        runner: successfulRunner,
      }),
      /EEXIST/,
    );

    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: fixture.workspace,
        outputDirectory: path.join(fixture.root, 'escape'),
        executionId: 'CHG-2026-1004',
        profiles: [{ ...fixture.profile, directory: '../outside' }],
        runner: successfulRunner,
      }),
      /escapes the workspace/,
    );

    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: fixture.workspace,
        outputDirectory: path.join(fixture.workspace, 'evidence'),
        executionId: 'CHG-2026-1005',
        profiles: [fixture.profile],
        runner: successfulRunner,
      }),
      /outside the source workspace/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('collector blocks evidence when source changes during the run', async () => {
  const fixture = await fixtureWorkspace();
  try {
    const output = path.join(fixture.root, 'evidence-mutated');
    let mutated = false;
    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: fixture.workspace,
        outputDirectory: output,
        executionId: 'CHG-2026-1006',
        profiles: [fixture.profile],
        runner: async (program, arguments_, options) => {
          if (!mutated && arguments_[0] !== '--version') {
            mutated = true;
            await writeFile(
              path.join(options.cwd, 'package.json'),
              '{"private":true,"changed":true}\n',
            );
          }
          return successfulRunner(program, arguments_, options);
        },
      }),
      /changed during release evidence collection/,
    );
    assert.equal(
      (await stat(path.join(output, 'collection-failed.json'))).mode & 0o777,
      0o600,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('collector hashes only tracked files and excludes ignored private paths', async () => {
  const fixture = await fixtureWorkspace();
  try {
    const privateDirectory = path.join(fixture.workspace, 'review-output');
    const profilePrivateDirectory = path.join(
      fixture.workspace,
      'deploy/reference/private',
    );
    await mkdir(privateDirectory);
    await mkdir(profilePrivateDirectory);
    await writeFile(path.join(privateDirectory, 'internal-review.json'), '{"private":true}\n');
    await writeFile(path.join(profilePrivateDirectory, 'operator-note.txt'), 'private\n');

    const output = path.join(fixture.root, 'evidence-ignored-private');
    const manifest = await collectReleaseEvidence({
      workspaceRoot: fixture.workspace,
      outputDirectory: output,
      executionId: 'CHG-2026-1010',
      profiles: [fixture.sourceProfile],
      runner: successfulRunner,
    });
    const source = JSON.parse(
      await readFile(path.join(output, 'source-manifest.json'), 'utf8'),
    );
    const artifact = JSON.parse(
      await readFile(path.join(output, 'release-deployment-artifact.json'), 'utf8'),
    );

    assert.equal(manifest.source.file_count, 4);
    assert.equal(source.files.some((file) => file.path.startsWith('review-output/')), false);
    assert.deepEqual(artifact.files.map((file) => file.path), ['tooling.mjs']);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('collector rejects modified, untracked, and non-Git source workspaces', async () => {
  const modified = await fixtureWorkspace();
  try {
    let modifiedRunnerCalls = 0;
    await writeFile(
      path.join(modified.workspace, 'deploy/reference/tooling.mjs'),
      'export const ready = false;\n',
    );
    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: modified.workspace,
        outputDirectory: path.join(modified.root, 'evidence-modified'),
        executionId: 'CHG-2026-1011',
        profiles: [modified.sourceProfile],
        runner: async (...arguments_) => {
          modifiedRunnerCalls += 1;
          return successfulRunner(...arguments_);
        },
      }),
      /clean Git snapshot/,
    );
    assert.equal(modifiedRunnerCalls, 0);
  } finally {
    await rm(modified.root, { recursive: true, force: true });
  }

  const untracked = await fixtureWorkspace();
  try {
    let untrackedRunnerCalls = 0;
    await writeFile(path.join(untracked.workspace, 'untracked.txt'), 'untracked\n');
    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: untracked.workspace,
        outputDirectory: path.join(untracked.root, 'evidence-untracked'),
        executionId: 'CHG-2026-1012',
        profiles: [untracked.sourceProfile],
        runner: async (...arguments_) => {
          untrackedRunnerCalls += 1;
          return successfulRunner(...arguments_);
        },
      }),
      /clean Git snapshot/,
    );
    assert.equal(untrackedRunnerCalls, 0);
  } finally {
    await rm(untracked.root, { recursive: true, force: true });
  }

  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-release-non-git-'));
  const workspace = path.join(root, 'workspace');
  await mkdir(path.join(workspace, 'deploy/reference'), { recursive: true });
  await writeFile(
    path.join(workspace, 'deploy/reference/tooling.mjs'),
    'export const ready = true;\n',
  );
  try {
    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: workspace,
        outputDirectory: path.join(root, 'evidence'),
        executionId: 'CHG-2026-1013',
        profiles: [
          {
            id: 'release.deployment',
            directory: 'deploy/reference',
            artifact_kind: 'source',
            commands: [['node', ['--test', 'test/*.test.mjs']]],
          },
        ],
        runner: successfulRunner,
      }),
      /readable Git repository/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('collector rejects tracked symbolic links from the Git source scope', async () => {
  const fixture = await fixtureWorkspace();
  try {
    await symlink(
      'deploy/reference/tooling.mjs',
      path.join(fixture.workspace, 'tracked-link.mjs'),
    );
    commitWorkspace(fixture.workspace, 'add tracked symlink');
    await assert.rejects(
      collectReleaseEvidence({
        workspaceRoot: fixture.workspace,
        outputDirectory: path.join(fixture.root, 'evidence-symlink'),
        executionId: 'CHG-2026-1014',
        profiles: [fixture.sourceProfile],
        runner: successfulRunner,
      }),
      /regular files only/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function fixtureWorkspace() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-release-evidence-'));
  const workspace = path.join(root, 'workspace');
  const packageDirectory = path.join(workspace, 'director/reference');
  const sourceDirectory = path.join(workspace, 'deploy/reference');
  await mkdir(packageDirectory, { recursive: true });
  await mkdir(sourceDirectory, { recursive: true });
  await Promise.all([
    writeFile(
      path.join(workspace, '.gitignore'),
      ['dist/', 'review-output/', 'deploy/reference/private/', ''].join('\n'),
    ),
    writeFile(
      path.join(packageDirectory, 'package.json'),
      '{"private":true,"packageManager":"pnpm@11.18.0"}\n',
    ),
    writeFile(path.join(packageDirectory, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n'),
    writeFile(path.join(sourceDirectory, 'tooling.mjs'), 'export const ready = true;\n'),
  ]);
  initializeWorkspace(workspace);
  return {
    root,
    workspace,
    packageDirectory,
    profile: {
      id: 'release.director',
      directory: 'director/reference',
      artifact_kind: 'build',
      commands: [
        ['pnpm', ['check']],
        ['pnpm', ['build']],
      ],
    },
    sourceProfile: {
      id: 'release.deployment',
      directory: 'deploy/reference',
      artifact_kind: 'source',
      commands: [['node', ['--test', 'test/*.test.mjs']]],
    },
  };
}

function initializeWorkspace(workspace) {
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: workspace });
  execFileSync('git', ['config', 'user.name', 'Release Fixture'], { cwd: workspace });
  execFileSync('git', ['config', 'user.email', 'release-fixture@example.invalid'], {
    cwd: workspace,
  });
  commitWorkspace(workspace, 'initial release fixture');
}

function commitWorkspace(workspace, message) {
  execFileSync('git', ['add', '--all'], { cwd: workspace });
  execFileSync('git', ['commit', '-q', '-m', message], { cwd: workspace });
}

async function successfulRunner(_program, arguments_, options) {
  if (arguments_[0] === 'build') {
    const dist = path.join(options.cwd, 'dist');
    await mkdir(dist, { recursive: true });
    await writeFile(path.join(dist, 'index.js'), 'export const ready = true;\n');
  }
  return {
    exitCode: 0,
    durationMs: 1,
    stdout: arguments_[0] === '--version' ? '11.18.0\n' : 'ok\n',
    stderr: '',
  };
}
