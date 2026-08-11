import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { collectReleaseEvidence } from '../scripts/release-evidence.mjs';

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
    assert.equal(manifest.source.file_count, 2);
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
    assert.equal(manifest.checks[0].commands.length, 2);
    assert.equal(calls, 2);
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
          if (!mutated) {
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

async function fixtureWorkspace() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-release-evidence-'));
  const workspace = path.join(root, 'workspace');
  const packageDirectory = path.join(workspace, 'director/reference');
  await mkdir(packageDirectory, { recursive: true });
  await Promise.all([
    writeFile(path.join(packageDirectory, 'package.json'), '{"private":true}\n'),
    writeFile(path.join(packageDirectory, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n'),
  ]);
  return {
    root,
    workspace,
    packageDirectory,
    profile: {
      id: 'release.director',
      directory: 'director/reference',
      commands: [
        ['pnpm', ['check']],
        ['pnpm', ['build']],
      ],
    },
  };
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
    stdout: 'ok\n',
    stderr: '',
  };
}
