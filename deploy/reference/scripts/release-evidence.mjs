import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const executionIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;
const safeRelativePathPattern = /^[A-Za-z0-9._/-]+$/;
export const releaseEvidencePnpmVersion = '11.16.0';
const allowedCheckIds = new Set([
  'release.director',
  'release.gateway',
  'release.ui',
  'release.deployment',
]);
const ignoredSourceDirectories = new Set([
  '.git',
  '.pnpm-store',
  '.vite',
  'coverage',
  'dist',
  'node_modules',
]);

export const releaseProfiles = [
  {
    id: 'release.director',
    directory: 'director/reference',
    artifact_kind: 'build',
    preparation_commands: [
      ['pnpm', ['install', '--frozen-lockfile', '--offline']],
    ],
    commands: [
      ['pnpm', ['db:checksums']],
      ['pnpm', ['check']],
      ['pnpm', ['lint']],
      ['pnpm', ['test', '--', '--maxWorkers=2']],
      ['pnpm', ['build']],
    ],
  },
  {
    id: 'release.gateway',
    directory: 'gateway/reference',
    artifact_kind: 'build',
    preparation_commands: [
      ['pnpm', ['install', '--frozen-lockfile', '--offline']],
    ],
    commands: [
      ['pnpm', ['check']],
      ['pnpm', ['lint']],
      ['pnpm', ['test', '--', '--maxWorkers=2']],
      ['pnpm', ['build']],
    ],
  },
  {
    id: 'release.ui',
    directory: 'ui/reference',
    artifact_kind: 'build',
    preparation_commands: [
      ['pnpm', ['install', '--frozen-lockfile', '--offline']],
    ],
    commands: [
      ['pnpm', ['check']],
      ['pnpm', ['test', '--', '--maxWorkers=2']],
      ['pnpm', ['build']],
    ],
  },
  {
    id: 'release.deployment',
    directory: 'deploy/reference',
    artifact_kind: 'source',
    commands: [
      ['node', ['--test', 'test/*.test.mjs']],
    ],
  },
];

export async function collectReleaseEvidence({
  workspaceRoot = defaultWorkspaceRoot,
  outputDirectory,
  executionId,
  profiles = releaseProfiles,
  runner = runCommand,
}) {
  if (
    typeof executionId !== 'string' ||
    !executionIdPattern.test(executionId) ||
    executionId.startsWith('replace-')
  ) {
    throw new Error('A non-placeholder execution ID is required.');
  }
  if (typeof outputDirectory !== 'string' || outputDirectory.length === 0) {
    throw new Error('A new protected output directory is required.');
  }
  validateProfiles(profiles);

  const root = path.resolve(workspaceRoot);
  const output = path.resolve(outputDirectory);
  if (insidePath(root, output)) {
    throw new Error('Release evidence must be stored outside the source workspace.');
  }
  await mkdir(output, { mode: 0o700 });
  await chmod(output, 0o700);
  const startedAt = new Date().toISOString();
  const checks = [];

  try {
    const toolchain = await verifyReleaseToolchain(root, profiles, runner);
    const sourceBefore = await sourceTreeManifest(root);
    const sourceDocument = {
      schema_version: 1,
      file_count: sourceBefore.files.length,
      total_bytes: sourceBefore.totalBytes,
      tree_sha256: canonicalHash(sourceBefore.files),
      files: sourceBefore.files,
    };
    await writePrivateJson(path.join(output, 'source-manifest.json'), sourceDocument);
    const preparations = new Map();
    for (const profile of profiles) {
      const workingDirectory = safeWorkspacePath(root, profile.directory);
      await assertProfileDirectory(workingDirectory, profile.artifact_kind);
      preparations.set(
        profile.id,
        await runProfileCommands(
          profile.preparation_commands ?? [],
          workingDirectory,
          runner,
        ),
      );
    }
    for (const profile of profiles) {
      checks.push(
        await collectProfile({
          root,
          output,
          executionId,
          profile,
          preparation: preparations.get(profile.id),
          runner,
        }),
      );
    }
    const sourceAfter = await sourceTreeManifest(root);
    const sourceAfterHash = canonicalHash(sourceAfter.files);
    if (sourceAfterHash !== sourceDocument.tree_sha256) {
      throw new Error('Source workspace changed during release evidence collection.');
    }
    const completedAt = new Date().toISOString();
    const manifestWithoutHash = {
      schema_version: 1,
      execution_id: executionId,
      started_at: startedAt,
      completed_at: completedAt,
      toolchain,
      source: {
        manifest_file: 'source-manifest.json',
        manifest_sha256: canonicalHash(sourceDocument),
        file_count: sourceDocument.file_count,
        total_bytes: sourceDocument.total_bytes,
        tree_sha256: sourceDocument.tree_sha256,
      },
      checks,
    };
    const manifest = {
      ...manifestWithoutHash,
      collection_sha256: canonicalHash(manifestWithoutHash),
    };
    await writePrivateJson(path.join(output, 'release-evidence.json'), manifest);
    return manifest;
  } catch (error) {
    await writePrivateJson(path.join(output, 'collection-failed.json'), {
      schema_version: 1,
      execution_id: executionId,
      failed_at: new Date().toISOString(),
      completed_checks: checks.map((check) => ({
        id: check.id,
        status: check.status,
      })),
    }).catch(() => undefined);
    throw error;
  }
}

async function verifyReleaseToolchain(root, profiles, runner) {
  const pnpmProfiles = profiles.filter((profile) =>
    [...(profile.preparation_commands ?? []), ...profile.commands].some(
      ([program]) => program === 'pnpm',
    ),
  );
  if (pnpmProfiles.length === 0) {
    return { pnpm_version: null };
  }
  for (const profile of pnpmProfiles) {
    const packagePath = path.join(
      safeWorkspacePath(root, profile.directory),
      'package.json',
    );
    const document = JSON.parse(await readFile(packagePath, 'utf8'));
    if (document.packageManager !== `pnpm@${releaseEvidencePnpmVersion}`) {
      throw new Error('Every release package must pin the approved pnpm version.');
    }
  }
  const result = await runner('pnpm', ['--version'], {
    cwd: root,
    environment: childEnvironment(),
  });
  const version = result.stdout.trim();
  if (result.exitCode !== 0 || version !== releaseEvidencePnpmVersion) {
    throw new Error(`Release builder requires pnpm ${releaseEvidencePnpmVersion}.`);
  }
  return { pnpm_version: version };
}

async function collectProfile({
  root,
  output,
  executionId,
  profile,
  preparation,
  runner,
}) {
  const workingDirectory = safeWorkspacePath(root, profile.directory);
  await assertProfileDirectory(workingDirectory, profile.artifact_kind);
  if (profile.artifact_kind === 'build') {
    await rm(path.join(workingDirectory, 'dist'), { recursive: true, force: true });
  }
  const commandRecords = [...(preparation?.commandRecords ?? [])];
  const logParts = [...(preparation?.logParts ?? [])];
  let status = preparation?.status ?? 'PASS';

  if (status === 'PASS') {
    const verification = await runProfileCommands(
      profile.commands,
      workingDirectory,
      runner,
    );
    commandRecords.push(...verification.commandRecords);
    logParts.push(...verification.logParts);
    status = verification.status;
  }

  const slug = profile.id.replaceAll('.', '-');
  const logName = `${slug}.log`;
  const logPath = path.join(output, logName);
  await writeFile(logPath, logParts.join(''), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  await chmod(logPath, 0o600);
  const logSha256 = await fileHash(logPath);
  const observedAt = new Date().toISOString();
  let artifact = null;
  if (status === 'PASS') {
    artifact = profile.artifact_kind === 'build'
      ? await buildArtifactEvidence(workingDirectory, output, slug)
      : await sourceArtifactEvidence(workingDirectory, output, slug);
  }

  return {
    id: profile.id,
    status,
    observed_at: observedAt,
    evidence_ref: `artifact:${executionId}/${profile.id}`,
    log_file: logName,
    log_sha256: logSha256,
    commands: commandRecords,
    artifact,
  };
}

async function runProfileCommands(commands, workingDirectory, runner) {
  const commandRecords = [];
  const logParts = [];
  let status = 'PASS';
  for (const [program, arguments_] of commands) {
    const result = await runner(program, arguments_, {
      cwd: workingDirectory,
      environment: childEnvironment(),
    });
    commandRecords.push({
      program,
      arguments: arguments_,
      exit_code: result.exitCode,
      duration_ms: result.durationMs,
    });
    logParts.push(
      `$ ${program} ${arguments_.join(' ')}\n`,
      `exit_code=${result.exitCode ?? 'not_executed'} duration_ms=${result.durationMs}\n`,
      result.stdout,
      result.stdout.endsWith('\n') ? '' : '\n',
      result.stderr,
      result.stderr.length === 0 || result.stderr.endsWith('\n') ? '' : '\n',
    );
    if (result.exitCode !== 0) {
      status = 'FAIL';
      break;
    }
  }
  return { status, commandRecords, logParts };
}

async function buildArtifactEvidence(workingDirectory, output, slug) {
  const [packageJsonSha256, lockfileSha256, buildTree] = await Promise.all([
    fileHash(path.join(workingDirectory, 'package.json')),
    fileHash(path.join(workingDirectory, 'pnpm-lock.yaml')),
    directoryManifest(path.join(workingDirectory, 'dist')),
  ]);
  const artifactDocument = {
    schema_version: 1,
    package_json_sha256: packageJsonSha256,
    lockfile_sha256: lockfileSha256,
    build_file_count: buildTree.files.length,
    build_total_bytes: buildTree.totalBytes,
    build_tree_sha256: canonicalHash(buildTree.files),
    files: buildTree.files,
  };
  const artifactName = `${slug}-artifact.json`;
  await writePrivateJson(path.join(output, artifactName), artifactDocument);
  return {
    manifest_file: artifactName,
    manifest_sha256: canonicalHash(artifactDocument),
    package_json_sha256: packageJsonSha256,
    lockfile_sha256: lockfileSha256,
    build_file_count: buildTree.files.length,
    build_total_bytes: buildTree.totalBytes,
    build_tree_sha256: artifactDocument.build_tree_sha256,
  };
}

async function sourceArtifactEvidence(workingDirectory, output, slug) {
  const sourceTree = await directoryManifest(workingDirectory);
  const artifactDocument = {
    schema_version: 1,
    artifact_kind: 'source',
    source_file_count: sourceTree.files.length,
    source_total_bytes: sourceTree.totalBytes,
    source_tree_sha256: canonicalHash(sourceTree.files),
    files: sourceTree.files,
  };
  const artifactName = `${slug}-artifact.json`;
  await writePrivateJson(path.join(output, artifactName), artifactDocument);
  return {
    artifact_kind: 'source',
    manifest_file: artifactName,
    manifest_sha256: canonicalHash(artifactDocument),
    source_file_count: sourceTree.files.length,
    source_total_bytes: sourceTree.totalBytes,
    source_tree_sha256: artifactDocument.source_tree_sha256,
  };
}

async function directoryManifest(directory) {
  const root = path.resolve(directory);
  const rootMetadata = await lstat(root).catch(() => undefined);
  if (rootMetadata === undefined || !rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error('A successful build did not produce a regular dist directory.');
  }
  const files = [];
  await walkDirectory(root, root, files);
  if (files.length === 0) {
    throw new Error('A successful build produced an empty dist directory.');
  }
  return {
    files,
    totalBytes: files.reduce((sum, file) => safeAdd(sum, file.size_bytes), 0),
  };
}

async function sourceTreeManifest(root) {
  const files = [];
  await walkSourceTree(root, root, files);
  if (files.length === 0) {
    throw new Error('Source workspace is empty.');
  }
  return {
    files,
    totalBytes: files.reduce((sum, file) => safeAdd(sum, file.size_bytes), 0),
  };
}

async function walkSourceTree(root, current, files) {
  const entries = await readdir(current, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    if (
      ignoredSourceDirectories.has(entry.name) &&
      (entry.isDirectory() || entry.isSymbolicLink())
    ) {
      continue;
    }
    if (
      entry.name === '.DS_Store' ||
      entry.name.endsWith('.log') ||
      entry.name.endsWith('.tsbuildinfo')
    ) {
      continue;
    }
    const absolutePath = path.join(current, entry.name);
    const relativePath = path.relative(root, absolutePath).split(path.sep).join('/');
    if (!safeRelativePathPattern.test(relativePath)) {
      throw new Error('Source workspace contains an unsafe relative path.');
    }
    if (entry.isSymbolicLink()) {
      throw new Error('Source workspace must not contain symbolic links.');
    }
    if (entry.isDirectory()) {
      await walkSourceTree(root, absolutePath, files);
    } else if (entry.isFile()) {
      const metadata = await lstat(absolutePath);
      files.push({
        path: relativePath,
        size_bytes: metadata.size,
        sha256: await fileHash(absolutePath),
      });
    } else {
      throw new Error('Source workspace contains an unsupported filesystem object.');
    }
  }
}

async function walkDirectory(root, current, files) {
  const entries = await readdir(current, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const absolutePath = path.join(current, entry.name);
    const relativePath = path.relative(root, absolutePath).split(path.sep).join('/');
    if (!safeRelativePathPattern.test(relativePath)) {
      throw new Error('Build output contains an unsafe relative path.');
    }
    if (entry.isSymbolicLink()) {
      throw new Error('Build output must not contain symbolic links.');
    }
    if (entry.isDirectory()) {
      await walkDirectory(root, absolutePath, files);
    } else if (entry.isFile()) {
      const metadata = await lstat(absolutePath);
      if (!Number.isSafeInteger(metadata.size) || metadata.size < 0) {
        throw new Error('Build output contains an unsupported file size.');
      }
      files.push({
        path: relativePath,
        size_bytes: metadata.size,
        sha256: await fileHash(absolutePath),
      });
    } else {
      throw new Error('Build output contains an unsupported filesystem object.');
    }
  }
}

function runCommand(program, arguments_, options) {
  const startedAt = Date.now();
  const result = spawnSync(program, arguments_, {
    cwd: options.cwd,
    env: options.environment,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
    timeout: 15 * 60 * 1_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    exitCode: result.status,
    durationMs: Date.now() - startedAt,
    stdout: typeof result.stdout === 'string' ? result.stdout : '',
    stderr:
      typeof result.stderr === 'string'
        ? result.stderr
        : result.error === undefined
          ? ''
          : 'Command execution failed before a normal exit.\n',
  };
}

function childEnvironment() {
  const environment = {
    CI: 'true',
    NO_COLOR: '1',
  };
  for (const name of [
    'PATH',
    'HOME',
    'TMPDIR',
    'TMP',
    'TEMP',
    'PNPM_HOME',
    'COREPACK_HOME',
    'XDG_CACHE_HOME',
  ]) {
    const value = process.env[name];
    if (value !== undefined && value.length > 0) environment[name] = value;
  }
  return environment;
}

function validateProfiles(profiles) {
  if (!Array.isArray(profiles) || profiles.length === 0) {
    throw new Error('At least one release profile is required.');
  }
  const ids = new Set();
  for (const profile of profiles) {
    if (
      profile === null ||
      typeof profile !== 'object' ||
      !allowedCheckIds.has(profile.id) ||
      ids.has(profile.id) ||
      typeof profile.directory !== 'string' ||
      !safeRelativePathPattern.test(profile.directory) ||
      path.isAbsolute(profile.directory) ||
      !['build', 'source'].includes(profile.artifact_kind) ||
      !Array.isArray(profile.commands) ||
      profile.commands.length === 0
    ) {
      throw new Error('Release profiles are invalid.');
    }
    if (
      profile.preparation_commands !== undefined &&
      (!Array.isArray(profile.preparation_commands) ||
        profile.preparation_commands.length === 0)
    ) {
      throw new Error('Release profile preparation commands are invalid.');
    }
    for (const command of [
      ...(profile.preparation_commands ?? []),
      ...profile.commands,
    ]) {
      if (
        !Array.isArray(command) ||
        command.length !== 2 ||
        !['node', 'pnpm'].includes(command[0]) ||
        !Array.isArray(command[1]) ||
        command[1].some((argument) => typeof argument !== 'string')
      ) {
        throw new Error('Release profile commands are invalid.');
      }
    }
    ids.add(profile.id);
  }
}

async function assertProfileDirectory(directory, artifactKind) {
  const metadata = await lstat(directory).catch(() => undefined);
  if (metadata === undefined || !metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error('Release profile directory is unavailable.');
  }
  if (artifactKind !== 'build') return;
  await Promise.all([
    lstat(path.join(directory, 'package.json')),
    lstat(path.join(directory, 'pnpm-lock.yaml')),
  ]).catch(() => {
    throw new Error('Release package metadata is incomplete.');
  });
}

function safeWorkspacePath(root, relativePath) {
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(root, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Release package path escapes the workspace.');
  }
  return resolved;
}

function insidePath(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative.length === 0 || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function fileHash(filePath) {
  const metadata = await lstat(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error('Evidence hashing requires a regular file.');
  }
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) digest.update(chunk);
  return `sha256:${digest.digest('hex')}`;
}

async function writePrivateJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(filePath, 0o600);
}

function canonicalHash(value) {
  const digest = createHash('sha256');
  digest.update(JSON.stringify(canonicalize(value)));
  return `sha256:${digest.digest('hex')}`;
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

function safeAdd(left, right) {
  const total = left + right;
  if (!Number.isSafeInteger(total)) {
    throw new Error('Build output size exceeds the supported range.');
  }
  return total;
}

async function main() {
  if (process.argv.length !== 4) {
    process.stderr.write(
      'Usage: node scripts/release-evidence.mjs <new-output-directory> <execution-id>\n',
    );
    process.exitCode = 2;
    return;
  }
  try {
    const manifest = await collectReleaseEvidence({
      outputDirectory: process.argv[2],
      executionId: process.argv[3],
    });
    const status = manifest.checks.every((check) => check.status === 'PASS')
      ? 'PASS'
      : 'BLOCKED';
    process.stdout.write(
      `${JSON.stringify(
        {
          execution_id: manifest.execution_id,
          status,
          checks: manifest.checks.map((check) => ({
            id: check.id,
            status: check.status,
          })),
          collection_sha256: manifest.collection_sha256,
        },
        null,
        2,
      )}\n`,
    );
    if (status !== 'PASS') process.exitCode = 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown collection error.';
    process.stderr.write(`Release evidence collection failed: ${message}\n`);
    process.exitCode = 2;
  }
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  await main();
}
