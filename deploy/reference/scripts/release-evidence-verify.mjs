import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  releaseEvidencePnpmVersion,
  releaseProfiles,
} from './release-evidence.mjs';
import { gitSourceManifest } from './git-source-manifest.mjs';

const digestPattern = /^sha256:[0-9a-f]{64}$/;
const executionIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;
const safeRelativePathPattern = /^[A-Za-z0-9._/-]+$/;
const maximumJsonBytes = 32 * 1024 * 1024;
const maximumManifestFiles = 100_000;
const profileById = new Map(
  releaseProfiles.map((profile) => [profile.id, profile]),
);

export async function verifyReleaseEvidence({
  evidenceDirectory,
  workspaceRoot,
}) {
  if (typeof evidenceDirectory !== 'string' || evidenceDirectory.length === 0) {
    throw new Error('A release evidence directory is required.');
  }
  if (
    workspaceRoot !== undefined &&
    (typeof workspaceRoot !== 'string' || workspaceRoot.length === 0)
  ) {
    throw new Error('Workspace root must be a non-empty path when provided.');
  }

  const evidenceRoot = path.resolve(evidenceDirectory);
  await assertPrivateDirectory(evidenceRoot);
  const manifest = await readPrivateJson(
    path.join(evidenceRoot, 'release-evidence.json'),
    'release evidence manifest',
  );
  const normalized = validateReleaseManifest(manifest);
  const expectedFiles = new Set(['release-evidence.json', normalized.source.manifest_file]);

  const sourceDocument = await readPrivateJson(
    evidencePath(evidenceRoot, normalized.source.manifest_file),
    'source manifest',
  );
  const sourceFiles = validateSourceManifest(sourceDocument, normalized.source);

  const checkResults = [];
  const artifactDocuments = new Map();
  for (const check of normalized.checks) {
    expectedFiles.add(check.log_file);
    const logPath = evidencePath(evidenceRoot, check.log_file);
    await assertPrivateRegularFile(logPath, 'release log');
    if ((await fileHash(logPath)) !== check.log_sha256) {
      throw new Error(`Release log hash mismatch for ${check.id}.`);
    }

    let artifactFiles = null;
    if (check.status === 'PASS') {
      expectedFiles.add(check.artifact.manifest_file);
      const artifactDocument = await readPrivateJson(
        evidencePath(evidenceRoot, check.artifact.manifest_file),
        `${check.id} artifact manifest`,
      );
      artifactFiles = validateArtifactManifest(
        artifactDocument,
        check.artifact,
        profileById.get(check.id),
      );
      artifactDocuments.set(check.id, artifactDocument);
    }
    checkResults.push({
      id: check.id,
      status: check.status,
      log_sha256: check.log_sha256,
      artifact_manifest_sha256: check.artifact?.manifest_sha256 ?? null,
      artifact_file_count: artifactFiles?.length ?? 0,
    });
  }
  await assertExactEvidenceFiles(evidenceRoot, expectedFiles);

  let workspace = null;
  if (workspaceRoot !== undefined) {
    workspace = await verifyWorkspace(
      path.resolve(workspaceRoot),
      normalized,
      sourceDocument,
      artifactDocuments,
    );
  }

  return {
    schema_version: 1,
    execution_id: normalized.execution_id,
    release_gate: normalized.checks.every((check) => check.status === 'PASS')
      ? 'PASS'
      : 'BLOCKED',
    verification_scope:
      workspace === null ? 'evidence_integrity' : 'evidence_and_workspace',
    toolchain: { ...normalized.toolchain },
    source: {
      file_count: sourceFiles.length,
      tree_sha256: normalized.source.tree_sha256,
      workspace_match: workspace === null ? 'NOT_RUN' : 'PASS',
    },
    checks: checkResults,
    evidence_file_count: expectedFiles.size,
    collection_sha256: normalized.collection_sha256,
    workspace,
  };
}

function validateReleaseManifest(manifest) {
  assertObject(manifest, 'release evidence manifest');
  assertExactKeys(
    manifest,
    [
      'schema_version',
      'execution_id',
      'started_at',
      'completed_at',
      'toolchain',
      'source',
      'checks',
      'collection_sha256',
    ],
    'release evidence manifest',
  );
  if (manifest.schema_version !== 1) {
    throw new Error('Release evidence schema version is unsupported.');
  }
  if (
    typeof manifest.execution_id !== 'string' ||
    !executionIdPattern.test(manifest.execution_id) ||
    manifest.execution_id.startsWith('replace-')
  ) {
    throw new Error('Release evidence execution ID is invalid.');
  }
  const startedAt = timestamp(manifest.started_at, 'started_at');
  const completedAt = timestamp(manifest.completed_at, 'completed_at');
  if (completedAt < startedAt) {
    throw new Error('Release evidence completion precedes its start.');
  }

  assertObject(manifest.toolchain, 'release toolchain');
  assertExactKeys(manifest.toolchain, ['pnpm_version'], 'release toolchain');
  if (manifest.toolchain.pnpm_version !== releaseEvidencePnpmVersion) {
    throw new Error(
      `Release evidence requires pnpm ${releaseEvidencePnpmVersion}.`,
    );
  }

  const source = validateSourceReference(manifest.source);
  const checks = validateChecks(
    manifest.checks,
    manifest.execution_id,
    startedAt,
    completedAt,
  );
  assertDigest(manifest.collection_sha256, 'collection_sha256');
  const { collection_sha256: _claimedHash, ...withoutHash } = manifest;
  if (canonicalHash(withoutHash) !== manifest.collection_sha256) {
    throw new Error('Release evidence collection hash mismatch.');
  }
  return { ...manifest, source, checks };
}

function validateSourceReference(source) {
  assertObject(source, 'source reference');
  assertExactKeys(
    source,
    [
      'manifest_file',
      'manifest_sha256',
      'file_count',
      'total_bytes',
      'tree_sha256',
    ],
    'source reference',
  );
  if (source.manifest_file !== 'source-manifest.json') {
    throw new Error('Release evidence source manifest filename is invalid.');
  }
  assertDigest(source.manifest_sha256, 'source manifest hash');
  assertDigest(source.tree_sha256, 'source tree hash');
  assertCount(source.file_count, 'source file count');
  assertCount(source.total_bytes, 'source total bytes');
  return source;
}

function validateChecks(checks, executionId, startedAt, completedAt) {
  if (!Array.isArray(checks) || checks.length !== releaseProfiles.length) {
    throw new Error('Release evidence must contain every release profile.');
  }
  return checks.map((check, index) => {
    const profile = releaseProfiles[index];
    assertObject(check, 'release check');
    assertExactKeys(
      check,
      [
        'id',
        'status',
        'observed_at',
        'evidence_ref',
        'log_file',
        'log_sha256',
        'commands',
        'artifact',
      ],
      'release check',
    );
    if (check.id !== profile.id || !['PASS', 'FAIL'].includes(check.status)) {
      throw new Error('Release checks are unknown, reordered or invalid.');
    }
    const observedAt = timestamp(check.observed_at, `${check.id} observed_at`);
    if (observedAt < startedAt || observedAt > completedAt) {
      throw new Error(`Release check timestamp is outside the collection for ${check.id}.`);
    }
    const slug = profile.id.replaceAll('.', '-');
    if (
      check.evidence_ref !== `artifact:${executionId}/${check.id}` ||
      check.log_file !== `${slug}.log`
    ) {
      throw new Error(`Release evidence references are invalid for ${check.id}.`);
    }
    assertDigest(check.log_sha256, `${check.id} log hash`);
    validateCommands(check.commands, profile, check.status);
    if (check.status === 'PASS') {
      validateArtifactReference(check.artifact, profile, slug);
    } else if (check.artifact !== null) {
      throw new Error(`Failed release check cannot claim an artifact for ${check.id}.`);
    }
    return check;
  });
}

function validateCommands(commands, profile, status) {
  const expected = [
    ...(profile.preparation_commands ?? []),
    ...profile.commands,
  ];
  if (
    !Array.isArray(commands) ||
    commands.length === 0 ||
    commands.length > expected.length ||
    (status === 'PASS' && commands.length !== expected.length)
  ) {
    throw new Error(`Release command sequence is incomplete for ${profile.id}.`);
  }
  commands.forEach((command, index) => {
    assertObject(command, 'release command');
    assertExactKeys(
      command,
      ['program', 'arguments', 'exit_code', 'duration_ms'],
      'release command',
    );
    const [expectedProgram, expectedArguments] = expected[index];
    if (
      command.program !== expectedProgram ||
      !Array.isArray(command.arguments) ||
      JSON.stringify(command.arguments) !== JSON.stringify(expectedArguments)
    ) {
      throw new Error(`Release command sequence differs for ${profile.id}.`);
    }
    if (
      command.exit_code !== null &&
      (!Number.isSafeInteger(command.exit_code) || command.exit_code < 0)
    ) {
      throw new Error(`Release command exit code is invalid for ${profile.id}.`);
    }
    assertCount(command.duration_ms, `${profile.id} command duration`);
    const shouldSucceed = status === 'PASS' || index < commands.length - 1;
    if (shouldSucceed ? command.exit_code !== 0 : command.exit_code === 0) {
      throw new Error(`Release command result contradicts ${status} for ${profile.id}.`);
    }
  });
}

function validateArtifactReference(artifact, profile, slug) {
  assertObject(artifact, `${profile.id} artifact reference`);
  const commonKeys = ['manifest_file', 'manifest_sha256'];
  const buildKeys = [
    ...commonKeys,
    'package_json_sha256',
    'lockfile_sha256',
    'build_file_count',
    'build_total_bytes',
    'build_tree_sha256',
  ];
  const sourceKeys = [
    'artifact_kind',
    ...commonKeys,
    'source_file_count',
    'source_total_bytes',
    'source_tree_sha256',
  ];
  assertExactKeys(
    artifact,
    profile.artifact_kind === 'build' ? buildKeys : sourceKeys,
    `${profile.id} artifact reference`,
  );
  if (artifact.manifest_file !== `${slug}-artifact.json`) {
    throw new Error(`Artifact manifest filename is invalid for ${profile.id}.`);
  }
  assertDigest(artifact.manifest_sha256, `${profile.id} artifact manifest hash`);
  if (profile.artifact_kind === 'build') {
    assertDigest(artifact.package_json_sha256, `${profile.id} package hash`);
    assertDigest(artifact.lockfile_sha256, `${profile.id} lockfile hash`);
    assertCount(artifact.build_file_count, `${profile.id} build file count`);
    assertCount(artifact.build_total_bytes, `${profile.id} build total bytes`);
    assertDigest(artifact.build_tree_sha256, `${profile.id} build tree hash`);
  } else {
    if (artifact.artifact_kind !== 'source') {
      throw new Error(`Artifact kind is invalid for ${profile.id}.`);
    }
    assertCount(artifact.source_file_count, `${profile.id} source file count`);
    assertCount(artifact.source_total_bytes, `${profile.id} source total bytes`);
    assertDigest(artifact.source_tree_sha256, `${profile.id} source tree hash`);
  }
}

function validateSourceManifest(document, reference) {
  assertObject(document, 'source manifest');
  assertExactKeys(
    document,
    ['schema_version', 'file_count', 'total_bytes', 'tree_sha256', 'files'],
    'source manifest',
  );
  if (document.schema_version !== 1) {
    throw new Error('Source manifest schema version is unsupported.');
  }
  const files = validateFileEntries(document.files, 'source manifest');
  assertCount(document.file_count, 'source file count');
  assertCount(document.total_bytes, 'source total bytes');
  assertDigest(document.tree_sha256, 'source tree hash');
  const totalBytes = files.reduce((total, file) => safeAdd(total, file.size_bytes), 0);
  if (
    document.file_count !== files.length ||
    document.total_bytes !== totalBytes ||
    document.tree_sha256 !== canonicalHash(files)
  ) {
    throw new Error('Source tree summary does not match its file list.');
  }
  if (
    canonicalHash(document) !== reference.manifest_sha256 ||
    document.file_count !== reference.file_count ||
    document.total_bytes !== reference.total_bytes ||
    document.tree_sha256 !== reference.tree_sha256
  ) {
    throw new Error('Source manifest does not match the release evidence reference.');
  }
  return files;
}

function validateArtifactManifest(document, reference, profile) {
  assertObject(document, `${profile.id} artifact manifest`);
  const files = validateFileEntries(
    document.files,
    `${profile.id} artifact manifest`,
  );
  if (profile.artifact_kind === 'build') {
    assertExactKeys(
      document,
      [
        'schema_version',
        'package_json_sha256',
        'lockfile_sha256',
        'build_file_count',
        'build_total_bytes',
        'build_tree_sha256',
        'files',
      ],
      `${profile.id} artifact manifest`,
    );
    if (document.schema_version !== 1) {
      throw new Error(`Artifact schema version is unsupported for ${profile.id}.`);
    }
    validateTreeSummary(document, files, 'build');
    for (const key of [
      'package_json_sha256',
      'lockfile_sha256',
      'build_file_count',
      'build_total_bytes',
      'build_tree_sha256',
    ]) {
      if (document[key] !== reference[key]) {
        throw new Error(`Artifact summary mismatch for ${profile.id}.`);
      }
    }
  } else {
    assertExactKeys(
      document,
      [
        'schema_version',
        'artifact_kind',
        'source_file_count',
        'source_total_bytes',
        'source_tree_sha256',
        'files',
      ],
      `${profile.id} artifact manifest`,
    );
    if (document.schema_version !== 1 || document.artifact_kind !== 'source') {
      throw new Error(`Artifact schema or kind is invalid for ${profile.id}.`);
    }
    validateTreeSummary(document, files, 'source');
    for (const key of [
      'source_file_count',
      'source_total_bytes',
      'source_tree_sha256',
    ]) {
      if (document[key] !== reference[key]) {
        throw new Error(`Artifact summary mismatch for ${profile.id}.`);
      }
    }
  }
  if (canonicalHash(document) !== reference.manifest_sha256) {
    throw new Error(`Artifact manifest hash mismatch for ${profile.id}.`);
  }
  return files;
}

function validateFileEntries(files, label) {
  if (!Array.isArray(files) || files.length === 0 || files.length > maximumManifestFiles) {
    throw new Error(`${label} must contain a bounded non-empty file list.`);
  }
  const seenPaths = new Set();
  return files.map((file) => {
    assertObject(file, `${label} file`);
    assertExactKeys(file, ['path', 'size_bytes', 'sha256'], `${label} file`);
    if (
      typeof file.path !== 'string' ||
      !safeRelativePathPattern.test(file.path) ||
      path.posix.isAbsolute(file.path) ||
      file.path.split('/').includes('..') ||
      file.path.includes('//') ||
      file.path === '.' ||
      seenPaths.has(file.path)
    ) {
      throw new Error(`${label} contains an unsafe or duplicate path.`);
    }
    seenPaths.add(file.path);
    assertCount(file.size_bytes, `${label} file size`);
    assertDigest(file.sha256, `${label} file hash`);
    return file;
  });
}

function validateTreeSummary(document, files, prefix) {
  const fileCountKey = `${prefix}_file_count`;
  const totalBytesKey = `${prefix}_total_bytes`;
  const treeHashKey = `${prefix}_tree_sha256`;
  assertCount(document[fileCountKey], `${prefix} file count`);
  assertCount(document[totalBytesKey], `${prefix} total bytes`);
  assertDigest(document[treeHashKey], `${prefix} tree hash`);
  const totalBytes = files.reduce(
    (total, file) => safeAdd(total, file.size_bytes),
    0,
  );
  if (
    document[fileCountKey] !== files.length ||
    document[totalBytesKey] !== totalBytes ||
    document[treeHashKey] !== canonicalHash(files)
  ) {
    throw new Error(`${prefix} tree summary does not match its file list.`);
  }
}

async function verifyWorkspace(
  root,
  manifest,
  sourceDocument,
  artifactDocuments,
) {
  await assertRegularDirectory(root, 'release workspace');
  const currentSource = await gitSourceManifest(root);
  if (canonicalHash(currentSource.files) !== sourceDocument.tree_sha256) {
    throw new Error('Workspace source tree does not match the release evidence.');
  }
  const profiles = [];
  for (const check of manifest.checks) {
    if (check.status !== 'PASS') {
      profiles.push({ id: check.id, artifact_match: 'NOT_RUN' });
      continue;
    }
    const profile = profileById.get(check.id);
    const workingDirectory = safeWorkspacePath(root, profile.directory);
    const artifactDocument = artifactDocuments.get(check.id);
    if (profile.artifact_kind === 'build') {
      const [packageHash, lockfileHash, buildTree] = await Promise.all([
        fileHash(path.join(workingDirectory, 'package.json')),
        fileHash(path.join(workingDirectory, 'pnpm-lock.yaml')),
        directoryManifest(path.join(workingDirectory, 'dist'), 'build output'),
      ]);
      if (
        packageHash !== artifactDocument.package_json_sha256 ||
        lockfileHash !== artifactDocument.lockfile_sha256 ||
        canonicalHash(buildTree.files) !== artifactDocument.build_tree_sha256
      ) {
        throw new Error(
          `Workspace artifact does not match release evidence for ${check.id}.`,
        );
      }
      profiles.push({
        id: check.id,
        artifact_match: 'PASS',
        file_count: buildTree.files.length,
        tree_sha256: artifactDocument.build_tree_sha256,
      });
    } else {
      const sourceTree = await gitSourceManifest(root, {
        pathPrefix: profile.directory,
      });
      if (canonicalHash(sourceTree.files) !== artifactDocument.source_tree_sha256) {
        throw new Error(
          `Workspace artifact does not match release evidence for ${check.id}.`,
        );
      }
      profiles.push({
        id: check.id,
        artifact_match: 'PASS',
        file_count: sourceTree.files.length,
        tree_sha256: artifactDocument.source_tree_sha256,
      });
    }
  }
  return {
    source_file_count: currentSource.files.length,
    source_tree_sha256: sourceDocument.tree_sha256,
    profiles,
  };
}

async function directoryManifest(directory, label) {
  await assertRegularDirectory(directory, label);
  const files = [];
  await walkDirectory(directory, directory, files, label);
  if (files.length === 0) throw new Error(`${label} is empty.`);
  return {
    files,
    totalBytes: files.reduce(
      (total, file) => safeAdd(total, file.size_bytes),
      0,
    ),
  };
}

async function walkDirectory(root, current, files, label) {
  const entries = await readdir(current, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const absolutePath = path.join(current, entry.name);
    const relativePath = path.relative(root, absolutePath).split(path.sep).join('/');
    if (!safeRelativePathPattern.test(relativePath)) {
      throw new Error(`${label} contains an unsafe relative path.`);
    }
    if (entry.isSymbolicLink()) {
      throw new Error(`${label} must not contain symbolic links.`);
    }
    if (entry.isDirectory()) {
      await walkDirectory(root, absolutePath, files, label);
    } else if (entry.isFile()) {
      const metadata = await lstat(absolutePath);
      files.push({
        path: relativePath,
        size_bytes: metadata.size,
        sha256: await fileHash(absolutePath),
      });
    } else {
      throw new Error(`${label} contains an unsupported filesystem object.`);
    }
  }
}

async function assertExactEvidenceFiles(root, expectedFiles) {
  const entries = await readdir(root, { withFileTypes: true });
  const actual = entries.map((entry) => entry.name).sort();
  const expected = [...expectedFiles].sort();
  if (
    entries.some((entry) => !entry.isFile() || entry.isSymbolicLink()) ||
    JSON.stringify(actual) !== JSON.stringify(expected)
  ) {
    throw new Error(
      'Evidence directory contains missing, extra or unsupported files.',
    );
  }
  for (const name of actual) {
    await assertPrivateRegularFile(path.join(root, name), 'evidence file');
  }
}

function safeWorkspacePath(root, relativePath) {
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(root, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Release profile path escapes the workspace.');
  }
  return resolved;
}

function evidencePath(root, filename) {
  if (
    typeof filename !== 'string' ||
    !safeRelativePathPattern.test(filename) ||
    filename.includes('/') ||
    filename === '.' ||
    filename === '..'
  ) {
    throw new Error('Evidence filename is unsafe.');
  }
  return path.join(root, filename);
}

async function readPrivateJson(filePath, label) {
  await assertPrivateRegularFile(filePath, label);
  const metadata = await lstat(filePath);
  if (metadata.size > maximumJsonBytes) {
    throw new Error(`${label} exceeds the supported size.`);
  }
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

async function assertPrivateDirectory(directory) {
  await assertRegularDirectory(directory, 'release evidence directory');
  const metadata = await lstat(directory);
  if ((metadata.mode & 0o077) !== 0) {
    throw new Error(
      'Release evidence directory must not grant group or other access.',
    );
  }
}

async function assertRegularDirectory(directory, label) {
  const metadata = await lstat(directory).catch(() => undefined);
  if (metadata === undefined || !metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular directory.`);
  }
}

async function assertPrivateRegularFile(filePath, label) {
  const metadata = await lstat(filePath).catch(() => undefined);
  if (metadata === undefined || !metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file.`);
  }
  if ((metadata.mode & 0o077) !== 0) {
    throw new Error(`${label} must not grant group or other access.`);
  }
}

async function fileHash(filePath) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) digest.update(chunk);
  return `sha256:${digest.digest('hex')}`;
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

function timestamp(value, label) {
  if (typeof value !== 'string') throw new Error(`${label} must be a timestamp.`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp.`);
  }
  return milliseconds;
}

function assertObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
}

function assertExactKeys(value, keys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} contains missing or unsupported fields.`);
  }
}

function assertDigest(value, label) {
  if (typeof value !== 'string' || !digestPattern.test(value)) {
    throw new Error(`${label} must be a SHA-256 digest.`);
  }
}

function assertCount(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer.`);
  }
}

function safeAdd(left, right) {
  const total = left + right;
  if (!Number.isSafeInteger(total)) {
    throw new Error('Manifest size exceeds the supported range.');
  }
  return total;
}

async function main() {
  if (process.argv.length < 3 || process.argv.length > 4) {
    process.stderr.write(
      'Usage: node scripts/release-evidence-verify.mjs <evidence-directory> [builder-workspace]\n',
    );
    process.exitCode = 2;
    return;
  }
  try {
    const report = await verifyReleaseEvidence({
      evidenceDirectory: process.argv[2],
      workspaceRoot: process.argv[3],
    });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (report.release_gate !== 'PASS') process.exitCode = 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown verification error.';
    process.stderr.write(`Release evidence verification failed: ${message}\n`);
    process.exitCode = 2;
  }
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  await main();
}
