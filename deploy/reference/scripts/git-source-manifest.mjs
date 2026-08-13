import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const safeRelativePathPattern = /^[A-Za-z0-9._/-]+$/;

export async function gitSourceManifest(workspaceRoot, { pathPrefix = null } = {}) {
  const root = path.resolve(workspaceRoot);
  const topLevel = path.resolve(runGit(root, ['rev-parse', '--show-toplevel']).trim());
  const [realRoot, realTopLevel] = await Promise.all([realpath(root), realpath(topLevel)]);
  if (realTopLevel !== realRoot) {
    throw new Error('Release workspace must be the root of a Git repository.');
  }
  const status = runGit(root, [
    'status',
    '--porcelain=v1',
    '-z',
    '--untracked-files=all',
    '--ignored=no',
  ]);
  if (status.length > 0) {
    throw new Error('Release source workspace must be a clean Git snapshot.');
  }

  const prefix = normalizePrefix(pathPrefix);
  const trackedPaths = zeroSeparated(runGit(root, ['ls-files', '-z']));
  const seen = new Set();
  const files = [];
  for (const relativePath of trackedPaths) {
    if (!safeRelativePath(relativePath) || seen.has(relativePath)) {
      throw new Error('Git source snapshot contains an unsafe or duplicate path.');
    }
    seen.add(relativePath);
    if (prefix !== null && !relativePath.startsWith(`${prefix}/`)) continue;
    const absolutePath = path.join(root, ...relativePath.split('/'));
    const metadata = await lstat(absolutePath).catch(() => undefined);
    if (
      metadata === undefined ||
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      !Number.isSafeInteger(metadata.size) ||
      metadata.size < 0
    ) {
      throw new Error('Git source snapshot must contain regular files only.');
    }
    files.push({
      path: prefix === null ? relativePath : relativePath.slice(prefix.length + 1),
      size_bytes: metadata.size,
      sha256: await fileHash(absolutePath),
    });
  }
  if (files.length === 0) {
    throw new Error(
      prefix === null
        ? 'Git source snapshot is empty.'
        : 'Release source profile contains no tracked files.',
    );
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  return {
    headCommit: runGit(root, ['rev-parse', 'HEAD']).trim(),
    files,
    totalBytes: files.reduce((total, file) => safeAdd(total, file.size_bytes), 0),
  };
}

function normalizePrefix(value) {
  if (value === null) return null;
  if (!safeRelativePath(value) || value.endsWith('/')) {
    throw new Error('Release source profile path is invalid.');
  }
  return value;
}

function safeRelativePath(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    safeRelativePathPattern.test(value) &&
    !path.posix.isAbsolute(value) &&
    path.posix.normalize(value) === value &&
    value !== '..' &&
    !value.startsWith('../')
  );
}

function zeroSeparated(value) {
  if (value.length === 0) return [];
  const values = value.split('\0');
  if (values.at(-1) === '') values.pop();
  return values;
}

function runGit(root, arguments_) {
  const result = spawnSync('git', arguments_, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error !== undefined || result.status !== 0) {
    throw new Error('Release workspace requires a readable Git repository.');
  }
  return result.stdout ?? '';
}

async function fileHash(filePath) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) digest.update(chunk);
  return `sha256:${digest.digest('hex')}`;
}

function safeAdd(left, right) {
  const total = left + right;
  if (!Number.isSafeInteger(total)) {
    throw new Error('Git source snapshot exceeds the supported size.');
  }
  return total;
}
