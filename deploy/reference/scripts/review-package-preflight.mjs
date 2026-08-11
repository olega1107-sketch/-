#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const maximumFileBytes = 10 * 1024 * 1024;
const maximumPackageBytes = 100 * 1024 * 1024;
const forbiddenDirectories = new Set([
  '.agents',
  '.codex',
  '.director-state',
  '.gateway-state',
  '.evidence',
  'coverage',
  'dist',
  'evidence',
  'node_modules',
  'review-output',
  'secrets',
]);
const forbiddenExtensions = new Set([
  '.cer',
  '.crt',
  '.der',
  '.jks',
  '.key',
  '.p12',
  '.pem',
  '.pfx',
]);
const secretPatterns = Object.freeze([
  {
    code: 'private_key_material',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    code: 'openai_api_key',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    code: 'github_access_token',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  },
  {
    code: 'aws_access_key',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    code: 'google_api_key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
  },
  {
    code: 'slack_access_token',
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/,
  },
  {
    code: 'database_url_credentials',
    pattern: /\bpostgres(?:ql)?:\/\/[^\s:/]+:[^\s@/]+@[^\s/]+/i,
  },
]);

export const requiredReviewFiles = Object.freeze([
  '.gitignore',
  'README.md',
  'REVIEWING.md',
  'docs/dirizhor/context.md',
  'docs/dirizhor/constitution.md',
  'docs/dirizhor/module-boundaries.md',
  'docs/dirizhor/mvp-scenarios.md',
  'docs/dirizhor/architecture-guardrails.md',
  'deploy/reference/target-conformance-runbook.md',
]);

export async function inspectReviewPackage({
  workspaceRoot = defaultWorkspaceRoot,
  gitCommand = runGit,
} = {}) {
  const root = await realpath(path.resolve(workspaceRoot));
  const status = gitCommand(root, [
    'status',
    '--porcelain=v1',
    '--untracked-files=all',
    '-z',
  ]);
  const trackedResult = gitCommand(root, ['ls-files', '-z']);
  const headResult = gitCommand(root, ['rev-parse', '--verify', 'HEAD'], {
    allowFailure: true,
  });
  const headCommit =
    headResult.status === 0 && /^(?:[0-9a-f]{40}|[0-9a-f]{64})\n?$/.test(headResult.stdout)
      ? headResult.stdout.trim()
      : null;
  const trackedFiles = zeroSeparated(trackedResult.stdout);
  const trackedSet = new Set(trackedFiles);
  const issues = [];

  if (status.stdout.length > 0) {
    issues.push({ code: 'git_worktree_dirty', path: null });
  }
  if (trackedFiles.length === 0) {
    issues.push({ code: 'git_snapshot_empty', path: null });
  }
  if (headCommit === null) {
    issues.push({ code: 'git_head_missing', path: null });
  }
  if (new Set(trackedFiles).size !== trackedFiles.length) {
    issues.push({ code: 'git_tracked_path_duplicate', path: null });
  }
  for (const required of requiredReviewFiles) {
    if (!trackedSet.has(required)) {
      issues.push({ code: 'required_entrypoint_missing', path: required });
    }
  }

  let totalBytes = 0;
  const textDocuments = new Map();
  for (const relativePath of trackedFiles) {
    if (!safeRelativePath(relativePath)) {
      issues.push({ code: 'tracked_path_invalid', path: relativePath });
      continue;
    }
    if (forbiddenPath(relativePath)) {
      issues.push({ code: 'forbidden_tracked_path', path: relativePath });
    }
    const absolutePath = path.join(root, ...relativePath.split('/'));
    const metadata = await lstat(absolutePath);
    if (metadata.isSymbolicLink()) {
      issues.push({ code: 'tracked_symlink_forbidden', path: relativePath });
      continue;
    }
    if (!metadata.isFile()) {
      issues.push({ code: 'tracked_non_file_forbidden', path: relativePath });
      continue;
    }
    if (metadata.size > maximumFileBytes) {
      issues.push({ code: 'tracked_file_too_large', path: relativePath });
      continue;
    }
    totalBytes += metadata.size;
    if (totalBytes > maximumPackageBytes) {
      issues.push({ code: 'review_package_too_large', path: null });
      break;
    }
    const bytes = await readFile(absolutePath);
    if (bytes.includes(0)) continue;
    const text = bytes.toString('utf8');
    textDocuments.set(relativePath, text);
    for (const secret of secretPatterns) {
      if (secret.pattern.test(text)) {
        issues.push({ code: secret.code, path: relativePath });
      }
    }
  }

  for (const [relativePath, text] of textDocuments) {
    if (!relativePath.endsWith('.md')) continue;
    for (const target of markdownTargets(text)) {
      const resolved = resolveMarkdownTarget(relativePath, target);
      if (resolved === null) continue;
      const trackedDirectory = trackedFiles.some((candidate) =>
        candidate.startsWith(`${resolved.replace(/\/$/, '')}/`),
      );
      if (!safeRelativePath(resolved) || (!trackedSet.has(resolved) && !trackedDirectory)) {
        issues.push({ code: 'markdown_local_link_missing', path: relativePath });
      }
    }
  }

  const uniqueIssues = uniqueSortedIssues(issues);
  const checks = [
    check('git.clean_snapshot', uniqueIssues, [
      'git_worktree_dirty',
      'git_snapshot_empty',
      'git_head_missing',
      'git_tracked_path_duplicate',
      'tracked_path_invalid',
    ]),
    check('package.required_entrypoints', uniqueIssues, [
      'required_entrypoint_missing',
    ]),
    check('package.bounded_regular_files', uniqueIssues, [
      'tracked_symlink_forbidden',
      'tracked_non_file_forbidden',
      'tracked_file_too_large',
      'review_package_too_large',
    ]),
    check('package.forbidden_paths', uniqueIssues, ['forbidden_tracked_path']),
    check(
      'package.high_confidence_secret_scan',
      uniqueIssues,
      secretPatterns.map((item) => item.code),
    ),
    check('package.local_markdown_links', uniqueIssues, [
      'markdown_local_link_missing',
    ]),
  ];
  const report = {
    schema_version: 1,
    status: checks.every((item) => item.status === 'PASS') ? 'PASS' : 'FAIL',
    head_commit: headCommit,
    tracked_file_count: trackedFiles.length,
    tracked_bytes: totalBytes,
    checks,
    issues: uniqueIssues,
  };
  return { ...report, report_sha256: canonicalHash(report) };
}

function runGit(root, args, options = {}) {
  const result = spawnSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error !== undefined) {
    throw new Error('Git could not be executed for review-package preflight.');
  }
  if (result.status !== 0 && options.allowFailure !== true) {
    throw new Error('Review-package preflight requires a readable Git repository.');
  }
  return {
    status: result.status,
    stdout: result.stdout ?? '',
  };
}

function zeroSeparated(value) {
  if (value.length === 0) return [];
  const values = value.split('\0');
  if (values.at(-1) === '') values.pop();
  return values;
}

function safeRelativePath(value) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.includes('\0') ||
    value.includes('\\') ||
    path.posix.isAbsolute(value)
  ) {
    return false;
  }
  const normalized = path.posix.normalize(value);
  return normalized === value && normalized !== '..' && !normalized.startsWith('../');
}

function forbiddenPath(relativePath) {
  const parts = relativePath.split('/');
  const basename = parts.at(-1).toLowerCase();
  const extension = path.posix.extname(basename);
  return (
    parts.some((part) => forbiddenDirectories.has(part.toLowerCase())) ||
    (basename.startsWith('.env') && basename !== '.env.example') ||
    basename === '.ds_store' ||
    basename === 'kubeconfig' ||
    basename.startsWith('kubeconfig.') ||
    forbiddenExtensions.has(extension) ||
    basename.endsWith('-evidence.json') ||
    basename === 'oci-release-failed.json' ||
    basename === 'render-evidence.json'
  );
}

function markdownTargets(text) {
  return [...text.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)].map((match) => match[1].trim());
}

function resolveMarkdownTarget(sourcePath, target) {
  const unwrapped = target.startsWith('<') && target.endsWith('>')
    ? target.slice(1, -1)
    : target;
  const withoutFragment = unwrapped.split('#', 1)[0];
  if (
    withoutFragment.length === 0 ||
    /^(?:https?:|mailto:)/i.test(withoutFragment)
  ) {
    return null;
  }
  let decoded;
  try {
    decoded = decodeURIComponent(withoutFragment);
  } catch {
    return '__invalid_encoded_link__';
  }
  if (path.posix.isAbsolute(decoded)) return decoded;
  return path.posix.normalize(path.posix.join(path.posix.dirname(sourcePath), decoded));
}

function uniqueSortedIssues(issues) {
  const unique = new Map();
  for (const issue of issues) {
    unique.set(`${issue.code}\0${issue.path ?? ''}`, issue);
  }
  return [...unique.values()].sort((left, right) =>
    `${left.code}\0${left.path ?? ''}`.localeCompare(`${right.code}\0${right.path ?? ''}`),
  );
}

function check(id, issues, codes) {
  const codeSet = new Set(codes);
  const issueCount = issues.filter((issue) => codeSet.has(issue.code)).length;
  return {
    id,
    status: issueCount === 0 ? 'PASS' : 'FAIL',
    issue_count: issueCount,
  };
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
  if (argv.length > 1) {
    throw new Error(
      'Usage: node deploy/reference/scripts/review-package-preflight.mjs [workspace-root]',
    );
  }
  const report = await inspectReviewPackage({
    ...(argv[0] === undefined ? {} : { workspaceRoot: argv[0] }),
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.status === 'PASS' ? 0 : 1;
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : 'Review-package preflight failed.';
    process.stderr.write(`Review-package preflight failed: ${message}\n`);
    process.exitCode = 2;
  });
}
