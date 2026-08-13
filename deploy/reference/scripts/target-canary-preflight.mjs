#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, chmod, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  targetCanaryMaterialSpecifications,
  validateTargetCanaryConfig,
} from './target-canary.mjs';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const minimumNodeVersion = Object.freeze([22, 18, 0]);
const maximumMaterialBytes = 1024 * 1024;
const protectedModes = new Set([0o400, 0o440, 0o600, 0o640]);

export async function runTargetCanaryPreflight(config, dependencies = {}) {
  validateTargetCanaryConfig(config);
  const runtime = {
    now: dependencies.now ?? (() => new Date()),
    nodeVersion: dependencies.nodeVersion ?? process.versions.node,
    access: dependencies.access ?? access,
    lstat: dependencies.lstat ?? lstat,
  };
  const checks = [nodeVersionCheck(runtime.nodeVersion)];
  for (const specification of targetCanaryMaterialSpecifications(config)) {
    checks.push(await materialCheck(specification, runtime));
  }

  const report = {
    schema_version: 1,
    execution_id: config.execution_id,
    environment: config.environment,
    checked_at: isoNow(runtime.now),
    status: checks.every((check) => check.status === 'PASS') ? 'PASS' : 'BLOCKED',
    config_sha256: canonicalHash(config),
    checks,
    limitations: [
      'Does not read or validate material contents.',
      'Does not contact DNS, TLS endpoints, the IdP, Director, or Gateway.',
      'Does not replace certificate preflight or the live target canary.',
    ],
  };
  return { ...report, report_sha256: canonicalHash(report) };
}

export async function writeTargetCanaryPreflight({
  config,
  outputDirectory,
  workspaceRoot = defaultWorkspaceRoot,
  dependencies,
}) {
  validateTargetCanaryConfig(config);
  const resolvedOutput = path.resolve(outputDirectory);
  const resolvedWorkspace = path.resolve(workspaceRoot);
  if (isWithin(resolvedOutput, resolvedWorkspace)) {
    throw new Error('Target canary preflight output directory must be outside the source workspace.');
  }
  await mkdir(resolvedOutput, { mode: 0o700 });
  await chmod(resolvedOutput, 0o700);
  const report = await runTargetCanaryPreflight(config, dependencies);
  const reportPath = path.join(resolvedOutput, 'target-canary-preflight.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(reportPath, 0o600);
  return { report, reportPath };
}

function nodeVersionCheck(value) {
  const version = parseNodeVersion(value);
  if (version === null || compareVersion(version, minimumNodeVersion) < 0) {
    return blockedCheck('runtime.node', 'node_version_unsupported');
  }
  return {
    id: 'runtime.node',
    status: 'PASS',
    observations: { version: version.join('.'), minimum: minimumNodeVersion.join('.') },
    reason_code: null,
  };
}

async function materialCheck(specification, runtime) {
  const id = `material.${specification.label}`;
  let metadata;
  try {
    metadata = await runtime.lstat(specification.path);
  } catch {
    return blockedCheck(id, 'material_unreadable');
  }
  if (metadata.isSymbolicLink()) {
    return blockedCheck(id, 'material_symlink_forbidden');
  }
  if (!metadata.isFile()) {
    return blockedCheck(id, 'material_not_regular_file');
  }
  const mode = metadata.mode & 0o777;
  if (
    (specification.protected && !protectedModes.has(mode)) ||
    (!specification.protected && (mode & 0o022) !== 0)
  ) {
    return blockedCheck(id, 'material_permissions');
  }
  if (!Number.isSafeInteger(metadata.size) || metadata.size < 1 || metadata.size > maximumMaterialBytes) {
    return blockedCheck(id, 'material_size');
  }
  try {
    await runtime.access(specification.path, constants.R_OK);
  } catch {
    return blockedCheck(id, 'material_unreadable');
  }
  return {
    id,
    status: 'PASS',
    observations: {
      kind: specification.kind,
      protected: specification.protected,
      mode: modeString(mode),
    },
    reason_code: null,
  };
}

function blockedCheck(id, reasonCode) {
  return { id, status: 'BLOCKED', observations: null, reason_code: reasonCode };
}

function parseNodeVersion(value) {
  if (typeof value !== 'string') return null;
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(value);
  if (match === null) return null;
  const version = match.slice(1).map(Number);
  return version.every(Number.isSafeInteger) ? version : null;
}

function compareVersion(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function isoNow(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error('Target canary preflight clock returned an invalid date.');
  }
  return value.toISOString();
}

function modeString(mode) {
  return mode.toString(8).padStart(4, '0');
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

function isWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function main(argv) {
  if (argv.length !== 2) {
    throw new Error(
      'Usage: node scripts/target-canary-preflight.mjs <new-output-directory> <config.json>',
    );
  }
  let config;
  try {
    config = JSON.parse(await readFile(argv[1], 'utf8'));
  } catch {
    throw new Error('Target canary config could not be read.');
  }
  const result = await writeTargetCanaryPreflight({
    config,
    outputDirectory: argv[0],
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        status: result.report.status,
        execution_id: result.report.execution_id,
        report_sha256: result.report.report_sha256,
        pass: result.report.checks.filter((check) => check.status === 'PASS').length,
        blocked: result.report.checks.filter((check) => check.status === 'BLOCKED').length,
        report_file: path.basename(result.reportPath),
      },
      null,
      2,
    )}\n`,
  );
  process.exitCode = result.report.status === 'PASS' ? 0 : 1;
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : 'Target canary preflight failed.';
    process.stderr.write(`Target canary preflight failed: ${message}\n`);
    process.exitCode = 2;
  });
}
