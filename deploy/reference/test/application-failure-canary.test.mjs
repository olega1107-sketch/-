import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  runApplicationFailureCanary,
  validateApplicationFailureCanaryConfig,
  writeApplicationFailureCanaryEvidence,
} from '../scripts/application-failure-canary.mjs';

test('config validator pins the destructive target and external evidence', () => {
  const config = validConfig();
  assert.doesNotThrow(() => validateApplicationFailureCanaryConfig(config));
  assert.throws(
    () =>
      validateApplicationFailureCanaryConfig({
        ...config,
        kubernetes: { ...config.kubernetes, kubectl_path: 'kubectl' },
      }),
    /absolute path/,
  );
  assert.throws(
    () =>
      validateApplicationFailureCanaryConfig({
        ...config,
        kubernetes: { ...config.kubernetes, kubectl_client_version: 'v1.34' },
      }),
    /exact supported/,
  );
  assert.throws(
    () =>
      validateApplicationFailureCanaryConfig({
        ...config,
        external_evidence: {
          primary_canary_ref: 'run:duplicate',
          migration_startup_guard_ref: 'run:duplicate',
        },
      }),
    /distinct artifacts/,
  );
  assert.throws(
    () => validateApplicationFailureCanaryConfig({ ...config, unsupported: true }),
    /missing or unsupported fields/,
  );
});

test('runner proves dependency degradation, restoration, outage isolation, and graceful restart', async () => {
  const config = validConfig();
  const controller = new SyntheticFailureController(config);
  const report = await runApplicationFailureCanary(config, dependencies(controller));

  assert.equal(report.status, 'PASS');
  assert.equal(report.checks.length, 8);
  assert.ok(report.checks.every((check) => check.status === 'PASS'));
  assert.deepEqual(report.registry_updates, [
    {
      id: 'application.failure_modes',
      status: 'PASS',
      observed_at: '2026-08-11T12:00:00.000Z',
      evidence_refs: [
        'run:CHG-123-application-failure-canary-01/application-failure-canary',
        'run:CHG-123/application-canary',
        'artifact:CHG-123/postgresql-startup-guards',
      ],
    },
  ]);
  assert.match(report.report_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(controller.trace, [
    'postgres:true',
    'postgres:false',
    'mode:director:0',
    'mode:director:448',
    'mode:gateway:0',
    'mode:gateway:448',
    'replicas:0',
    'replicas:1',
    'restart:director',
    'restart:gateway',
  ]);
});

test('runner fails closed and restores PostgreSQL policy when readiness does not degrade', async () => {
  const config = validConfig();
  const controller = new SyntheticFailureController(config, {
    ignorePostgresqlFault: true,
  });
  const report = await runApplicationFailureCanary(config, dependencies(controller));

  assert.equal(report.status, 'FAIL');
  assert.deepEqual(
    report.checks.map((check) => [check.id, check.status]),
    [
      ['target.identity', 'PASS'],
      ['readiness.baseline', 'PASS'],
      ['readiness.postgresql_outage', 'FAIL'],
      ['readiness.document_store_outage', 'NOT_RUN'],
      ['readiness.gateway_store_outage', 'NOT_RUN'],
      ['availability.gateway_outage', 'NOT_RUN'],
      ['lifecycle.graceful_restart', 'NOT_RUN'],
      ['evidence.migration_startup_guards', 'NOT_RUN'],
    ],
  );
  assert.deepEqual(report.checks[2].error, {
    code: 'postgresql_readiness_not_degraded',
    message: 'Expected bounded health transition was not observed before timeout.',
  });
  assert.equal(controller.postgresqlBlocked, false);
  assert.deepEqual(controller.trace, ['postgres:true', 'postgres:false']);
  assert.equal(report.registry_updates[0].status, 'FAIL');
});

test('runner attempts restore after an ambiguous fault-application response', async () => {
  const config = validConfig();
  const controller = new SyntheticFailureController(config, {
    throwAfterPostgresqlBlock: true,
  });
  const report = await runApplicationFailureCanary(config, dependencies(controller));

  assert.equal(report.status, 'FAIL');
  assert.equal(report.checks[2].status, 'FAIL');
  assert.equal(controller.postgresqlBlocked, false);
  assert.deepEqual(controller.trace, ['postgres:true', 'postgres:false']);
});

test('evidence writer uses a new external directory with private modes', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-failure-canary-'));
  const workspace = path.join(root, 'workspace');
  const output = path.join(root, 'evidence');
  await mkdir(workspace);
  try {
    const config = validConfig();
    const result = await writeApplicationFailureCanaryEvidence({
      config,
      outputDirectory: output,
      workspaceRoot: workspace,
      dependencies: dependencies(new SyntheticFailureController(config)),
    });
    assert.equal(result.report.status, 'PASS');
    assert.equal((await stat(output)).mode & 0o777, 0o700);
    assert.equal((await stat(result.reportPath)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(result.reportPath, 'utf8')), result.report);

    await assert.rejects(
      writeApplicationFailureCanaryEvidence({
        config,
        outputDirectory: output,
        workspaceRoot: workspace,
        dependencies: dependencies(new SyntheticFailureController(config)),
      }),
      /EEXIST/,
    );
    await assert.rejects(
      writeApplicationFailureCanaryEvidence({
        config,
        outputDirectory: path.join(workspace, 'evidence'),
        workspaceRoot: workspace,
        dependencies: dependencies(new SyntheticFailureController(config)),
      }),
      /outside the source workspace/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function dependencies(controller) {
  let monotonic = 0;
  return {
    controller,
    now: () => new Date('2026-08-11T12:00:00.000Z'),
    monotonicNow: () => {
      monotonic += 5_000;
      return monotonic;
    },
    sleep: async () => {},
  };
}

class SyntheticFailureController {
  constructor(config, behavior = {}) {
    this.config = config;
    this.behavior = behavior;
    this.postgresqlBlocked = false;
    this.pathModes = { director: 0o700, gateway: 0o700 };
    this.gatewayReplicas = 1;
    this.restartCounts = { director: 0, gateway: 0 };
    this.trace = [];
  }

  async inspectTarget() {
    return {
      kubectl_client_version: this.config.kubernetes.kubectl_client_version,
      context: this.config.kubernetes.context,
      namespace: this.config.kubernetes.namespace,
      deployments: {
        director: {
          deployment_id: this.config.kubernetes.deployment_id,
          replicas: 1,
          image: `registry.invalid/dirizhor/director@sha256:${'a'.repeat(64)}`,
        },
        gateway: {
          deployment_id: this.config.kubernetes.deployment_id,
          replicas: 1,
          image: `registry.invalid/dirizhor/gateway@sha256:${'b'.repeat(64)}`,
        },
      },
    };
  }

  async probe(component) {
    if (component === 'gateway' && this.gatewayReplicas === 0) {
      throw new Error('Gateway is unavailable.');
    }
    const postgresqlUnavailable =
      component === 'director' &&
      this.postgresqlBlocked &&
      this.behavior.ignorePostgresqlFault !== true;
    const storageUnavailable = this.pathModes[component] === 0;
    const ready = postgresqlUnavailable || storageUnavailable ? 'unavailable' : 'ok';
    return {
      live: { status_code: 200, body: { status: 'ok' } },
      ready: { status_code: ready === 'ok' ? 200 : 503, body: { status: ready } },
    };
  }

  async getPathMode(component) {
    return this.pathModes[component];
  }

  async setPathMode(component, mode) {
    this.pathModes[component] = mode;
    this.trace.push(`mode:${component}:${mode}`);
  }

  async setPostgresqlBlocked(blocked) {
    this.postgresqlBlocked = blocked;
    this.trace.push(`postgres:${blocked}`);
    if (blocked && this.behavior.throwAfterPostgresqlBlock === true) {
      throw new Error('Synthetic ambiguous response.');
    }
  }

  async setGatewayReplicas(replicas) {
    this.gatewayReplicas = replicas;
    this.trace.push(`replicas:${replicas}`);
    return { replicas, active_pods: replicas };
  }

  async gracefulRestart(component, marker) {
    assert.equal(
      marker,
      component === 'director'
        ? 'Reference Director graceful shutdown complete (SIGTERM).'
        : 'Agent Gateway graceful shutdown complete (SIGTERM).',
    );
    const before = this.restartCounts[component];
    this.restartCounts[component] += 1;
    this.trace.push(`restart:${component}`);
    return {
      exit_code: 0,
      restart_count_before: before,
      restart_count_after: this.restartCounts[component],
      graceful_marker_seen: true,
    };
  }
}

function validConfig() {
  return {
    schema_version: 1,
    execution_id: 'CHG-123-application-failure-canary-01',
    environment: 'production-pilot',
    operation_timeout_ms: 10_000,
    kubernetes: {
      kubectl_path: '/usr/local/bin/kubectl',
      context: 'dirizhor-production',
      namespace: 'dirizhor-pilot',
      cluster_domain: 'cluster.local',
      kubectl_client_version: 'v1.34.2',
      deployment_id: 'pilot-2026-08-11-01',
      postgresql_cidrs: ['192.0.2.10/32'],
      postgresql_port: 5432,
    },
    external_evidence: {
      primary_canary_ref: 'run:CHG-123/application-canary',
      migration_startup_guard_ref: 'artifact:CHG-123/postgresql-startup-guards',
    },
  };
}
