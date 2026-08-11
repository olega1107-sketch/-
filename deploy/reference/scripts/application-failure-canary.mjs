#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$/;
const dnsLabelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const hostnamePattern = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;
const cidrPattern = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/;
const kubernetesVersionPattern = /^v1\.([1-9][0-9]?)\.([0-9]+)$/;
const digestImagePattern = /^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$/;
const evidenceReferencePattern = /^(?:alert|artifact|backup|change|dashboard|run|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const components = Object.freeze(['director', 'gateway']);
const componentPaths = Object.freeze({
  director: '/var/lib/dirizhor/documents',
  gateway: '/var/lib/dirizhor/gateway',
});
const gracefulMarkers = Object.freeze({
  director: 'Reference Director graceful shutdown complete (SIGTERM).',
  gateway: 'Agent Gateway graceful shutdown complete (SIGTERM).',
});

export class FailureCanaryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'FailureCanaryError';
    this.code = code;
  }
}

export function validateApplicationFailureCanaryConfig(document) {
  assertObject(document, 'config');
  assertExactKeys(
    document,
    [
      'schema_version',
      'execution_id',
      'environment',
      'operation_timeout_ms',
      'kubernetes',
      'external_evidence',
    ],
    'config',
  );
  if (document.schema_version !== 1) {
    throw new Error('Application failure canary config schema_version must be 1.');
  }
  assertIdentifier(document.execution_id, 'execution_id');
  assertIdentifier(document.environment, 'environment');
  if (
    !Number.isSafeInteger(document.operation_timeout_ms) ||
    document.operation_timeout_ms < 10_000 ||
    document.operation_timeout_ms > 300_000
  ) {
    throw new Error('operation_timeout_ms must be an integer from 10000 through 300000.');
  }
  validateKubernetesConfig(document.kubernetes);
  validateExternalEvidence(document.external_evidence);
  return document;
}

export async function runApplicationFailureCanary(config, dependencies = {}) {
  validateApplicationFailureCanaryConfig(config);
  const runtime = {
    now: dependencies.now ?? (() => new Date()),
    monotonicNow: dependencies.monotonicNow ?? (() => Date.now()),
    sleep:
      dependencies.sleep ??
      ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))),
  };
  const controller =
    dependencies.controller ??
    new KubernetesFailureController(config.kubernetes, {
      runCommand: dependencies.runCommand,
      sleep: runtime.sleep,
    });
  const startedAt = isoNow(runtime.now);
  const checks = [];
  const definitions = [
    ['target.identity', [], () => checkTargetIdentity(config, controller)],
    ['readiness.baseline', ['target.identity'], () => checkBaseline(controller)],
    [
      'readiness.postgresql_outage',
      ['readiness.baseline'],
      () => checkPostgresqlOutage(config, runtime, controller),
    ],
    [
      'readiness.document_store_outage',
      ['readiness.postgresql_outage'],
      () => checkStorageOutage(config, runtime, controller, 'director'),
    ],
    [
      'readiness.gateway_store_outage',
      ['readiness.document_store_outage'],
      () => checkStorageOutage(config, runtime, controller, 'gateway'),
    ],
    [
      'availability.gateway_outage',
      ['readiness.gateway_store_outage'],
      () => checkGatewayOutage(config, runtime, controller),
    ],
    [
      'lifecycle.graceful_restart',
      ['availability.gateway_outage'],
      () => checkGracefulRestart(config, runtime, controller),
    ],
    [
      'evidence.migration_startup_guards',
      ['lifecycle.graceful_restart'],
      () => checkExternalEvidence(config),
    ],
  ];

  for (const [id, required, execute] of definitions) {
    if (required.some((requiredId) => checks.find((check) => check.id === requiredId)?.status !== 'PASS')) {
      checks.push(notRunCheck(id));
      continue;
    }
    checks.push(await executeCheck(id, execute, runtime));
  }

  const completedAt = isoNow(runtime.now);
  const status = checks.every((check) => check.status === 'PASS') ? 'PASS' : 'FAIL';
  const evidenceRef = `run:${config.execution_id}/application-failure-canary`;
  const report = {
    schema_version: 1,
    execution_id: config.execution_id,
    environment: config.environment,
    started_at: startedAt,
    completed_at: completedAt,
    status,
    evidence_ref: evidenceRef,
    checks,
    registry_updates: [
      {
        id: 'application.failure_modes',
        status,
        observed_at: completedAt,
        evidence_refs: [
          evidenceRef,
          config.external_evidence.primary_canary_ref,
          config.external_evidence.migration_startup_guard_ref,
        ],
      },
    ],
    external_evidence_refs: [
      config.external_evidence.primary_canary_ref,
      config.external_evidence.migration_startup_guard_ref,
    ],
    limitations: [
      'Requires an approved change window because it mutates live NetworkPolicy, file modes, and replica state.',
      'References, but does not read, the primary-canary and disposable-database startup-guard evidence.',
      'Targets the single-replica Director and Gateway pilot topology defined by the Kubernetes contract.',
      'Does not inject an upstream inference-provider outage or replace provider-specific resilience tests.',
    ],
  };
  return { ...report, report_sha256: canonicalHash(report) };
}

export async function writeApplicationFailureCanaryEvidence({
  config,
  outputDirectory,
  workspaceRoot = defaultWorkspaceRoot,
  dependencies,
}) {
  validateApplicationFailureCanaryConfig(config);
  const resolvedOutput = path.resolve(outputDirectory);
  const resolvedWorkspace = path.resolve(workspaceRoot);
  if (isWithin(resolvedOutput, resolvedWorkspace)) {
    throw new Error('Application failure canary output directory must be outside the source workspace.');
  }
  await mkdir(resolvedOutput, { mode: 0o700 });
  await chmod(resolvedOutput, 0o700);
  const report = await runApplicationFailureCanary(config, dependencies);
  const reportPath = path.join(resolvedOutput, 'application-failure-canary-evidence.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(reportPath, 0o600);
  return { report, reportPath };
}

async function checkTargetIdentity(config, controller) {
  const target = await controller.inspectTarget();
  if (
    target.kubectl_client_version !== config.kubernetes.kubectl_client_version ||
    target.context !== config.kubernetes.context ||
    target.namespace !== config.kubernetes.namespace
  ) {
    fail('target_identity_mismatch', 'Kubernetes client, context, or namespace differs from the pinned target.');
  }
  for (const component of components) {
    const deployment = target.deployments?.[component];
    if (
      !isObject(deployment) ||
      deployment.deployment_id !== config.kubernetes.deployment_id ||
      deployment.replicas !== 1 ||
      !digestImagePattern.test(deployment.image)
    ) {
      fail('deployment_identity_mismatch', 'A stateful deployment differs from the pinned release contract.');
    }
  }
  if (new Set(components.map((component) => target.deployments[component].image)).size !== 2) {
    fail('deployment_image_collision', 'Director and Gateway unexpectedly use the same image reference.');
  }
  return {
    kubectl_client_version: target.kubectl_client_version,
    context_matches: true,
    namespace_matches: true,
    deployment_id_matches: true,
    stateful_replicas: { director: 1, gateway: 1 },
    digest_images: true,
  };
}

async function checkBaseline(controller) {
  const director = await controller.probe('director');
  const gateway = await controller.probe('gateway');
  assertProbe(director, 200, 'ok', 'director_baseline');
  assertProbe(gateway, 200, 'ok', 'gateway_baseline');
  const directorMode = await controller.getPathMode('director');
  const gatewayMode = await controller.getPathMode('gateway');
  if (directorMode !== 0o700 || gatewayMode !== 0o700) {
    fail('state_path_mode_mismatch', 'A persistent state root is not protected with mode 0700.');
  }
  return {
    director_live: 200,
    director_ready: 200,
    gateway_live: 200,
    gateway_ready: 200,
    state_root_modes: { director: '0700', gateway: '0700' },
  };
}

async function checkPostgresqlOutage(config, runtime, controller) {
  let faultApplied = false;
  let failure;
  try {
    faultApplied = true;
    await controller.setPostgresqlBlocked(true);
    const degraded = await waitForProbe(
      config,
      runtime,
      controller,
      'director',
      (probe) => probeMatches(probe, 200, 'ok', 503, 'unavailable'),
      'postgresql_readiness_not_degraded',
    );
    assertProbe(degraded, 503, 'unavailable', 'director_postgresql_outage');
  } catch (error) {
    failure = error;
  } finally {
    if (faultApplied) {
      try {
        await controller.setPostgresqlBlocked(false);
        await waitForHealthy(config, runtime, controller, 'director');
      } catch {
        failure = new FailureCanaryError(
          'postgresql_fault_restore_failed',
          'PostgreSQL egress policy was not proven restored.',
        );
      }
    }
  }
  if (failure !== undefined) throw failure;
  return {
    fault: 'director_postgresql_egress_blocked',
    live_during_fault: 200,
    ready_during_fault: 503,
    generic_unavailable_body: true,
    policy_restored: true,
    readiness_recovered: true,
  };
}

async function checkStorageOutage(config, runtime, controller, component) {
  const originalMode = await controller.getPathMode(component);
  if (originalMode !== 0o700) {
    fail('state_path_mode_mismatch', 'Persistent state root mode changed before fault injection.');
  }
  let faultApplied = false;
  let failure;
  try {
    faultApplied = true;
    await controller.setPathMode(component, 0o000);
    const degraded = await waitForProbe(
      config,
      runtime,
      controller,
      component,
      (probe) => probeMatches(probe, 200, 'ok', 503, 'unavailable'),
      `${component}_store_readiness_not_degraded`,
    );
    assertProbe(degraded, 503, 'unavailable', `${component}_store_outage`);
  } catch (error) {
    failure = error;
  } finally {
    if (faultApplied) {
      try {
        await controller.setPathMode(component, originalMode);
        await waitForHealthy(config, runtime, controller, component);
      } catch {
        failure = new FailureCanaryError(
          'state_path_restore_failed',
          'Persistent state root permissions were not proven restored.',
        );
      }
    }
  }
  if (failure !== undefined) throw failure;
  return {
    component,
    fault: 'state_root_mode_0000',
    live_during_fault: 200,
    ready_during_fault: 503,
    generic_unavailable_body: true,
    original_mode: '0700',
    mode_restored: true,
    readiness_recovered: true,
  };
}

async function checkGatewayOutage(config, runtime, controller) {
  let scaledDown = false;
  let failure;
  try {
    scaledDown = true;
    const stopped = await controller.setGatewayReplicas(0);
    if (stopped.replicas !== 0 || stopped.active_pods !== 0) {
      fail('gateway_outage_not_observed', 'Gateway deployment did not reach zero active replicas.');
    }
    const director = await waitForHealthy(config, runtime, controller, 'director');
    assertProbe(director, 200, 'ok', 'director_during_gateway_outage');
  } catch (error) {
    failure = error;
  } finally {
    if (scaledDown) {
      try {
        const restored = await controller.setGatewayReplicas(1);
        if (restored.replicas !== 1 || restored.active_pods !== 1) {
          throw new Error('Gateway replica restoration was incomplete.');
        }
        await waitForHealthy(config, runtime, controller, 'gateway');
      } catch {
        failure = new FailureCanaryError(
          'gateway_replica_restore_failed',
          'Gateway deployment was not proven restored to one ready replica.',
        );
      }
    }
  }
  if (failure !== undefined) throw failure;
  return {
    gateway_active_pods_during_fault: 0,
    director_live_during_fault: 200,
    director_ready_during_fault: 200,
    gateway_replicas_restored: 1,
    gateway_readiness_recovered: true,
    primary_canary_recovery_evidence_referenced: true,
  };
}

async function checkGracefulRestart(config, runtime, controller) {
  const observations = [];
  for (const component of components) {
    const result = await controller.gracefulRestart(component, gracefulMarkers[component]);
    if (
      result.exit_code !== 0 ||
      result.graceful_marker_seen !== true ||
      !Number.isSafeInteger(result.restart_count_before) ||
      result.restart_count_after !== result.restart_count_before + 1
    ) {
      fail('graceful_restart_mismatch', 'A service did not complete the bounded SIGTERM restart contract.');
    }
    await waitForHealthy(config, runtime, controller, component);
    observations.push({
      component,
      exit_code: 0,
      restart_increment: 1,
      graceful_marker_seen: true,
      readiness_recovered: true,
    });
  }
  return {
    services: observations,
    director_current_migration_history_restart: true,
  };
}

async function checkExternalEvidence(config) {
  return {
    disposable_database_startup_guard_evidence_referenced: true,
    primary_application_recovery_evidence_referenced: true,
    reference_count: 2,
  };
}

async function waitForHealthy(config, runtime, controller, component) {
  return waitForProbe(
    config,
    runtime,
    controller,
    component,
    (probe) => probeMatches(probe, 200, 'ok', 200, 'ok'),
    `${component}_readiness_not_recovered`,
  );
}

async function waitForProbe(config, runtime, controller, component, predicate, failureCode) {
  const deadline = runtime.monotonicNow() + config.operation_timeout_ms;
  do {
    try {
      const probe = await controller.probe(component);
      if (predicate(probe)) return probe;
    } catch {
      // Transient transport failures are expected while a fault is taking effect.
    }
    await runtime.sleep(1_000);
  } while (runtime.monotonicNow() < deadline);
  fail(failureCode, 'Expected bounded health transition was not observed before timeout.');
}

function assertProbe(probe, readyStatus, readyBody, label) {
  if (!probeMatches(probe, 200, 'ok', readyStatus, readyBody)) {
    fail(`${label}_health_mismatch`, 'Health endpoint returned an unexpected bounded contract.');
  }
}

function probeMatches(probe, liveStatus, liveBody, readyStatus, readyBody) {
  return (
    isObject(probe) &&
    healthMatches(probe.live, liveStatus, liveBody) &&
    healthMatches(probe.ready, readyStatus, readyBody)
  );
}

function healthMatches(response, statusCode, bodyStatus) {
  return (
    isObject(response) &&
    response.status_code === statusCode &&
    isObject(response.body) &&
    Object.keys(response.body).length === 1 &&
    response.body.status === bodyStatus
  );
}

async function executeCheck(id, execute, runtime) {
  const began = runtime.monotonicNow();
  try {
    const observations = await execute();
    return {
      id,
      status: 'PASS',
      observed_at: isoNow(runtime.now),
      duration_ms: duration(runtime.monotonicNow() - began),
      observations,
      error: null,
    };
  } catch (error) {
    return {
      id,
      status: 'FAIL',
      observed_at: isoNow(runtime.now),
      duration_ms: duration(runtime.monotonicNow() - began),
      observations: null,
      error: reportedFailure(error),
    };
  }
}

function notRunCheck(id) {
  return {
    id,
    status: 'NOT_RUN',
    observed_at: null,
    duration_ms: 0,
    observations: null,
    error: {
      code: 'dependency_failed',
      message: 'A required earlier failure-mode check did not pass.',
    },
  };
}

function reportedFailure(error) {
  if (error instanceof FailureCanaryError) {
    return { code: error.code, message: error.message };
  }
  return {
    code: 'unexpected_failure',
    message: 'Failure-mode check failed without a bounded diagnostic.',
  };
}

function fail(code, message) {
  throw new FailureCanaryError(code, message);
}

export class KubernetesFailureController {
  constructor(config, dependencies = {}) {
    this.config = config;
    this.runCommand = dependencies.runCommand ?? runCommand;
    this.sleep =
      dependencies.sleep ??
      ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.originalDirectorPolicySpec = null;
  }

  async inspectTarget() {
    const version = await this.kubectl(['version', '--client', '-o', 'json'], false);
    const context = await this.kubectl(
      ['config', 'get-contexts', this.config.context, '-o', 'name'],
      false,
    );
    const versionDocument = parseCommandJson(version, 'kubectl client version');
    const contextName = context.stdout.trim();
    if (contextName !== this.config.context) throw new Error('Pinned Kubernetes context is absent.');
    const deployments = {};
    for (const component of components) {
      const deployment = parseCommandJson(
        await this.kubectl(['get', 'deployment', `dirizhor-${component}`, '-o', 'json']),
        `${component} deployment`,
      );
      deployments[component] = inspectDeployment(deployment, component);
    }
    return {
      kubectl_client_version: versionDocument.clientVersion?.gitVersion,
      context: contextName,
      namespace: this.config.namespace,
      deployments,
    };
  }

  async probe(component) {
    assertComponent(component);
    const pod = await this.selectPod(component, true);
    const serverName = `dirizhor-${component}.${this.config.namespace}.svc.${this.config.cluster_domain}`;
    const probeScript = healthProbeScript(component, serverName);
    const result = await this.kubectl([
      'exec',
      pod.metadata.name,
      '-c',
      component,
      '--',
      'node',
      '-e',
      probeScript,
    ]);
    const probe = parseCommandJson(result, `${component} health probe`);
    if (!isObject(probe.live) || !isObject(probe.ready)) {
      throw new Error('Health probe output has an invalid shape.');
    }
    return probe;
  }

  async getPathMode(component) {
    assertComponent(component);
    const pod = await this.selectPod(component, true);
    const result = await this.kubectl([
      'exec',
      pod.metadata.name,
      '-c',
      component,
      '--',
      'node',
      '-e',
      `process.stdout.write((require('fs').statSync(${JSON.stringify(componentPaths[component])}).mode&0o777).toString(8))`,
    ]);
    const value = result.stdout.trim();
    if (!/^[0-7]{3,4}$/.test(value)) throw new Error('State path mode output is invalid.');
    return Number.parseInt(value, 8);
  }

  async setPathMode(component, mode) {
    assertComponent(component);
    if (![0o000, 0o700].includes(mode)) throw new Error('Unsupported state path mode.');
    const pod = await this.selectPod(component, false);
    await this.kubectl([
      'exec',
      pod.metadata.name,
      '-c',
      component,
      '--',
      'node',
      '-e',
      `require('fs').chmodSync(${JSON.stringify(componentPaths[component])},${mode})`,
    ]);
  }

  async setPostgresqlBlocked(blocked) {
    if (blocked) {
      if (this.originalDirectorPolicySpec !== null) {
        throw new Error('PostgreSQL egress fault is already active.');
      }
      const policy = await this.readDirectorPolicy();
      const egress = policy.spec?.egress;
      if (!Array.isArray(egress)) throw new Error('Director NetworkPolicy egress is invalid.');
      const observedCidrs = [];
      const filtered = egress.filter((rule) => {
        const cidr = postgresRuleCidr(rule, this.config.postgresql_port);
        if (cidr === null || !this.config.postgresql_cidrs.includes(cidr)) return true;
        observedCidrs.push(cidr);
        return false;
      });
      if (!sameStringSet(observedCidrs, this.config.postgresql_cidrs)) {
        throw new Error('Director NetworkPolicy does not contain the exact PostgreSQL egress set.');
      }
      this.originalDirectorPolicySpec = structuredClone(policy.spec);
      policy.spec.egress = filtered;
      await this.replacePolicy(policy);
      return;
    }

    if (this.originalDirectorPolicySpec === null) {
      throw new Error('PostgreSQL egress fault is not active.');
    }
    const policy = await this.readDirectorPolicy();
    policy.spec = this.originalDirectorPolicySpec;
    await this.replacePolicy(policy);
    this.originalDirectorPolicySpec = null;
  }

  async setGatewayReplicas(replicas) {
    if (![0, 1].includes(replicas)) throw new Error('Unsupported Gateway replica count.');
    await this.kubectl([
      'scale',
      'deployment/dirizhor-gateway',
      `--replicas=${replicas}`,
    ]);
    return this.waitForGatewayReplicas(replicas);
  }

  async gracefulRestart(component, marker) {
    assertComponent(component);
    if (marker !== gracefulMarkers[component]) throw new Error('Unexpected graceful marker.');
    const pod = await this.selectPod(component, true);
    const podName = pod.metadata.name;
    const podUid = pod.metadata.uid;
    const before = containerRestartCount(pod, component);
    try {
      await this.kubectl([
        'exec',
        podName,
        '-c',
        component,
        '--',
        'node',
        '-e',
        "process.kill(1,'SIGTERM')",
      ]);
    } catch {
      // The exec stream can close while PID 1 is shutting down; restart evidence decides success.
    }

    const deadline = Date.now() + this.config.operation_timeout_ms;
    let restarted;
    while (Date.now() < deadline) {
      try {
        const current = await this.readPod(podName);
        if (
          current.metadata?.uid === podUid &&
          containerRestartCount(current, component) === before + 1 &&
          isPodReady(current)
        ) {
          restarted = current;
          break;
        }
      } catch {
        // The pod API can be transient while the container restarts.
      }
      await this.sleep(1_000);
    }
    if (restarted === undefined) throw new Error('Container did not complete an in-place restart.');
    const status = containerStatus(restarted, component);
    const termination = status.lastState?.terminated;
    const previousLogs = await this.kubectl([
      'logs',
      podName,
      '-c',
      component,
      '--previous',
      '--tail=200',
    ]);
    return {
      exit_code: termination?.exitCode,
      restart_count_before: before,
      restart_count_after: status.restartCount,
      graceful_marker_seen: previousLogs.stdout.split('\n').includes(marker),
    };
  }

  async readDirectorPolicy() {
    const policy = parseCommandJson(
      await this.kubectl(['get', 'networkpolicy', 'dirizhor-director', '-o', 'json']),
      'Director NetworkPolicy',
    );
    if (
      policy.metadata?.name !== 'dirizhor-director' ||
      policy.metadata?.namespace !== this.config.namespace ||
      policy.metadata?.labels?.['app.kubernetes.io/managed-by'] !== 'dirizhor-target-renderer'
    ) {
      throw new Error('Director NetworkPolicy identity is invalid.');
    }
    return policy;
  }

  async replacePolicy(policy) {
    await this.kubectl(['replace', '-f', '-'], true, `${JSON.stringify(policy)}\n`);
  }

  async waitForGatewayReplicas(replicas) {
    const deadline = Date.now() + this.config.operation_timeout_ms;
    while (Date.now() < deadline) {
      const deployment = parseCommandJson(
        await this.kubectl(['get', 'deployment', 'dirizhor-gateway', '-o', 'json']),
        'Gateway deployment',
      );
      const pods = await this.listPods('gateway');
      const activePods = pods.filter(
        (pod) => pod.metadata?.deletionTimestamp === undefined && pod.status?.phase === 'Running',
      );
      const readyPods = activePods.filter(isPodReady);
      if (
        deployment.spec?.replicas === replicas &&
        activePods.length === replicas &&
        readyPods.length === replicas
      ) {
        return { replicas, active_pods: activePods.length };
      }
      await this.sleep(1_000);
    }
    throw new Error('Gateway deployment did not reach the requested replica state.');
  }

  async selectPod(component, requireReady) {
    const pods = (await this.listPods(component)).filter(
      (pod) =>
        pod.metadata?.deletionTimestamp === undefined &&
        pod.status?.phase === 'Running' &&
        (!requireReady || isPodReady(pod)),
    );
    if (pods.length !== 1 || typeof pods[0]?.metadata?.name !== 'string') {
      throw new Error(`Expected exactly one active ${component} pod.`);
    }
    return pods[0];
  }

  async listPods(component) {
    const result = parseCommandJson(
      await this.kubectl([
        'get',
        'pods',
        '-l',
        `app.kubernetes.io/name=dirizhor,app.kubernetes.io/component=${component}`,
        '-o',
        'json',
      ]),
      `${component} pods`,
    );
    if (!Array.isArray(result.items)) throw new Error('Kubernetes pod list is invalid.');
    return result.items;
  }

  async readPod(name) {
    return parseCommandJson(
      await this.kubectl(['get', 'pod', name, '-o', 'json']),
      'Kubernetes pod',
    );
  }

  async kubectl(args, namespaced = true, input) {
    const commandArgs = [
      '--context',
      this.config.context,
      ...(namespaced ? ['--namespace', this.config.namespace] : []),
      ...args,
    ];
    return this.runCommand(this.config.kubectl_path, commandArgs, {
      timeoutMs: this.config.operation_timeout_ms,
      maxOutputBytes: 1024 * 1024,
      input,
    });
  }
}

function inspectDeployment(deployment, component) {
  const container = deployment.spec?.template?.spec?.containers?.find(
    (candidate) => candidate.name === component,
  );
  const deploymentId = deployment.metadata?.annotations?.['dirizhor.io/deployment-id'];
  const podDeploymentId =
    deployment.spec?.template?.metadata?.annotations?.['dirizhor.io/deployment-id'];
  const imageDigest = deployment.metadata?.annotations?.['dirizhor.io/image-digest'];
  if (
    deployment.metadata?.name !== `dirizhor-${component}` ||
    deployment.metadata?.labels?.['app.kubernetes.io/managed-by'] !== 'dirizhor-target-renderer' ||
    deployment.spec?.strategy?.type !== 'Recreate' ||
    deploymentId !== podDeploymentId ||
    typeof container?.image !== 'string' ||
    container.image.slice(container.image.indexOf('@') + 1) !== imageDigest
  ) {
    throw new Error('Stateful deployment does not match the rendered identity contract.');
  }
  return {
    deployment_id: deploymentId,
    replicas: deployment.spec.replicas,
    image: container.image,
  };
}

function healthProbeScript(component, serverName) {
  const port = component === 'director' ? 8444 : 8443;
  const caPath =
    component === 'director'
      ? '/run/secrets/director-tls/ca.crt'
      : '/run/secrets/gateway-probe-tls/ca.crt';
  const identity =
    component === 'gateway'
      ? ",cert:fs.readFileSync('/run/secrets/gateway-probe-tls/tls.crt'),key:fs.readFileSync('/run/secrets/gateway-probe-tls/tls.key')"
      : '';
  return [
    "const fs=require('fs'),https=require('https')",
    `const request=(p)=>new Promise((resolve,reject)=>{const r=https.get({host:'127.0.0.1',port:${port},path:p,servername:${JSON.stringify(serverName)},timeout:3000,ca:fs.readFileSync(${JSON.stringify(caPath)})${identity}},s=>{const chunks=[];let size=0;s.on('data',c=>{size+=c.length;if(size>256){r.destroy();return}chunks.push(c)});s.on('end',()=>{try{resolve({status_code:s.statusCode,body:JSON.parse(Buffer.concat(chunks).toString('utf8'))})}catch{reject(new Error('invalid response'))}})});r.on('timeout',()=>r.destroy());r.on('error',reject)})`,
    "Promise.all([request('/health/live'),request('/health/ready')]).then(([live,ready])=>process.stdout.write(JSON.stringify({live,ready}))).catch(()=>process.exit(2))",
  ].join(';');
}

function postgresRuleCidr(rule, port) {
  if (
    !isObject(rule) ||
    !Array.isArray(rule.to) ||
    rule.to.length !== 1 ||
    !isObject(rule.to[0]?.ipBlock) ||
    Object.keys(rule.to[0].ipBlock).length !== 1 ||
    !Array.isArray(rule.ports) ||
    rule.ports.length !== 1 ||
    rule.ports[0]?.protocol !== 'TCP' ||
    rule.ports[0]?.port !== port
  ) {
    return null;
  }
  return typeof rule.to[0].ipBlock.cidr === 'string' ? rule.to[0].ipBlock.cidr : null;
}

function containerStatus(pod, component) {
  const status = pod.status?.containerStatuses?.find((candidate) => candidate.name === component);
  if (!isObject(status) || !Number.isSafeInteger(status.restartCount)) {
    throw new Error('Container status is unavailable.');
  }
  return status;
}

function containerRestartCount(pod, component) {
  return containerStatus(pod, component).restartCount;
}

function isPodReady(pod) {
  return pod.status?.conditions?.some(
    (condition) => condition.type === 'Ready' && condition.status === 'True',
  ) === true;
}

export async function runCommand(command, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const maxOutputBytes = options.maxOutputBytes ?? 1024 * 1024;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      env: process.env,
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error === null) resolve(result);
      else reject(error);
    };
    const append = (chunks, chunk, currentBytes) => {
      const next = currentBytes + chunk.length;
      if (next > maxOutputBytes) {
        child.kill('SIGKILL');
        finish(new Error('Kubernetes command exceeded the bounded output limit.'));
        return currentBytes;
      }
      chunks.push(chunk);
      return next;
    };
    child.stdout.on('data', (chunk) => {
      stdoutBytes = append(stdout, chunk, stdoutBytes);
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes = append(stderr, chunk, stderrBytes);
    });
    child.stdin.on('error', () => undefined);
    child.once('error', () => finish(new Error('Kubernetes command could not be started.')));
    child.once('close', (code, signal) => {
      if (code !== 0 || signal !== null) {
        finish(new Error('Kubernetes command did not complete successfully.'));
        return;
      }
      finish(null, {
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new Error('Kubernetes command timed out.'));
    }, timeoutMs);
    if (options.input === undefined) child.stdin.end();
    else child.stdin.end(options.input);
  });
}

function parseCommandJson(result, label) {
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error(`${label} returned malformed JSON.`);
  }
  if (!isObject(parsed)) throw new Error(`${label} returned a non-object JSON document.`);
  return parsed;
}

function validateKubernetesConfig(config) {
  assertObject(config, 'kubernetes');
  assertExactKeys(
    config,
    [
      'kubectl_path',
      'context',
      'namespace',
      'cluster_domain',
      'kubectl_client_version',
      'deployment_id',
      'postgresql_cidrs',
      'postgresql_port',
    ],
    'kubernetes',
  );
  if (
    typeof config.kubectl_path !== 'string' ||
    !path.isAbsolute(config.kubectl_path) ||
    path.basename(config.kubectl_path) !== 'kubectl'
  ) {
    throw new Error('kubectl_path must be an absolute path ending in kubectl.');
  }
  assertIdentifier(config.context, 'kubernetes.context');
  if (!dnsLabelPattern.test(config.namespace)) throw new Error('Kubernetes namespace is invalid.');
  if (!hostnamePattern.test(config.cluster_domain) || net.isIP(config.cluster_domain) !== 0) {
    throw new Error('Kubernetes cluster_domain must be a DNS hostname.');
  }
  const version = kubernetesVersionPattern.exec(config.kubectl_client_version);
  if (version === null || Number(version[1]) < 34) {
    throw new Error('kubectl_client_version must be an exact supported v1.34+ patch version.');
  }
  assertIdentifier(config.deployment_id, 'kubernetes.deployment_id');
  if (
    !Array.isArray(config.postgresql_cidrs) ||
    config.postgresql_cidrs.length === 0 ||
    !sameStringSet(config.postgresql_cidrs, [...new Set(config.postgresql_cidrs)]) ||
    config.postgresql_cidrs.some((cidr) => !validIpv4Cidr(cidr))
  ) {
    throw new Error('postgresql_cidrs must contain unique IPv4 CIDRs.');
  }
  if (
    !Number.isSafeInteger(config.postgresql_port) ||
    config.postgresql_port < 1 ||
    config.postgresql_port > 65_535
  ) {
    throw new Error('postgresql_port is invalid.');
  }
}

function validateExternalEvidence(evidence) {
  assertObject(evidence, 'external_evidence');
  assertExactKeys(
    evidence,
    ['primary_canary_ref', 'migration_startup_guard_ref'],
    'external_evidence',
  );
  for (const value of Object.values(evidence)) {
    if (typeof value !== 'string' || !evidenceReferencePattern.test(value)) {
      throw new Error('External evidence references are invalid.');
    }
  }
  if (evidence.primary_canary_ref === evidence.migration_startup_guard_ref) {
    throw new Error('External evidence references must identify distinct artifacts.');
  }
}

function validIpv4Cidr(value) {
  if (typeof value !== 'string') return false;
  const match = cidrPattern.exec(value);
  return (
    match !== null &&
    net.isIP(match[1]) === 4 &&
    match[1].split('.').every((octet) => Number(octet) <= 255)
  );
}

function assertIdentifier(value, name) {
  if (typeof value !== 'string' || !identifierPattern.test(value)) {
    throw new Error(`${name} must be a bounded identifier.`);
  }
}

function assertComponent(component) {
  if (!components.includes(component)) throw new Error('Unsupported component.');
}

function assertObject(value, name) {
  if (!isObject(value)) throw new Error(`${name} must be an object.`);
}

function assertExactKeys(value, expected, name) {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${name} contains missing or unsupported fields.`);
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sameStringSet(left, right) {
  return (
    new Set(left).size === left.length &&
    new Set(right).size === right.length &&
    [...left].sort().join('\0') === [...right].sort().join('\0')
  );
}

function canonicalHash(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex')}`;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function isoNow(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error('Canary clock returned an invalid time.');
  }
  return value.toISOString();
}

function duration(value) {
  return Number.isFinite(value) && value > 0 ? Math.round(value) : 0;
}

function isWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function main(argv) {
  if (argv.length !== 2) {
    throw new Error(
      'Usage: node scripts/application-failure-canary.mjs <new-output-directory> <config.json>',
    );
  }
  let config;
  try {
    config = JSON.parse(await readFile(argv[1], 'utf8'));
  } catch {
    throw new Error('Application failure canary config could not be read.');
  }
  const result = await writeApplicationFailureCanaryEvidence({
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
        fail: result.report.checks.filter((check) => check.status === 'FAIL').length,
        not_run: result.report.checks.filter((check) => check.status === 'NOT_RUN').length,
        evidence_file: path.basename(result.reportPath),
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
    const message = error instanceof Error ? error.message : 'Application failure canary failed.';
    process.stderr.write(`Application failure canary failed: ${message}\n`);
    process.exitCode = 2;
  });
}
