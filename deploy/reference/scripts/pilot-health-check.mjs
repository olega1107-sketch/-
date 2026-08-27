import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const requiredDeployments = Object.freeze([
  'dirizhor-director',
  'dirizhor-edge',
  'dirizhor-gateway',
  'dirizhor-inference',
]);

export function evaluateDeploymentStatus(deployments, required = requiredDeployments) {
  const byName = new Map(deployments.map((deployment) => [deployment.name, deployment]));
  const missing = required.filter((name) => !byName.has(name));
  const notReady = required.filter((name) => {
    const deployment = byName.get(name);
    return deployment !== undefined && (
      deployment.replicas < 1 ||
      deployment.updated !== deployment.replicas ||
      deployment.ready !== deployment.replicas ||
      deployment.available !== deployment.replicas
    );
  });
  return {
    status: missing.length === 0 && notReady.length === 0 ? 'PASS' : 'FAIL',
    deployment_count: deployments.length,
    missing,
    not_ready: notReady,
  };
}

export function parseDeploymentRows(payload) {
  if (!payload || !Array.isArray(payload.items)) {
    throw new Error('kubectl deployment payload is invalid.');
  }
  return payload.items.map((item) => ({
    name: item?.metadata?.name,
    replicas: item?.status?.replicas ?? 0,
    updated: item?.status?.updatedReplicas ?? 0,
    ready: item?.status?.readyReplicas ?? 0,
    available: item?.status?.availableReplicas ?? 0,
  })).filter((item) => typeof item.name === 'string');
}

export async function checkPublicEndpoint(url, fetchImpl = fetch) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
    });
    return { status: response.status, status_code: 'PASS' };
  } finally {
    clearTimeout(timeout);
  }
}

function kubectlDeployments(kubectl, kubeconfig, namespace) {
  const result = spawnSync(
    kubectl,
    ['--kubeconfig', kubeconfig, '--request-timeout=5s', '-n', namespace, 'get', 'deployments', '-o', 'json'],
    { encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] },
  );
  if (result.error !== undefined || result.status !== 0) {
    throw new Error('kubectl deployment query failed.');
  }
  return parseDeploymentRows(JSON.parse(result.stdout));
}

export async function runHealthCheck({
  publicUrl = process.env.PILOT_PUBLIC_URL ?? 'https://pilot.baza.fyi/',
  kubectl = process.env.KUBECTL_BIN,
  kubeconfig = process.env.KUBECONFIG,
  namespace = process.env.PILOT_NAMESPACE ?? 'dirizhor-pilot',
  fetchImpl = fetch,
} = {}) {
  const publicResult = await checkPublicEndpoint(publicUrl, fetchImpl)
    .then((result) => ({ ...result, status_code: result.status >= 200 && result.status < 400 ? 'PASS' : 'FAIL' }))
    .catch(() => ({ status: null, status_code: 'FAIL' }));
  const clusterResult = { status_code: 'SKIPPED' };
  if (kubectl !== undefined && kubeconfig !== undefined) {
    try {
      await access(kubeconfig, constants.R_OK);
      const readiness = evaluateDeploymentStatus(kubectlDeployments(kubectl, kubeconfig, namespace));
      Object.assign(clusterResult, readiness, { status_code: readiness.status });
    } catch {
      clusterResult.status_code = 'FAIL';
    }
  }
  return {
    status: publicResult.status_code === 'PASS' && clusterResult.status_code !== 'FAIL' ? 'PASS' : 'FAIL',
    public: publicResult,
    cluster: clusterResult,
  };
}

async function main() {
  const report = await runHealthCheck();
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (report.status !== 'PASS') process.exitCode = 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
