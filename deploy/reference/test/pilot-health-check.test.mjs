import test from 'node:test';
import assert from 'node:assert/strict';

import {
  checkPublicEndpoint,
  evaluateDeploymentStatus,
  parseDeploymentRows,
  runHealthCheck,
} from '../scripts/pilot-health-check.mjs';

const ready = [
  'dirizhor-director',
  'dirizhor-edge',
  'dirizhor-gateway',
  'dirizhor-inference',
].map((name) => ({ name, replicas: 1, updated: 1, ready: 1, available: 1 }));

test('passes when every required deployment is ready', () => {
  assert.deepEqual(evaluateDeploymentStatus(ready), {
    status: 'PASS', deployment_count: 4, missing: [], not_ready: [],
  });
});

test('fails closed when a required deployment is missing or not ready', () => {
  const result = evaluateDeploymentStatus([
    ...ready.filter(({ name }) => name !== 'dirizhor-gateway'),
    { name: 'dirizhor-edge', replicas: 2, updated: 1, ready: 1, available: 1 },
  ]);
  assert.equal(result.status, 'FAIL');
  assert.deepEqual(result.missing, ['dirizhor-gateway']);
  assert.deepEqual(result.not_ready, ['dirizhor-edge']);
});

test('parses only safe deployment readiness fields', () => {
  assert.deepEqual(parseDeploymentRows({
    items: [{ metadata: { name: 'dirizhor-edge' }, status: { replicas: 2, updatedReplicas: 2, readyReplicas: 2, availableReplicas: 2, secret: 'ignored' } }],
  }), [{ name: 'dirizhor-edge', replicas: 2, updated: 2, ready: 2, available: 2 }]);
});

test('checks public endpoint without reading the response body', async () => {
  let bodyRead = false;
  const result = await checkPublicEndpoint('https://pilot.baza.fyi/', async () => ({
    status: 200,
    text: async () => { bodyRead = true; return 'not read'; },
  }));
  assert.deepEqual(result, { status: 200, status_code: 'PASS' });
  assert.equal(bodyRead, false);
});

test('reports public status and skips cluster when no kubeconfig is supplied', async () => {
  const report = await runHealthCheck({
    publicUrl: 'https://pilot.baza.fyi/',
    fetchImpl: async () => ({ status: 204 }),
  });
  assert.deepEqual(report, {
    status: 'PASS',
    public: { status: 204, status_code: 'PASS' },
    cluster: { status_code: 'SKIPPED' },
  });
});
