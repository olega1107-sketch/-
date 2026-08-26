import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { renderInternalInference, validateInternalInferenceConfig } from '../scripts/internal-inference-render.mjs';

const config = JSON.parse(await readFile(path.resolve('deploy/reference/internal-inference-config.example.json'), 'utf8'));

test('renders an isolated internal inference deployment on the dedicated worker', () => {
  const resources = renderInternalInference(config);
  const deployment = resources.find((resource) => resource.kind === 'Deployment');
  const policy = resources.find((resource) => resource.kind === 'NetworkPolicy');
  assert.equal(deployment.spec.strategy.type, 'Recreate');
  assert.equal(deployment.spec.template.spec.nodeSelector['dirizhor.io/workload'], 'internal-inference');
  assert.deepEqual(deployment.spec.template.spec.tolerations, [{ key: 'dirizhor.io/workload', operator: 'Equal', value: 'internal-inference', effect: 'NoSchedule' }]);
  assert.equal(deployment.spec.template.spec.automountServiceAccountToken, false);
  assert.equal(deployment.spec.template.spec.containers.length, 2);
  assert.ok(deployment.spec.template.spec.containers.every((container) => container.securityContext.readOnlyRootFilesystem));
  const modelRuntime = deployment.spec.template.spec.containers.find((container) => container.name === 'model-runtime');
  assert.match(modelRuntime.args[0], /--offline/);
  assert.match(modelRuntime.args[0], /cat \/model-parts\/part-\*/);
  assert.deepEqual(modelRuntime.startupProbe.exec.command, ['/bin/sh', '-ec', 'curl --fail --silent --show-error --output /dev/null http://127.0.0.1:8080/health']);
  assert.deepEqual(modelRuntime.livenessProbe.exec.command, ['/bin/sh', '-ec', 'curl --fail --silent --show-error --output /dev/null http://127.0.0.1:8080/health']);
  assert.deepEqual(policy.spec.egress, []);
  assert.deepEqual(policy.spec.ingress[0].from[0].podSelector.matchLabels, {
    'app.kubernetes.io/name': 'dirizhor',
    'app.kubernetes.io/component': 'gateway',
  });
});

test('rejects mutable images and any alternate pilot model', () => {
  assert.throws(() => validateInternalInferenceConfig({ ...config, images: { ...config.images, adapter: 'registry.invalid/adapter:latest' } }), /digest-pinned/);
  assert.throws(() => validateInternalInferenceConfig({ ...config, model: { ...config.model, id: 'unapproved-model' } }), /not approved/);
});
