import assert from 'node:assert/strict';
import test from 'node:test';

import { renderAlertRelay, validateAlertRelayConfig } from '../scripts/alert-relay-render.mjs';
import { composeEmail, validateAlertPayload } from '../monitoring/resend-relay.mjs';

const config = {
  schema_version: 1,
  namespace: 'monitoring',
  image: 'registry.example.invalid/dirizhor/alert-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  sender: 'alerts@alerts.baza.fyi',
  recipient: 'olega.1107@gmail.com',
  secrets: { runtime: 'dirizhor-alert-relay-runtime' },
};

test('renders a private digest-pinned Resend relay boundary', () => {
  const resources = renderAlertRelay(config);
  const deployment = resources.find((resource) => resource.kind === 'Deployment');
  const service = resources.find((resource) => resource.kind === 'Service');
  const cilium = resources.find((resource) => resource.kind === 'CiliumNetworkPolicy');
  const alertmanager = resources.find((resource) => resource.kind === 'AlertmanagerConfig');
  assert.equal(service.spec.type, 'ClusterIP');
  assert.equal(deployment.spec.template.spec.automountServiceAccountToken, false);
  assert.equal(deployment.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem, true);
  assert.equal(deployment.spec.template.spec.containers[0].env.some((item) => item.name === 'RESEND_API_KEY'), false);
  assert.deepEqual(cilium.spec.egress[0].toPorts[0].rules.dns, [{ matchPattern: '*' }]);
  assert.deepEqual(cilium.spec.egress[1].toFQDNs, [{ matchName: 'api.resend.com' }]);
  assert.equal(alertmanager.spec.receivers[0].webhookConfigs[0].httpConfig.authorization.credentials.key, 'webhook-token');
});

test('rejects unpinned images and unverified-sender shapes', () => {
  assert.throws(() => validateAlertRelayConfig({ ...config, image: 'registry.example.invalid/dirizhor/alert-relay:latest' }));
  assert.throws(() => validateAlertRelayConfig({ ...config, image: 'registry.example.invalid/dirizhor/alert-relay@sha256:0000000000000000000000000000000000000000000000000000000000000000' }));
  assert.throws(() => validateAlertRelayConfig({ ...config, sender: 'Dirizhor <alerts@alerts.baza.fyi>' }));
});

test('emits non-sensitive deterministic Resend messages for critical payloads', () => {
  const payload = validateAlertPayload({
    status: 'firing',
    alerts: [{ labels: { alertname: 'DirizhorReadinessUnavailable', severity: 'critical', service: 'director', namespace: 'dirizhor-pilot' }, fingerprint: 'fd2ac0' }],
  });
  const first = composeEmail(payload, { from: config.sender, to: config.recipient });
  const second = composeEmail(payload, { from: config.sender, to: config.recipient });
  assert.equal(first.idempotencyKey, second.idempotencyKey);
  assert.match(first.idempotencyKey, /^dirizhor-[0-9a-f]{64}$/);
  assert.equal(first.text.includes('annotations'), false);
  assert.throws(() => validateAlertPayload({ status: 'firing', alerts: [{ labels: { alertname: 'Unsafe', severity: 'warning' } }] }));
});
