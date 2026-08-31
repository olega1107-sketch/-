import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('operational alert thresholds match the approved pilot adoption decision', async () => {
  const rules = await readFile(new URL('../monitoring/alert-rules.yaml', import.meta.url), 'utf8');
  const monitors = await readFile(new URL('../monitoring/service-monitors.yaml', import.meta.url), 'utf8');
  assert.match(rules, /for: 120s/);
  assert.match(rules, /> 0\.01/);
  assert.match(rules, /\[5m\]/);
  assert.match(rules, /> 1\.5/);
  assert.match(rules, /DirizhorMetricsTargetMissing/);
  assert.match(rules, /DirizhorPostgresUnavailable/);
  assert.match(rules, /DirizhorDocumentStoreUnavailable/);
  assert.match(rules, /DirizhorAuditWriteFailure/);
  assert.match(rules, /DirizhorGatewayQueueStuck/);
  assert.match(rules, /DirizhorGatewayQueueScanFailure/);
  assert.match(rules, /DirizhorPrometheusConfigReloadFailed/);
  assert.match(rules, /DirizhorAlertmanagerConfigReloadFailed/);
  assert.match(rules, /DirizhorAlertmanagerNotificationFailure/);
  assert.match(monitors, /dirizhor-prometheus-control-plane/);
  assert.match(monitors, /operated-prometheus: "true"/);
  assert.match(monitors, /dirizhor-alertmanager-control-plane/);
  assert.match(monitors, /operated-alertmanager: "true"/);
});
