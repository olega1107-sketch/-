import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('restore verifier remains isolated, read-only, digest-pinned and test-only', async () => {
  const dockerfile = await readFile(new URL('../../../director/reference/Dockerfile.restore-verifier', import.meta.url), 'utf8');
  const manifest = await readFile(new URL('../restore-verifier-template.yaml', import.meta.url), 'utf8');
  assert.match(dockerfile, /^# syntax=docker\/dockerfile:1\.7/m);
  assert.match(dockerfile, /USER 10001:10001/);
  assert.match(dockerfile, /document-store-evidence\.ts/);
  assert.match(manifest, /automountServiceAccountToken: false/);
  assert.match(manifest, /readOnly: true/g);
  assert.match(manifest, /readOnlyRootFilesystem: true/);
  assert.match(manifest, /__RESTORE_VERIFIER_IMAGE_DIGEST__/);
  assert.match(manifest, /__TEST_ONLY_DATABASE_SECRET__/);
  assert.match(manifest, /__RESTORE_POSTGRES_PRIVATE_CIDR__/);
  assert.doesNotMatch(manifest, /kind:\s*(LoadBalancer|Ingress)\b|type:\s*LoadBalancer\b|hostNetwork:\s*true/);
});
