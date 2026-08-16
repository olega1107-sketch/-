import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../../../.github/workflows/architecture-ci.yml', import.meta.url);

test('architecture CI is immutable, read-only, and cannot publish', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');

  assert.match(workflow, /^permissions:\n  contents: read$/m);
  assert.match(workflow, /^  NODE_VERSION: 24\.19\.0$/m);
  assert.match(workflow, /^  PNPM_VERSION: 11\.16\.0$/m);
  assert.equal(
    workflow.match(
      /actions\/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6\.0\.2/g,
    )?.length,
    2,
  );
  assert.equal(
    workflow.match(
      /actions\/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6\.5\.0/g,
    )?.length,
    2,
  );
  assert.match(
    workflow,
    /pnpm\/action-setup@0977fd99725f1db4007ccb2928dbb4e90d06cc86 # v6\.0\.10/,
  );
  assert.match(workflow, /persist-credentials: false/g);
  assert.match(workflow, /package-manager-cache: false/g);
  assert.match(workflow, /version: \$\{\{ env\.PNPM_VERSION \}\}/);
  assert.match(workflow, /run_install: false/);
  assert.match(workflow, /run: pnpm test --maxWorkers=2/);
  assert.match(workflow, /working-directory: \$\{\{ matrix\.working_directory \}\}/);
  assert.equal(workflow.includes('matrix.working-directory'), false);
  assert.match(workflow, /node --test deploy\/reference\/test\/\*\.test\.mjs/);
  assert.match(workflow, /node deploy\/reference\/scripts\/container-preflight\.mjs/);

  for (const forbidden of [
    'packages: write',
    'id-token: write',
    'docker/login-action',
    'docker/build-push-action',
    'push: true',
    'AZURE_',
    'secrets.',
  ]) {
    assert.equal(workflow.includes(forbidden), false, `workflow contains ${forbidden}`);
  }
});
