import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL(
  '../../../.github/workflows/pilot-application-canary.yml',
  import.meta.url,
);

test('pilot application canary is manual, protected, and keeps its session outside Git', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');

  assert.match(workflow, /^  workflow_dispatch:$/m);
  assert.equal(/^  (?:push|pull_request):/m.test(workflow), false);
  assert.match(workflow, /^permissions:\n  contents: read$/m);
  assert.match(workflow, /^    environment: digitalocean-pilot$/m);
  assert.match(workflow, /secrets\.DIRIZHOR_APPLICATION_CANARY_CONFIG/);
  assert.match(workflow, /secrets\.DIRIZHOR_APPLICATION_CANARY_SESSION_TOKEN/);
  assert.match(workflow, /node deploy\/reference\/scripts\/application-canary\.mjs/);
  assert.match(workflow, /::add-mask::\$\{CANARY_SESSION_TOKEN\}/);
  assert.match(workflow, /chmod 0600/);
  assert.match(workflow, /rm -f "\$\{CANARY_INPUT_DIRECTORY\}/);
  assert.match(workflow, /if-no-files-found: warn/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.equal(workflow.includes('DIGITALOCEAN_ACCESS_TOKEN'), false);
  assert.equal(workflow.includes('KUBECONFIG'), false);
  assert.equal(workflow.includes('kubectl '), false);
  assert.equal(workflow.includes('terraform '), false);
  assert.equal(workflow.includes(':latest'), false);
  assert.equal(workflow.match(/secrets\./g)?.length, 2);
});
