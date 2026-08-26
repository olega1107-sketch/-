import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflow = await readFile('.github/workflows/pilot-inference-oci-release.yml', 'utf8');

test('internal inference release is manual, protected, immutable, and fail-closed', () => {
  assert.match(workflow, /workflow_dispatch:/);
  assert.doesNotMatch(workflow, /pull_request:|push:/);
  assert.match(workflow, /environment: digitalocean-pilot/);
  assert.match(workflow, /permissions:\n  contents: read\n  id-token: write/);
  assert.match(workflow, /Qwen3-4B-Q4_K_M\.gguf/);
  assert.match(workflow, /bc640142c66e1fdd12af0bd68f40445458f3869b/);
  assert.match(workflow, /7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5/);
  assert.match(workflow, /llama\.cpp:server@sha256:[0-9a-f]{64}/);
  assert.match(workflow, /--severity HIGH,CRITICAL/);
  assert.match(workflow, /Suppressions are prohibited/);
  assert.match(workflow, /cosign sign --yes/);
  assert.match(workflow, /cosign attest --yes --type cyclonedx/);
  assert.match(workflow, /docker logout/);
});
