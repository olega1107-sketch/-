import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL(
  '../../../.github/workflows/pilot-oci-release.yml',
  import.meta.url,
);
const nodeBuildUrl = new URL('../Dockerfile.node-build', import.meta.url);
const restoreVerifierWorkflowUrl = new URL(
  '../../../.github/workflows/restore-verifier-oci-release.yml',
  import.meta.url,
);
const alertRelayWorkflowUrl = new URL(
  '../../../.github/workflows/alert-relay-oci-release.yml',
  import.meta.url,
);

test('pilot OCI release is manual, pinned, protected, and fail-closed', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');

  assert.match(workflow, /^  workflow_dispatch:$/m);
  assert.equal(/^  (?:push|pull_request):/m.test(workflow), false);
  assert.match(workflow, /^  contents: read$/m);
  assert.match(workflow, /^  id-token: write$/m);
  assert.match(workflow, /^    environment: digitalocean-pilot$/m);
  assert.match(
    workflow,
    /secrets\.DIGITALOCEAN_ACCESS_TOKEN/,
  );
  assert.match(workflow, /--password-stdin/);
  assert.match(workflow, /docker login "\$\{REGISTRY_HOST\}"/);
  assert.equal(workflow.includes('DOCKER_CONFIG='), false);
  assert.match(workflow, /rm -f "\$\{HOME\}\/\.docker\/config\.json"/);
  assert.match(workflow, /if-no-files-found: warn/);
  assert.match(workflow, /cancel-in-progress: false/);

  for (const pinnedAction of [
    'actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd',
    'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
    'docker/setup-docker-action@e43656e248c0bd0647d3f5c195d116aacf6fcaf4',
    'docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f',
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  ]) {
    assert.match(workflow, new RegExp(pinnedAction));
  }

  for (const exactControl of [
    'DOCKER_VERSION: 28.3.3',
    'BUILDX_VERSION: 0.28.0',
    'SYFT_VERSION: 1.45.1',
    'TRIVY_VERSION: 0.74.0',
    'COSIGN_VERSION: 3.0.2',
    '20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716',
    '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
    '46dbdcb5467a3dfec2526923d0b3365e40c8d9dc00ec23d5aca3437449e8cbfd',
    'node:24.19.0-alpine3.24@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43',
    'nginx-unprivileged:1.31.4-alpine3.24-slim@sha256:021f32b23e2bfc8610ccdec499b709625dcee1369884d7a51bd8a23a3accb301',
  ]) {
    assert.equal(workflow.includes(exactControl), true, `missing ${exactControl}`);
  }

  for (const required of [
    '--provenance=mode=max',
    '--sbom=true',
    '--severity HIGH,CRITICAL',
    '--exit-on-eol 1',
    'cosign sign --yes',
    'cosign verify --output json',
    'cosign verify-attestation --type cyclonedx',
    'node deploy/reference/scripts/oci-release.mjs',
    'registry.digitalocean.com/dirizherpilotregistry',
    'digitalocean-pilot',
  ]) {
    assert.equal(workflow.includes(required), true, `missing ${required}`);
  }

  assert.equal(workflow.includes(':latest'), false);
  assert.equal(workflow.match(/secrets\./g)?.length, 1);
  assert.equal(
    /SIGSTORE_ID_TOKEN=.*GITHUB_ENV/.test(workflow),
    false,
    'short-lived signing token must remain step-scoped',
  );
});

test('restore verifier OCI release is manual, protected, digest-only, and isolated', async () => {
  const workflow = await readFile(restoreVerifierWorkflowUrl, 'utf8');

  assert.match(workflow, /^  workflow_dispatch:$/m);
  assert.equal(/^  (?:push|pull_request):/m.test(workflow), false);
  assert.match(workflow, /^  contents: read$/m);
  assert.match(workflow, /^  id-token: write$/m);
  assert.match(workflow, /^    environment: digitalocean-pilot$/m);
  assert.match(workflow, /director\/reference\/Dockerfile\.restore-verifier/);
  assert.match(workflow, /--platform linux\/amd64/);
  assert.match(workflow, /--provenance=mode=max/);
  assert.match(workflow, /--sbom=true/);
  assert.match(workflow, /--severity HIGH,CRITICAL/);
  assert.match(workflow, /--exit-on-eol 1/);
  assert.match(workflow, /cosign sign --yes/);
  assert.match(workflow, /cosign verify-attestation --type cyclonedx/);
  assert.match(workflow, /VERIFIER_IMAGE_REPOSITORY: node-build/);
  assert.match(workflow, /image="\$\{REGISTRY\}\/\$\{VERIFIER_IMAGE_REPOSITORY\}:restore-verifier-\$\{RELEASE_SUFFIX\}"/);
  assert.match(workflow, /image_ref="\$\{REGISTRY\}\/\$\{VERIFIER_IMAGE_REPOSITORY\}@\$\{digest\}"/);
  assert.match(workflow, /secrets\.DIGITALOCEAN_ACCESS_TOKEN/);
  assert.match(workflow, /rm -f "\$\{HOME\}\/\.docker\/config\.json"/);
  assert.equal(workflow.includes(':latest'), false);
  assert.equal(workflow.match(/secrets\./g)?.length, 1);
});

test('alert relay OCI release is manual, private, and fail-closed', async () => {
  const workflow = await readFile(alertRelayWorkflowUrl, 'utf8');

  assert.match(workflow, /^  workflow_dispatch:$/m);
  assert.equal(/^  (?:push|pull_request):/m.test(workflow), false);
  assert.match(workflow, /^  contents: read$/m);
  assert.match(workflow, /^  id-token: write$/m);
  assert.match(workflow, /^    environment: digitalocean-pilot$/m);
  assert.match(workflow, /deploy\/reference\/monitoring\/Dockerfile\.alert-relay/);
  assert.match(workflow, /RELAY_IMAGE_REPOSITORY: node-build/);
  assert.match(workflow, /--platform linux\/amd64/);
  assert.match(workflow, /--provenance=mode=max/);
  assert.match(workflow, /--sbom=true/);
  assert.match(workflow, /--severity HIGH,CRITICAL/);
  assert.match(workflow, /--exit-on-eol 1/);
  assert.match(workflow, /cosign sign --yes/);
  assert.match(workflow, /cosign verify-attestation --type cyclonedx/);
  assert.match(workflow, /secrets\.DIGITALOCEAN_ACCESS_TOKEN/);
  assert.match(workflow, /rm -f "\$\{HOME\}\/\.docker\/config\.json"/);
  assert.equal(workflow.includes(':latest'), false);
  assert.equal(workflow.match(/secrets\./g)?.length, 1);
});

test('Node build image pins its parent and exact package manager', async () => {
  const dockerfile = await readFile(nodeBuildUrl, 'utf8');

  assert.match(dockerfile, /^# syntax=docker\/dockerfile:1\.7$/m);
  assert.match(dockerfile, /^FROM \$\{NODE_RUNTIME_IMAGE\}$/m);
  assert.match(dockerfile, /@sha256:\[0-9a-f\]\{64\}/);
  assert.match(dockerfile, /test "\$\{PNPM_VERSION\}" = "11\.18\.0"/);
  assert.match(dockerfile, /corepack prepare "pnpm@\$\{PNPM_VERSION\}" --activate/);
  assert.match(dockerfile, /test "\$\(pnpm --version\)" = "\$\{PNPM_VERSION\}"/);
  assert.match(dockerfile, /rm -rf \/usr\/local\/lib\/node_modules\/npm/);
  assert.match(dockerfile, /rm -f \/usr\/local\/bin\/npm \/usr\/local\/bin\/npx/);
  assert.match(dockerfile, /test ! -L \/usr\/local\/bin\/npm/);
  assert.match(dockerfile, /node --version >\/dev\/null/);
  assert.equal(dockerfile.includes(':latest'), false);
});
