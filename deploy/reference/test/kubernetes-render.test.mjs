import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  buildKubernetesBundles,
  renderKubernetesTarget,
  validateKubernetesTargetConfig,
  validateRenderedResources,
} from '../scripts/kubernetes-render.mjs';

const digest = (character) => `sha256:${character.repeat(64)}`;

test('target config rejects mutable images, unsafe exposure, and unsupported scaling', () => {
  const config = validConfig();
  assert.doesNotThrow(() => validateKubernetesTargetConfig(config));
  assert.throws(
    () => validateKubernetesTargetConfig({ ...config, images: { ...config.images, edge: 'registry.invalid/dirizhor/edge:latest' } }),
    /digest-only image/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({ ...config, replicas: { ...config.replicas, director: 2 } }),
    /one stateful Director\/Gateway/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({ ...config, public: { ...config.public, load_balancer_source_ranges: ['0.0.0.0/0'] } }),
    /source ranges must be explicit/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({ ...config, agent_routes: config.agent_routes.map((route, index) => index === 0 ? { ...route, provider: 'fixture' } : route) }),
    /Agent route is invalid/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({ ...config, agent_routes: config.agent_routes.map((route) => route.provider === 'openai' ? { ...route, deployment_class: 'internal', provider_data_profile_version: null } : route) }),
    /deployment-class policy/,
  );
});

test('renderer writes ordered private bundles without Secret or PostgreSQL workloads', async () => {
  const fixture = await fixtureDirectories();
  try {
    const evidence = await renderKubernetesTarget({
      config: validConfig(),
      outputDirectory: fixture.output,
      workspaceRoot: fixture.workspace,
    });
    assert.deepEqual(evidence.apply_order, [
      '00-prerequisites.json',
      '10-migration-job.json',
      '20-workloads.json',
    ]);
    assert.equal(evidence.files.reduce((sum, file) => sum + file.resource_count, 0), 23);
    assert.equal(evidence.secret_resources_included, false);
    assert.match(evidence.render_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.equal((await stat(fixture.output)).mode & 0o777, 0o700);
    for (const file of [...evidence.apply_order, 'render-evidence.json']) {
      assert.equal((await stat(path.join(fixture.output, file))).mode & 0o777, 0o600);
    }
    const resources = await renderedResources(fixture.output, evidence.apply_order);
    assert.equal(resources.some((resource) => resource.kind === 'Secret'), false);
    assert.equal(resources.some((resource) => /postgres/i.test(resource.metadata?.name ?? '') && ['Deployment', 'StatefulSet'].includes(resource.kind)), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('rendered resources use restricted pods, digest images, runtime migrator, and target cluster domain', () => {
  const config = validConfig();
  config.networking.cluster_domain = 'corp.internal';
  const resources = allResources(buildKubernetesBundles(config));
  const report = validateRenderedResources(resources, config);
  assert.equal(report.status, 'ok');

  const serviceAccounts = resources.filter((resource) => resource.kind === 'ServiceAccount');
  assert.ok(serviceAccounts.every((account) => account.automountServiceAccountToken === false && account.spec === undefined));
  const directorConfig = resources.find((resource) => resource.kind === 'ConfigMap' && resource.metadata.name === 'dirizhor-director-config');
  assert.match(directorConfig.data.GATEWAY_BASE_URL, /\.svc\.corp\.internal:8443$/);
  const gatewayConfig = resources.find((resource) => resource.kind === 'ConfigMap' && resource.metadata.name === 'dirizhor-gateway-config');
  assert.equal(gatewayConfig.data.INTERNAL_PROVIDER_ORIGIN, config.internal_provider.origin);
  assert.equal(gatewayConfig.data.INTERNAL_PROVIDER_MODELS, 'approved-internal-model');
  const gateway = deployment(resources, 'gateway');
  assert.ok(gateway.spec.template.spec.volumes.some((volume) => volume.name === 'internal-provider-tls'));
  const job = resources.find((resource) => resource.kind === 'Job');
  assert.deepEqual(job.spec.template.spec.containers[0].command, ['node', 'dist/db-migrate-cli.js', 'migrate']);
});

test('manifest validator blocks root, mutable image, embedded Secret, and migration drift', () => {
  const config = validConfig();
  const cases = [
    {
      pattern: /restricted runtime contract/,
      mutate(resources) {
        deployment(resources, 'director').spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem = false;
      },
    },
    {
      pattern: /restricted runtime contract/,
      mutate(resources) {
        deployment(resources, 'edge').spec.template.spec.containers[0].image = 'registry.invalid/edge:latest';
      },
    },
    {
      pattern: /must not contain secret material/,
      mutate(resources) {
        resources.push({ apiVersion: 'v1', kind: 'Secret', metadata: { name: 'leak', namespace: config.namespace } });
      },
    },
    {
      pattern: /compiled runtime migrator/,
      mutate(resources) {
        resources.find((resource) => resource.kind === 'Job').spec.template.spec.containers[0].command = ['pnpm', 'db:migrate'];
      },
    },
  ];
  for (const fixture of cases) {
    const resources = structuredClone(allResources(buildKubernetesBundles(config)));
    fixture.mutate(resources);
    assert.throws(() => validateRenderedResources(resources, config), fixture.pattern);
  }
});

test('render directory must be new and outside the workspace', async () => {
  const fixture = await fixtureDirectories();
  try {
    await assert.rejects(
      renderKubernetesTarget({
        config: validConfig(),
        outputDirectory: path.join(fixture.workspace, 'render'),
        workspaceRoot: fixture.workspace,
      }),
      /outside the source workspace/,
    );
    await mkdir(fixture.output);
    await assert.rejects(
      renderKubernetesTarget({
        config: validConfig(),
        outputDirectory: fixture.output,
        workspaceRoot: fixture.workspace,
      }),
      /EEXIST/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

function validConfig() {
  return {
    schema_version: 1,
    deployment_id: 'pilot-2026-08-11-01',
    namespace: 'dirizhor-pilot',
    kubernetes_version: 'v1.34',
    images: {
      director: `registry.invalid/dirizhor/director@${digest('a')}`,
      gateway: `registry.invalid/dirizhor/gateway@${digest('b')}`,
      edge: `registry.invalid/dirizhor/edge@${digest('c')}`,
    },
    replicas: { edge: 2, director: 1, gateway: 1 },
    public: {
      host: 'dirizhor.example.invalid',
      max_body_size: '26m',
      load_balancer_source_ranges: ['198.51.100.0/24'],
      load_balancer_annotations: { 'service.beta.kubernetes.io/example-class': 'approved' },
    },
    networking: {
      cluster_domain: 'cluster.local',
      dns_namespace: 'kube-system',
      trusted_proxy_cidrs: ['10.70.0.0/24'],
      postgresql_cidrs: ['192.0.2.10/32'],
      postgresql_port: 5432,
      oidc_egress_cidrs: ['192.0.2.20/32'],
      internal_provider_egress_cidrs: ['10.80.0.10/32'],
      ai_provider_egress_cidrs: ['192.0.2.30/32'],
    },
    oidc: {
      issuer_url: 'https://idp.example.invalid',
      client_id: 'dirizhor-pilot',
      scopes: ['openid', 'profile', 'email'],
      id_token_signing_algorithm: 'RS256',
    },
    internal_provider: {
      origin: 'https://inference.internal.test',
      models: ['approved-internal-model'],
    },
    agent_routes: [
      {
        agent_type: 'canary_internal',
        provider: 'internal',
        model: 'approved-internal-model',
        deployment_class: 'internal',
        provider_data_profile_version: null,
      },
      {
        agent_type: 'architect',
        provider: 'openai',
        model: 'approved-model',
        deployment_class: 'external',
        provider_data_profile_version: 'approved-profile-v1',
      },
    ],
    secrets: {
      image_pull: 'dirizhor-registry-auth',
      service_tokens: 'dirizhor-service-tokens',
      director_runtime: 'dirizhor-director-runtime',
      director_tls: 'dirizhor-director-tls',
      director_gateway_client_tls: 'dirizhor-director-gateway-client-tls',
      gateway_runtime: 'dirizhor-gateway-runtime',
      gateway_tls: 'dirizhor-gateway-tls',
      gateway_director_client_tls: 'dirizhor-gateway-director-client-tls',
      gateway_probe_client_tls: 'dirizhor-gateway-probe-client-tls',
      gateway_internal_provider_tls: 'dirizhor-gateway-internal-provider-tls',
      edge_tls: 'dirizhor-edge-tls',
      edge_director_ca: 'dirizhor-edge-director-ca',
      postgres_ca: 'dirizhor-postgres-ca',
      migration_database: 'dirizhor-migration-database',
    },
    storage: {
      director: { storage_class_name: 'encrypted-rwo', size: '100Gi' },
      gateway: { storage_class_name: 'encrypted-rwo', size: '20Gi' },
    },
    resources: {
      edge: resource('100m', '128Mi', '500m', '256Mi'),
      director: resource('250m', '512Mi', '1000m', '1Gi'),
      gateway: resource('250m', '512Mi', '1000m', '1Gi'),
      migration: resource('100m', '256Mi', '500m', '512Mi'),
    },
  };
}

function resource(requestCpu, requestMemory, limitCpu, limitMemory) {
  return {
    requests: { cpu: requestCpu, memory: requestMemory, 'ephemeral-storage': '128Mi' },
    limits: { cpu: limitCpu, memory: limitMemory, 'ephemeral-storage': '256Mi' },
  };
}

async function fixtureDirectories() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-kubernetes-render-'));
  const workspace = path.join(root, 'workspace');
  await mkdir(workspace);
  return { root, workspace, output: path.join(root, 'render') };
}

function allResources(bundles) {
  return Object.values(bundles).flatMap((bundle) => bundle.items);
}

async function renderedResources(directory, files) {
  const resources = [];
  for (const file of files) {
    const bundle = JSON.parse(await readFile(path.join(directory, file), 'utf8'));
    resources.push(...bundle.items);
  }
  return resources;
}

function deployment(resources, component) {
  return resources.find((resource) =>
    resource.kind === 'Deployment' &&
    resource.metadata.labels['app.kubernetes.io/component'] === component,
  );
}
