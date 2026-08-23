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
const externalOnlyExampleUrl = new URL('../kubernetes-target-config.external-only.example.json', import.meta.url);

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
    () => validateKubernetesTargetConfig({ ...config, public: { ...config.public, load_balancer_annotations: { unsafe: 'annotation' } } }),
    /must not include load balancer annotations/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({ ...config, agent_routes: config.agent_routes.map((route, index) => index === 0 ? { ...route, provider: 'fixture' } : route) }),
    /Agent route is invalid/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({ ...config, agent_routes: config.agent_routes.map((route) => route.provider === 'openai' ? { ...route, deployment_class: 'internal', provider_data_profile_version: null } : route) }),
    /deployment-class policy/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({ ...config, postgresql: { ...config.postgresql, runtime_role: 'invalid role' } }),
    /runtime role is invalid/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({
      ...config,
      networking: { ...config.networking, oidc_egress_fqdns: ['*.example.test'] },
    }),
    /exact DNS names without wildcards/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({
      ...config,
      networking: { ...config.networking, ai_provider_egress_fqdns: ['localhost'] },
    }),
    /exact DNS names without wildcards/,
  );
  assert.throws(
    () => validateKubernetesTargetConfig({
      ...config,
      networking: {
        ...config.networking,
        oidc_egress_cidrs: [],
        oidc_egress_fqdns: [],
      },
    }),
    /must allow the provider endpoint/,
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
      '15-runtime-privilege-job.json',
      '20-workloads.json',
    ]);
    assert.equal(evidence.files.reduce((sum, file) => sum + file.resource_count, 0), 27);
    assert.equal(evidence.secret_resources_included, false);
    assert.equal(evidence.target_schema_version, 3);
    assert.equal(evidence.exposure, 'internal');
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
  const edgeService = resources.find((resource) => resource.kind === 'Service' && resource.metadata.name === 'dirizhor-edge');
  assert.equal(edgeService.spec.type, 'ClusterIP');
  assert.equal(edgeService.spec.externalTrafficPolicy, undefined);
  assert.equal(edgeService.spec.loadBalancerSourceRanges, undefined);
  assert.equal(edgeService.metadata.annotations, undefined);
  const directorFqdnPolicy = resources.find(
    (resource) => resource.kind === 'CiliumNetworkPolicy' && resource.metadata.name === 'dirizhor-director-oidc-fqdn-egress',
  );
  assert.deepEqual(directorFqdnPolicy.spec.egress[0].toFQDNs, [
    { matchName: 'idp.example.test' },
    { matchName: 'tokens.example.test' },
  ]);
  const gatewayFqdnPolicy = resources.find(
    (resource) => resource.kind === 'CiliumNetworkPolicy' && resource.metadata.name === 'dirizhor-gateway-ai-fqdn-egress',
  );
  assert.deepEqual(gatewayFqdnPolicy.spec.egress[0].toFQDNs, [{ matchName: 'api.example.test' }]);
  const directorConfig = resources.find((resource) => resource.kind === 'ConfigMap' && resource.metadata.name === 'dirizhor-director-config');
  assert.match(directorConfig.data.GATEWAY_BASE_URL, /\.svc\.corp\.internal:8443$/);
  assert.equal(directorConfig.data.DIRECTOR_WORKLOAD_SIGNING_KEY_ID, 'director-2026-08-a');
  assert.equal(directorConfig.data.DIRECTOR_WORKLOAD_TOKEN_TTL_SECONDS, '60');
  const gatewayConfig = resources.find((resource) => resource.kind === 'ConfigMap' && resource.metadata.name === 'dirizhor-gateway-config');
  assert.equal(gatewayConfig.data.INTERNAL_PROVIDER_ORIGIN, config.internal_provider.origin);
  assert.equal(gatewayConfig.data.INTERNAL_PROVIDER_MODELS, 'approved-internal-model');
  const gateway = deployment(resources, 'gateway');
  assert.ok(gateway.spec.template.spec.volumes.some((volume) => volume.name === 'internal-provider-tls'));
  assert.ok(gateway.spec.template.spec.volumes.some((volume) => volume.name === 'workload-identity'));
  assert.equal(
    gateway.spec.template.spec.containers[0].volumeMounts.find((mount) => mount.name === 'state').mountPath,
    '/var/lib/dirizhor',
  );
  const gatewayEnvNames = gateway.spec.template.spec.containers[0].env.map((entry) => entry.name);
  assert.ok(gatewayEnvNames.includes('GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64_FILE'));
  assert.ok(gatewayEnvNames.includes('DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON_FILE'));
  assert.equal(gatewayEnvNames.includes('GATEWAY_DIRECTOR_TOKEN_FILE'), false);
  const director = deployment(resources, 'director');
  assert.equal(
    director.spec.template.spec.containers[0].volumeMounts.find((mount) => mount.name === 'documents').mountPath,
    '/var/lib/dirizhor',
  );
  const edge = deployment(resources, 'edge');
  assert.equal(
    edge.spec.template.spec.volumes.find((volume) => volume.name === 'edge-secrets').projected.defaultMode,
    0o440,
  );
  const migration = job(resources, 'migration');
  assert.deepEqual(migration.spec.template.spec.containers[0].command, ['node', 'dist/db-migrate-cli.js', 'migrate']);
  const privilege = job(resources, 'runtime-privilege');
  assert.deepEqual(privilege.spec.template.spec.containers[0].command, ['node', 'dist/postgres-runtime-privilege-cli.js']);
  assert.equal(
    privilege.spec.template.spec.volumes.find((volume) => volume.name === 'director-runtime').secret.secretName,
    config.secrets.director_database,
  );
  assert.deepEqual(
    privilege.spec.template.spec.containers[0].env
      .filter((entry) => entry.name.startsWith('DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_'))
      .map((entry) => [entry.name, entry.value]),
    [
      ['DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_DATABASE', config.postgresql.database_name],
      ['DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_ROLE', config.postgresql.runtime_role],
    ],
  );
});

test('legacy schema keeps the explicit load balancer contract', () => {
  const config = cidrSchemaConfig(1);
  config.public.load_balancer_annotations = {
    'service.beta.kubernetes.io/example-class': 'approved',
  };

  const normalized = validateKubernetesTargetConfig(config);
  assert.equal(normalized.public.exposure, 'load-balancer');
  const resources = allResources(buildKubernetesBundles(normalized));
  assert.equal(validateRenderedResources(resources, normalized).status, 'ok');
  const edgeService = resources.find((resource) => resource.kind === 'Service' && resource.metadata.name === 'dirizhor-edge');
  assert.equal(edgeService.spec.type, 'LoadBalancer');
  assert.deepEqual(edgeService.spec.loadBalancerSourceRanges, config.public.load_balancer_source_ranges);
  assert.deepEqual(edgeService.metadata.annotations, config.public.load_balancer_annotations);
});

test('schema v2 supports an explicitly selected load balancer exposure', () => {
  const config = cidrSchemaConfig(2);
  config.public.exposure = 'load-balancer';
  config.public.load_balancer_annotations = {
    'service.beta.kubernetes.io/example-class': 'approved',
  };

  const normalized = validateKubernetesTargetConfig(config);
  assert.equal(normalized.public.exposure, 'load-balancer');
  const resources = allResources(buildKubernetesBundles(normalized));
  assert.equal(validateRenderedResources(resources, normalized).status, 'ok');
  const edgeService = resources.find((resource) => resource.kind === 'Service' && resource.metadata.name === 'dirizhor-edge');
  assert.equal(edgeService.spec.type, 'LoadBalancer');
  assert.deepEqual(edgeService.spec.loadBalancerSourceRanges, config.public.load_balancer_source_ranges);
  assert.deepEqual(edgeService.metadata.annotations, config.public.load_balancer_annotations);
});

test('schema v4 supports an external-only target without internal provider access', () => {
  const config = externalOnlyConfig();
  const normalized = validateKubernetesTargetConfig(config);
  const resources = allResources(buildKubernetesBundles(normalized));
  assert.equal(validateRenderedResources(resources, normalized).status, 'ok');

  const gatewayConfig = resources.find(
    (resource) => resource.kind === 'ConfigMap' && resource.metadata.name === 'dirizhor-gateway-config',
  );
  assert.equal(Object.keys(gatewayConfig.data).some((name) => name.startsWith('INTERNAL_PROVIDER_')), false);

  const gateway = deployment(resources, 'gateway');
  const container = gateway.spec.template.spec.containers[0];
  assert.equal(container.env.some((entry) => entry.name === 'INTERNAL_PROVIDER_TOKEN_FILE'), false);
  assert.equal(container.volumeMounts.some((mount) => mount.name === 'internal-provider-tls'), false);
  assert.equal(gateway.spec.template.spec.volumes.some((volume) => volume.name === 'internal-provider-tls'), false);

  const gatewayPolicy = resources.find(
    (resource) => resource.kind === 'NetworkPolicy' && resource.metadata.name === 'dirizhor-gateway',
  );
  assert.equal(
    gatewayPolicy.spec.egress.some((rule) => rule.to?.some((peer) => peer.ipBlock?.cidr === '10.80.0.10/32')),
    false,
  );
});

test('schema v4 external-only example stays renderable', async () => {
  const config = JSON.parse(await readFile(externalOnlyExampleUrl, 'utf8'));
  const normalized = validateKubernetesTargetConfig(config);
  const resources = allResources(buildKubernetesBundles(normalized));
  assert.equal(validateRenderedResources(resources, normalized).status, 'ok');
});

test('schema v4 keeps the dual-provider contract when an internal provider is configured', () => {
  const config = validConfig();
  config.schema_version = 4;
  const normalized = validateKubernetesTargetConfig(config);
  assert.equal(normalized.internal_provider.origin, config.internal_provider.origin);
  assert.equal(validateRenderedResources(allResources(buildKubernetesBundles(normalized)), normalized).status, 'ok');
});

test('schema v4 external-only target rejects internal provider remnants', () => {
  const base = externalOnlyConfig();
  const legacy = structuredClone(base);
  legacy.schema_version = 3;
  legacy.networking.internal_provider_egress_cidrs = ['10.80.0.10/32'];
  assert.throws(() => validateKubernetesTargetConfig(legacy), /required before schema v4/);

  const route = structuredClone(base);
  route.agent_routes.unshift(validConfig().agent_routes[0]);
  assert.throws(() => validateKubernetesTargetConfig(route), /must not contain internal agent routes/);

  const egress = structuredClone(base);
  egress.networking.internal_provider_egress_cidrs = ['10.80.0.10/32'];
  assert.throws(() => validateKubernetesTargetConfig(egress), /must not allow internal provider egress/);

  const secret = structuredClone(base);
  secret.secrets.gateway_internal_provider_tls = 'dirizhor-gateway-internal-provider-tls';
  assert.throws(() => validateKubernetesTargetConfig(secret), /must not reference an internal provider TLS Secret/);
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
        job(resources, 'migration').spec.template.spec.containers[0].command = ['pnpm', 'db:migrate'];
      },
    },
    {
      pattern: /compiled read-only probe/,
      mutate(resources) {
        job(resources, 'runtime-privilege').spec.template.spec.containers[0].command = ['pnpm', 'db:runtime-privileges'];
      },
    },
    {
      pattern: /persistent volume must contain/,
      mutate(resources) {
        deployment(resources, 'director').spec.template.spec.containers[0].volumeMounts
          .find((mount) => mount.name === 'documents').mountPath = '/var/lib/dirizhor/documents';
      },
    },
    {
      pattern: /projected TLS material must use mode 0440/,
      mutate(resources) {
        deployment(resources, 'edge').spec.template.spec.volumes
          .find((volume) => volume.name === 'edge-secrets').projected.defaultMode = 0o644;
      },
    },
    {
      pattern: /Cilium FQDN policy/,
      mutate(resources) {
        const policy = resources.find(
          (resource) => resource.kind === 'CiliumNetworkPolicy' && resource.metadata.name === 'dirizhor-director-oidc-fqdn-egress',
        );
        policy.spec.egress[0].toFQDNs = [{ matchPattern: '*' }];
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
    schema_version: 3,
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
      exposure: 'internal',
      host: 'dirizhor.example.invalid',
      max_body_size: '26m',
      load_balancer_source_ranges: ['198.51.100.0/24'],
      load_balancer_annotations: {},
    },
    networking: {
      cluster_domain: 'cluster.local',
      dns_namespace: 'kube-system',
      trusted_proxy_cidrs: ['10.70.0.0/24'],
      postgresql_cidrs: ['192.0.2.10/32'],
      postgresql_port: 5432,
      oidc_egress_cidrs: [],
      oidc_egress_fqdns: ['idp.example.test', 'tokens.example.test'],
      internal_provider_egress_cidrs: ['10.80.0.10/32'],
      ai_provider_egress_cidrs: [],
      ai_provider_egress_fqdns: ['api.example.test'],
    },
    postgresql: {
      database_name: 'dirizhor_pilot',
      runtime_role: 'dirizhor_runtime',
    },
    oidc: {
      issuer_url: 'https://idp.example.invalid',
      client_id: 'dirizhor-pilot',
      scopes: ['openid', 'profile', 'email'],
      id_token_signing_algorithm: 'RS256',
    },
    workload_identity: {
      director_signing_key_id: 'director-2026-08-a',
      gateway_signing_key_id: 'gateway-2026-08-a',
      token_ttl_seconds: 60,
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
      director_workload_identity: 'dirizhor-director-workload-identity',
      gateway_workload_identity: 'dirizhor-gateway-workload-identity',
      director_runtime: 'dirizhor-director-runtime',
      director_database: 'dirizhor-director-database',
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

function cidrSchemaConfig(schemaVersion) {
  const config = validConfig();
  config.schema_version = schemaVersion;
  config.networking.oidc_egress_cidrs = ['192.0.2.20/32'];
  config.networking.ai_provider_egress_cidrs = ['192.0.2.30/32'];
  delete config.networking.oidc_egress_fqdns;
  delete config.networking.ai_provider_egress_fqdns;
  if (schemaVersion === 1) delete config.public.exposure;
  return config;
}

function externalOnlyConfig() {
  const config = validConfig();
  config.schema_version = 4;
  config.internal_provider = null;
  config.agent_routes = config.agent_routes.filter((route) => route.provider !== 'internal');
  config.networking.internal_provider_egress_cidrs = [];
  config.secrets.gateway_internal_provider_tls = null;
  return config;
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

function job(resources, component) {
  return resources.find((resource) =>
    resource.kind === 'Job' &&
    resource.metadata.labels['app.kubernetes.io/component'] === component,
  );
}
