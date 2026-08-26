import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const dnsLabelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const digestReferencePattern = /^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$/;
const executionIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;
const kubernetesVersionPattern = /^v1\.\d{2}$/;
const quantityPattern = /^(?:[1-9][0-9]*m|[1-9][0-9]*(?:Mi|Gi))$/;
const cidrPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[0-9]|[12][0-9]|3[0-2])$/;
const componentNames = ['edge', 'director', 'gateway'];
const resourceNames = ['director', 'gateway', 'edge', 'migration'];

export async function renderKubernetesTarget({
  config,
  outputDirectory,
  workspaceRoot = defaultWorkspaceRoot,
}) {
  const normalized = validateKubernetesTargetConfig(config);
  const root = path.resolve(workspaceRoot);
  const output = path.resolve(outputDirectory ?? '');
  if (outputDirectory === undefined || outputDirectory.length === 0) {
    throw new Error('A new protected render directory is required.');
  }
  if (insidePath(root, output)) {
    throw new Error('Rendered target manifests must be stored outside the source workspace.');
  }
  await mkdir(output, { mode: 0o700 });
  await chmod(output, 0o700);

  const bundles = buildKubernetesBundles(normalized);
  validateRenderedResources(
    Object.values(bundles).flatMap((bundle) => bundle.items),
    normalized,
  );
  const files = [];
  for (const [fileName, bundle] of Object.entries(bundles)) {
    const filePath = path.join(output, fileName);
    await writePrivateJson(filePath, bundle);
    files.push({
      file: fileName,
      resource_count: bundle.items.length,
      sha256: await fileHash(filePath),
    });
  }
  const manifestWithoutHash = {
    schema_version: 1,
    target_schema_version: normalized.schema_version,
    deployment_id: normalized.deployment_id,
    namespace: normalized.namespace,
    exposure: normalized.public.exposure,
    rendered_at: new Date().toISOString(),
    apply_order: [
      '00-prerequisites.json',
      '10-migration-job.json',
      '15-runtime-privilege-job.json',
      '20-workloads.json',
    ],
    secret_resources_included: false,
    files,
  };
  const manifest = {
    ...manifestWithoutHash,
    render_sha256: canonicalHash(manifestWithoutHash),
  };
  await writePrivateJson(path.join(output, 'render-evidence.json'), manifest);
  return manifest;
}

export function validateKubernetesTargetConfig(config) {
  assertObject(config, 'config');
  assertExactKeys(config, [
    'schema_version', 'deployment_id', 'namespace', 'kubernetes_version',
    'images', 'replicas', 'public', 'networking', 'postgresql', 'oidc', 'workload_identity', 'internal_provider', 'agent_routes',
    'secrets', 'storage', 'resources',
  ], 'config');
  if (![1, 2, 3, 4].includes(config.schema_version)) throw new Error('Unsupported Kubernetes target schema.');
  if (!executionIdPattern.test(config.deployment_id) || config.deployment_id.startsWith('replace-')) {
    throw new Error('A non-placeholder deployment ID is required.');
  }
  if (!dnsLabelPattern.test(config.namespace)) throw new Error('Kubernetes namespace is invalid.');
  if (!kubernetesVersionPattern.test(config.kubernetes_version)) {
    throw new Error('kubernetes_version must pin an exact v1 minor.');
  }
  const normalized = structuredClone(config);
  validateImages(normalized.images);
  validateReplicas(normalized.replicas);
  validatePublic(normalized.public, normalized.schema_version);
  validateInternalProvider(normalized.internal_provider, normalized.schema_version);
  validateNetworking(normalized.networking, normalized.schema_version, normalized.internal_provider !== null);
  validatePostgresql(normalized.postgresql);
  validateOidc(normalized.oidc, normalized.public.host);
  validateWorkloadIdentity(normalized.workload_identity);
  validateAgentRoutes(normalized.agent_routes, normalized.internal_provider?.models ?? [], normalized.internal_provider !== null);
  validateSecrets(normalized.secrets, normalized.internal_provider !== null);
  validateStorage(normalized.storage);
  validateResources(normalized.resources);
  return normalized;
}

export function buildKubernetesBundles(config) {
  const namespace = config.namespace;
  const names = serviceNames(namespace, config.networking.cluster_domain);
  const prerequisites = [
    namespaceResource(config),
    ...componentNames.map((component) => serviceAccount(namespace, component)),
    configMap(namespace, 'edge', edgeEnvironment(config, names)),
    configMap(namespace, 'director', directorEnvironment(config, names)),
    configMap(namespace, 'gateway', gatewayEnvironment(config, names)),
    persistentVolumeClaim(namespace, 'director', config.storage.director),
    persistentVolumeClaim(namespace, 'gateway', config.storage.gateway),
    internalService(namespace, 'director', 8444),
    internalService(namespace, 'gateway', 8443),
    edgeService(config),
    ...networkPolicies(config),
    ...ciliumFqdnPolicies(config),
    edgeDisruptionBudget(namespace),
  ];
  const migration = [migrationJob(config)];
  const runtimePrivilege = [runtimePrivilegeJob(config)];
  const workloads = [
    edgeDeployment(config),
    directorDeployment(config),
    gatewayDeployment(config),
  ];
  return {
    '00-prerequisites.json': list(prerequisites),
    '10-migration-job.json': list(migration),
    '15-runtime-privilege-job.json': list(runtimePrivilege),
    '20-workloads.json': list(workloads),
  };
}

export function validateRenderedResources(resources, config) {
  if (!Array.isArray(resources) || resources.length < 15) {
    throw new Error('Rendered target is incomplete.');
  }
  if (resources.some((resource) => resource.kind === 'Secret')) {
    throw new Error('Rendered target must not contain secret material.');
  }
  const unique = new Set();
  for (const resource of resources) {
    const identity = `${resource.apiVersion}/${resource.kind}/${resource.metadata?.namespace ?? ''}/${resource.metadata?.name}`;
    if (unique.has(identity)) throw new Error('Rendered target contains duplicate resources.');
    unique.add(identity);
  }
  const namespace = findResource(resources, 'Namespace', config.namespace);
  if (
    namespace.metadata.labels['pod-security.kubernetes.io/enforce'] !== 'restricted' ||
    namespace.metadata.labels['pod-security.kubernetes.io/enforce-version'] !== config.kubernetes_version
  ) {
    throw new Error('Namespace does not enforce the pinned restricted Pod Security profile.');
  }
  for (const component of componentNames) {
    const account = findResource(resources, 'ServiceAccount', `dirizhor-${component}`);
    if (account.automountServiceAccountToken !== false || account.spec !== undefined) {
      throw new Error('ServiceAccount token automount must be disabled at the API field.');
    }
  }
  const workloads = resources.filter((resource) => ['Deployment', 'Job'].includes(resource.kind));
  if (workloads.length !== 5) throw new Error('Rendered workload set is incomplete.');
  for (const workload of workloads) validateWorkload(workload, config);
  validatePersistentRuntimeDirectories(workloads);
  validateEdgeSecretProjection(workloads);
  const migration = workloads.find(
    (resource) =>
      resource.kind === 'Job' &&
      resource.metadata.labels['app.kubernetes.io/component'] === 'migration',
  );
  const migrationContainer = migration?.spec?.template?.spec?.containers?.[0];
  if (
    migrationContainer?.command?.join(' ') !== 'node dist/db-migrate-cli.js migrate' ||
    migrationContainer?.image !== config.images.director
  ) {
    throw new Error('Migration job does not use the compiled runtime migrator.');
  }
  const privilege = workloads.find(
    (resource) =>
      resource.kind === 'Job' &&
      resource.metadata.labels['app.kubernetes.io/component'] === 'runtime-privilege',
  );
  const privilegeContainer = privilege?.spec?.template?.spec?.containers?.[0];
  if (
    privilegeContainer?.command?.join(' ') !== 'node dist/postgres-runtime-privilege-cli.js' ||
    privilegeContainer?.image !== config.images.director
  ) {
    throw new Error('Runtime privilege job does not use the compiled read-only probe.');
  }
  const statefulPostgres = resources.some((resource) =>
    ['StatefulSet', 'Deployment'].includes(resource.kind) &&
    /postgres/i.test(resource.metadata?.name ?? ''),
  );
  if (statefulPostgres) throw new Error('Target renderer must not deploy an unmanaged PostgreSQL server.');
  const edge = findResource(resources, 'Service', 'dirizhor-edge');
  const expectedEdgeServiceType = config.public.exposure === 'internal' ? 'ClusterIP' : 'LoadBalancer';
  if (
    edge.spec.type !== expectedEdgeServiceType ||
    edge.spec.ports?.[0]?.port !== 443 ||
    edge.spec.ports?.[0]?.targetPort !== 'https'
  ) {
    throw new Error('Edge service exposure contract is invalid.');
  }
  if (
    config.public.exposure === 'internal' &&
    (edge.spec.externalTrafficPolicy !== undefined ||
      edge.spec.loadBalancerSourceRanges !== undefined ||
      edge.metadata.annotations !== undefined)
  ) {
    throw new Error('Internal edge service must not include load balancer configuration.');
  }
  for (const name of ['default-deny', 'allow-dns', 'edge', 'director', 'gateway', 'migration', 'runtime-privilege']) {
    findResource(resources, 'NetworkPolicy', `dirizhor-${name}`);
  }
  for (const [name, component, fqdns] of [
    ['director-oidc-fqdn-egress', 'director', config.networking.oidc_egress_fqdns],
    ['gateway-ai-fqdn-egress', 'gateway', config.networking.ai_provider_egress_fqdns],
  ]) {
    if (fqdns.length === 0) continue;
    const policy = findResource(resources, 'CiliumNetworkPolicy', `dirizhor-${name}`);
    if (
      JSON.stringify(policy.spec.endpointSelector?.matchLabels) !== JSON.stringify(selector(component)) ||
      JSON.stringify(policy.spec.egress?.[0]?.toFQDNs) !== JSON.stringify(fqdns.map((matchName) => ({ matchName }))) ||
      JSON.stringify(policy.spec.egress?.[0]?.toPorts) !== JSON.stringify([{
        ports: [{ port: '443', protocol: 'TCP' }],
      }])
    ) {
      throw new Error(`Cilium FQDN policy ${name} is invalid.`);
    }
  }
  return { status: 'ok', resource_count: resources.length };
}

function namespaceResource(config) {
  return {
    apiVersion: 'v1',
    kind: 'Namespace',
    metadata: {
      name: config.namespace,
      labels: {
        'app.kubernetes.io/part-of': 'dirizhor',
        'pod-security.kubernetes.io/enforce': 'restricted',
        'pod-security.kubernetes.io/enforce-version': config.kubernetes_version,
        'pod-security.kubernetes.io/audit': 'restricted',
        'pod-security.kubernetes.io/audit-version': config.kubernetes_version,
        'pod-security.kubernetes.io/warn': 'restricted',
        'pod-security.kubernetes.io/warn-version': config.kubernetes_version,
      },
    },
  };
}

function serviceAccount(namespace, component) {
  return {
    apiVersion: 'v1',
    kind: 'ServiceAccount',
    metadata: {
      name: `dirizhor-${component}`,
      namespace,
      labels: labels(component),
    },
    automountServiceAccountToken: false,
  };
}

function configMap(namespace, component, data) {
  return namespacedResource('v1', 'ConfigMap', namespace, `dirizhor-${component}-config`, undefined, labels(component), { data });
}

function persistentVolumeClaim(namespace, component, storage) {
  return namespacedResource('v1', 'PersistentVolumeClaim', namespace, `dirizhor-${component}-data`, {
    accessModes: ['ReadWriteOnce'],
    volumeMode: 'Filesystem',
    storageClassName: storage.storage_class_name,
    resources: { requests: { storage: storage.size } },
  }, labels(component));
}

function internalService(namespace, component, port) {
  return namespacedResource('v1', 'Service', namespace, `dirizhor-${component}`, {
    type: 'ClusterIP',
    selector: selector(component),
    ports: [{ name: 'https', protocol: 'TCP', port, targetPort: 'https' }],
  }, labels(component));
}

function edgeService(config) {
  const internal = config.public.exposure === 'internal';
  const spec = {
    type: internal ? 'ClusterIP' : 'LoadBalancer',
    selector: selector('edge'),
    ports: [{ name: 'https', protocol: 'TCP', port: 443, targetPort: 'https' }],
    ...(internal ? {} : {
      externalTrafficPolicy: 'Local',
      loadBalancerSourceRanges: config.public.load_balancer_source_ranges,
    }),
  };
  return namespacedResource(
    'v1',
    'Service',
    config.namespace,
    'dirizhor-edge',
    spec,
    labels('edge'),
    internal ? {} : { metadata: { annotations: config.public.load_balancer_annotations } },
  );
}

function edgeDisruptionBudget(namespace) {
  return namespacedResource('policy/v1', 'PodDisruptionBudget', namespace, 'dirizhor-edge', {
    minAvailable: 1,
    selector: { matchLabels: selector('edge') },
  }, labels('edge'));
}

function edgeDeployment(config) {
  const container = {
    name: 'edge',
    image: config.images.edge,
    imagePullPolicy: 'IfNotPresent',
    envFrom: [{ configMapRef: { name: 'dirizhor-edge-config' } }],
    ports: [{ name: 'https', containerPort: 8443, protocol: 'TCP' }],
    resources: config.resources.edge,
    securityContext: containerSecurityContext(),
    startupProbe: tcpProbe(30),
    livenessProbe: tcpProbe(3),
    readinessProbe: tcpProbe(3),
    volumeMounts: [
      { name: 'edge-secrets', mountPath: '/run/secrets', readOnly: true },
      { name: 'tmp', mountPath: '/tmp' },
      { name: 'nginx-cache', mountPath: '/var/cache/nginx' },
    ],
  };
  return deployment(config, 'edge', config.replicas.edge, container, [
    {
      name: 'edge-secrets',
      projected: {
        defaultMode: 0o440,
        sources: [
          { secret: { name: config.secrets.edge_tls, items: [
            { key: 'tls.crt', path: 'public-tls.crt' },
            { key: 'tls.key', path: 'public-tls.key' },
          ] } },
          { secret: { name: config.secrets.edge_director_ca, items: [
            { key: 'ca.crt', path: 'director-upstream-ca.crt' },
          ] } },
        ],
      },
    },
    { name: 'tmp', emptyDir: { medium: 'Memory', sizeLimit: '128Mi' } },
    { name: 'nginx-cache', emptyDir: { medium: 'Memory', sizeLimit: '64Mi' } },
  ], { type: 'RollingUpdate', rollingUpdate: { maxUnavailable: 0, maxSurge: 1 } });
}

function directorDeployment(config) {
  const container = {
    name: 'director',
    image: config.images.director,
    imagePullPolicy: 'IfNotPresent',
    envFrom: [{ configMapRef: { name: 'dirizhor-director-config' } }],
    env: [
      secretFileEnv('DATABASE_URL_FILE', '/run/secrets/director-runtime/database-url'),
      secretFileEnv('DIRECTOR_CAPABILITY_KEY_BASE64_FILE', '/run/secrets/director-runtime/capability-key-base64'),
      secretFileEnv('DIRECTOR_OIDC_CLIENT_SECRET_FILE', '/run/secrets/director-runtime/oidc-client-secret'),
      secretFileEnv('DIRECTOR_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64_FILE', '/run/secrets/workload-identity/signing-private-key-base64'),
      secretFileEnv('GATEWAY_WORKLOAD_VERIFY_KEYS_JSON_FILE', '/run/secrets/workload-identity/gateway-verification-keys-json'),
    ],
    ports: [{ name: 'https', containerPort: 8444, protocol: 'TCP' }],
    resources: config.resources.director,
    securityContext: containerSecurityContext(),
    startupProbe: httpsProbe('/health/live', 30),
    livenessProbe: httpsProbe('/health/live', 3),
    readinessProbe: httpsProbe('/health/ready', 3),
    volumeMounts: [
      { name: 'documents', mountPath: '/var/lib/dirizhor' },
      { name: 'director-runtime', mountPath: '/run/secrets/director-runtime', readOnly: true },
      { name: 'workload-identity', mountPath: '/run/secrets/workload-identity', readOnly: true },
      { name: 'director-tls', mountPath: '/run/secrets/director-tls', readOnly: true },
      { name: 'gateway-client-tls', mountPath: '/run/secrets/gateway-client-tls', readOnly: true },
      { name: 'postgres-ca', mountPath: '/run/secrets/postgres', readOnly: true },
    ],
  };
  return deployment(config, 'director', 1, container, [
    pvcVolume('documents', 'dirizhor-director-data'),
    secretVolume('director-runtime', config.secrets.director_runtime),
    secretVolume('workload-identity', config.secrets.director_workload_identity),
    secretVolume('director-tls', config.secrets.director_tls),
    secretVolume('gateway-client-tls', config.secrets.director_gateway_client_tls),
    secretVolume('postgres-ca', config.secrets.postgres_ca),
  ], { type: 'Recreate' });
}

function gatewayDeployment(config) {
  const gatewayDns = serviceNames(
    config.namespace,
    config.networking.cluster_domain,
  ).gateway;
  const container = {
    name: 'gateway',
    image: config.images.gateway,
    imagePullPolicy: 'IfNotPresent',
    envFrom: [{ configMapRef: { name: 'dirizhor-gateway-config' } }],
    env: [
      secretFileEnv('GATEWAY_SPOOL_KEY_BASE64_FILE', '/run/secrets/gateway-runtime/spool-key-base64'),
      secretFileEnv('OPENAI_API_KEY_FILE', '/run/secrets/gateway-runtime/openai-api-key'),
      ...(config.internal_provider === null ? [] : [
        secretFileEnv('INTERNAL_PROVIDER_TOKEN_FILE', '/run/secrets/gateway-runtime/internal-provider-token'),
      ]),
      secretFileEnv('GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64_FILE', '/run/secrets/workload-identity/signing-private-key-base64'),
      secretFileEnv('DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON_FILE', '/run/secrets/workload-identity/director-verification-keys-json'),
    ],
    ports: [{ name: 'https', containerPort: 8443, protocol: 'TCP' }],
    resources: config.resources.gateway,
    securityContext: containerSecurityContext(),
    startupProbe: gatewayExecProbe('/health/live', gatewayDns, 30),
    livenessProbe: gatewayExecProbe('/health/live', gatewayDns, 3),
    readinessProbe: gatewayExecProbe('/health/ready', gatewayDns, 3),
    volumeMounts: [
      { name: 'state', mountPath: '/var/lib/dirizhor' },
      { name: 'gateway-runtime', mountPath: '/run/secrets/gateway-runtime', readOnly: true },
      { name: 'workload-identity', mountPath: '/run/secrets/workload-identity', readOnly: true },
      { name: 'gateway-tls', mountPath: '/run/secrets/gateway-tls', readOnly: true },
      { name: 'director-client-tls', mountPath: '/run/secrets/director-client-tls', readOnly: true },
      { name: 'gateway-probe-tls', mountPath: '/run/secrets/gateway-probe-tls', readOnly: true },
      ...(config.internal_provider === null ? [] : [
        { name: 'internal-provider-tls', mountPath: '/run/secrets/internal-provider-tls', readOnly: true },
      ]),
    ],
  };
  return deployment(config, 'gateway', 1, container, [
    pvcVolume('state', 'dirizhor-gateway-data'),
    secretVolume('gateway-runtime', config.secrets.gateway_runtime),
    secretVolume('workload-identity', config.secrets.gateway_workload_identity),
    secretVolume('gateway-tls', config.secrets.gateway_tls),
    secretVolume('director-client-tls', config.secrets.gateway_director_client_tls),
    secretVolume('gateway-probe-tls', config.secrets.gateway_probe_client_tls),
    ...(config.internal_provider === null ? [] : [
      secretVolume('internal-provider-tls', config.secrets.gateway_internal_provider_tls),
    ]),
  ], { type: 'Recreate' });
}

function migrationJob(config) {
  const component = 'migration';
  const name = `dirizhor-migrate-${dnsSlug(config.deployment_id)}`.slice(0, 63).replace(/-$/, '');
  return namespacedResource('batch/v1', 'Job', config.namespace, name, {
    backoffLimit: 0,
    activeDeadlineSeconds: 900,
    template: {
      metadata: { labels: selector(component) },
      spec: {
        restartPolicy: 'Never',
        serviceAccountName: 'dirizhor-director',
        automountServiceAccountToken: false,
        enableServiceLinks: false,
        os: { name: 'linux' },
        securityContext: podSecurityContext(),
        imagePullSecrets: [{ name: config.secrets.image_pull }],
        containers: [{
          name: 'migration',
          image: config.images.director,
          imagePullPolicy: 'IfNotPresent',
          command: ['node', 'dist/db-migrate-cli.js', 'migrate'],
          env: [
            secretFileEnv('DIRECTOR_MIGRATION_DATABASE_URL_FILE', '/run/secrets/migration/database-url'),
            secretFileEnv('DIRECTOR_MIGRATION_DATABASE_CA_PATH', '/run/secrets/postgres/ca.crt'),
          ],
          resources: config.resources.migration,
          securityContext: containerSecurityContext(),
          volumeMounts: [
            { name: 'migration-database', mountPath: '/run/secrets/migration', readOnly: true },
            { name: 'postgres-ca', mountPath: '/run/secrets/postgres', readOnly: true },
          ],
        }],
        volumes: [
          secretVolume('migration-database', config.secrets.migration_database),
          secretVolume('postgres-ca', config.secrets.postgres_ca),
        ],
      },
    },
  }, labels(component), { metadata: { annotations: deploymentAnnotations(config, config.images.director) } });
}

function runtimePrivilegeJob(config) {
  const component = 'runtime-privilege';
  const name = `dirizhor-runtime-privilege-${dnsSlug(config.deployment_id)}`
    .slice(0, 63)
    .replace(/-$/, '');
  return namespacedResource('batch/v1', 'Job', config.namespace, name, {
    backoffLimit: 0,
    activeDeadlineSeconds: 300,
    template: {
      metadata: { labels: selector(component) },
      spec: {
        restartPolicy: 'Never',
        serviceAccountName: 'dirizhor-director',
        automountServiceAccountToken: false,
        enableServiceLinks: false,
        os: { name: 'linux' },
        securityContext: podSecurityContext(),
        imagePullSecrets: [{ name: config.secrets.image_pull }],
        containers: [{
          name: 'runtime-privilege',
          image: config.images.director,
          imagePullPolicy: 'IfNotPresent',
          command: ['node', 'dist/postgres-runtime-privilege-cli.js'],
          env: [
            secretFileEnv('DATABASE_URL_FILE', '/run/secrets/director-runtime/database-url'),
            secretFileEnv('DIRECTOR_DATABASE_CA_PATH', '/run/secrets/postgres/ca.crt'),
            {
              name: 'DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_DATABASE',
              value: config.postgresql.database_name,
            },
            {
              name: 'DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_ROLE',
              value: config.postgresql.runtime_role,
            },
          ],
          resources: config.resources.migration,
          securityContext: containerSecurityContext(),
          volumeMounts: [
            { name: 'director-runtime', mountPath: '/run/secrets/director-runtime', readOnly: true },
            { name: 'postgres-ca', mountPath: '/run/secrets/postgres', readOnly: true },
          ],
        }],
        volumes: [
          secretVolume('director-runtime', config.secrets.director_database),
          secretVolume('postgres-ca', config.secrets.postgres_ca),
        ],
      },
    },
  }, labels(component), {
    metadata: { annotations: deploymentAnnotations(config, config.images.director) },
  });
}

function deployment(config, component, replicas, container, volumes, strategy) {
  return namespacedResource('apps/v1', 'Deployment', config.namespace, `dirizhor-${component}`, {
    replicas,
    revisionHistoryLimit: 3,
    progressDeadlineSeconds: 600,
    strategy,
    selector: { matchLabels: selector(component) },
    template: {
      metadata: {
        labels: selector(component),
        annotations: { 'dirizhor.io/deployment-id': config.deployment_id },
      },
      spec: {
        serviceAccountName: `dirizhor-${component}`,
        automountServiceAccountToken: false,
        enableServiceLinks: false,
        os: { name: 'linux' },
        terminationGracePeriodSeconds: component === 'edge' ? 30 : 45,
        securityContext: podSecurityContext(),
        imagePullSecrets: [{ name: config.secrets.image_pull }],
        containers: [container],
        volumes,
        ...(component === 'edge' ? { topologySpreadConstraints: [{
          maxSkew: 1,
          topologyKey: 'kubernetes.io/hostname',
          whenUnsatisfiable: 'ScheduleAnyway',
          labelSelector: { matchLabels: selector('edge') },
        }] } : {}),
      },
    },
  }, labels(component), { metadata: { annotations: deploymentAnnotations(config, container.image) } });
}

function networkPolicies(config) {
  const namespace = config.namespace;
  const portPeer = (cidr, port) => ({
    to: [{ ipBlock: { cidr } }],
    ports: [{ protocol: 'TCP', port }],
  });
  return [
    networkPolicy(namespace, 'default-deny', {}, { policyTypes: ['Ingress', 'Egress'] }),
    networkPolicy(namespace, 'allow-dns', {}, {
      policyTypes: ['Egress'],
      egress: [{
        to: [{
          namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': config.networking.dns_namespace } },
          podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } },
        }],
        ports: [
          { protocol: 'UDP', port: 53 },
          { protocol: 'TCP', port: 53 },
        ],
      }],
    }),
    networkPolicy(namespace, 'edge', selector('edge'), {
      policyTypes: ['Ingress', 'Egress'],
      ingress: config.public.load_balancer_source_ranges.map((cidr) => ({
        from: [{ ipBlock: { cidr } }],
        ports: [{ protocol: 'TCP', port: 8443 }],
      })),
      egress: [podEgress('director', 8444)],
    }),
    networkPolicy(namespace, 'director', selector('director'), {
      policyTypes: ['Ingress', 'Egress'],
      ingress: [podIngress('edge', 8444), podIngress('gateway', 8444)],
      egress: [
        podEgress('gateway', 8443),
        ...config.networking.postgresql_cidrs.map((cidr) => portPeer(cidr, config.networking.postgresql_port)),
        ...config.networking.oidc_egress_cidrs.map((cidr) => portPeer(cidr, 443)),
      ],
    }),
    networkPolicy(namespace, 'gateway', selector('gateway'), {
      policyTypes: ['Ingress', 'Egress'],
      ingress: [podIngress('director', 8443)],
      egress: [
        podEgress('director', 8444),
        ...(config.internal_provider === null ? [] : [{
          to: [{ podSelector: { matchLabels: { 'app.kubernetes.io/name': 'dirizhor-inference' } } }],
          ports: [{ protocol: 'TCP', port: 8443 }],
        }]),
        ...config.networking.internal_provider_egress_cidrs.map((cidr) => portPeer(cidr, 443)),
        ...config.networking.ai_provider_egress_cidrs.map((cidr) => portPeer(cidr, 443)),
      ],
    }),
    networkPolicy(namespace, 'migration', selector('migration'), {
      policyTypes: ['Ingress', 'Egress'],
      egress: config.networking.postgresql_cidrs.map((cidr) => portPeer(cidr, config.networking.postgresql_port)),
    }),
    networkPolicy(namespace, 'runtime-privilege', selector('runtime-privilege'), {
      policyTypes: ['Ingress', 'Egress'],
      egress: config.networking.postgresql_cidrs.map((cidr) => portPeer(cidr, config.networking.postgresql_port)),
    }),
  ];
}

function ciliumFqdnPolicies(config) {
  const namespace = config.namespace;
  return [
    ['director-oidc-fqdn-egress', 'director', config.networking.oidc_egress_fqdns],
    ['gateway-ai-fqdn-egress', 'gateway', config.networking.ai_provider_egress_fqdns],
  ].flatMap(([name, component, fqdns]) => fqdns.length === 0 ? [] : [
    namespacedResource('cilium.io/v2', 'CiliumNetworkPolicy', namespace, `dirizhor-${name}`, {
      endpointSelector: { matchLabels: selector(component) },
      egress: [{
        toFQDNs: fqdns.map((matchName) => ({ matchName })),
        toPorts: [{ ports: [{ port: '443', protocol: 'TCP' }] }],
      }],
    }, labels('network')),
  ]);
}

function edgeEnvironment(config, names) {
  return {
    DIRECTOR_PUBLIC_HOST: config.public.host,
    PUBLIC_LISTEN_PORT: '8443',
    DIRECTOR_PUBLIC_PORT: '443',
    DIRECTOR_UPSTREAM_HOST: names.director,
    DIRECTOR_UPSTREAM_PORT: '8444',
    DIRECTOR_UPSTREAM_TLS_NAME: names.director,
    DIRECTOR_MAX_BODY_SIZE: config.public.max_body_size,
  };
}

function directorEnvironment(config, names) {
  return {
    NODE_ENV: 'production',
    DIRECTOR_HOST: '0.0.0.0',
    DIRECTOR_PORT: '8444',
    DOCUMENT_STORE_ROOT: '/var/lib/dirizhor/documents',
    GATEWAY_BASE_URL: `https://${names.gateway}:8443`,
    DIRECTOR_PUBLIC_AUTH_MODE: 'session',
    DIRECTOR_TLS_CERT_PATH: '/run/secrets/director-tls/tls.crt',
    DIRECTOR_TLS_KEY_PATH: '/run/secrets/director-tls/tls.key',
    DIRECTOR_TLS_CA_PATH: '/run/secrets/director-tls/ca.crt',
    DIRECTOR_ALLOWED_PEER_CNS: 'agent-gateway',
    DIRECTOR_WORKLOAD_SIGNING_KEY_ID: config.workload_identity.director_signing_key_id,
    DIRECTOR_WORKLOAD_TOKEN_TTL_SECONDS: String(config.workload_identity.token_ttl_seconds),
    DIRECTOR_GATEWAY_CLIENT_CERT_PATH: '/run/secrets/gateway-client-tls/tls.crt',
    DIRECTOR_GATEWAY_CLIENT_KEY_PATH: '/run/secrets/gateway-client-tls/tls.key',
    DIRECTOR_GATEWAY_CA_PATH: '/run/secrets/gateway-client-tls/ca.crt',
    DIRECTOR_DATABASE_CA_PATH: '/run/secrets/postgres/ca.crt',
    DIRECTOR_TRUSTED_PROXY_CIDRS: config.networking.trusted_proxy_cidrs.join(','),
    DIRECTOR_AGENT_ROUTES_JSON: JSON.stringify(config.agent_routes),
    DIRECTOR_OIDC_ISSUER_URL: config.oidc.issuer_url,
    DIRECTOR_OIDC_CLIENT_ID: config.oidc.client_id,
    DIRECTOR_OIDC_REDIRECT_URI: `https://${config.public.host}/api/v1/auth/oidc/callback`,
    DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI: `https://${config.public.host}/`,
    DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI: `https://${config.public.host}/signed-out`,
    DIRECTOR_OIDC_SCOPES: config.oidc.scopes.join(' '),
    DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG: config.oidc.id_token_signing_algorithm,
    DIRECTOR_LOCAL_PASSWORD_LOGIN_ENABLED: 'false',
  };
}

function gatewayEnvironment(config, names) {
  return {
    NODE_ENV: 'production',
    GATEWAY_HOST: '0.0.0.0',
    GATEWAY_PORT: '8443',
    GATEWAY_STATE_DIR: '/var/lib/dirizhor/gateway',
    DIRECTOR_BASE_URL: `https://${names.director}:8444`,
    GATEWAY_ENABLE_FIXTURE_PROVIDER: 'false',
    GATEWAY_TLS_CERT_PATH: '/run/secrets/gateway-tls/tls.crt',
    GATEWAY_TLS_KEY_PATH: '/run/secrets/gateway-tls/tls.key',
    GATEWAY_TLS_CA_PATH: '/run/secrets/gateway-tls/ca.crt',
    GATEWAY_ALLOWED_PEER_CNS: 'director-api,gateway-probe',
    GATEWAY_WORKLOAD_SIGNING_KEY_ID: config.workload_identity.gateway_signing_key_id,
    GATEWAY_WORKLOAD_TOKEN_TTL_SECONDS: String(config.workload_identity.token_ttl_seconds),
    GATEWAY_DIRECTOR_CLIENT_CERT_PATH: '/run/secrets/director-client-tls/tls.crt',
    GATEWAY_DIRECTOR_CLIENT_KEY_PATH: '/run/secrets/director-client-tls/tls.key',
    GATEWAY_DIRECTOR_CA_PATH: '/run/secrets/director-client-tls/ca.crt',
    ...(config.internal_provider === null ? {} : {
      INTERNAL_PROVIDER_ORIGIN: config.internal_provider.origin,
      INTERNAL_PROVIDER_MODELS: config.internal_provider.models.join(','),
      INTERNAL_PROVIDER_CLIENT_CERT_PATH: '/run/secrets/internal-provider-tls/tls.crt',
      INTERNAL_PROVIDER_CLIENT_KEY_PATH: '/run/secrets/internal-provider-tls/tls.key',
      INTERNAL_PROVIDER_CA_PATH: '/run/secrets/internal-provider-tls/ca.crt',
      INTERNAL_PROVIDER_ALLOWED_CLIENT_CNS: 'agent-gateway-internal-provider',
    }),
  };
}

function validateWorkload(workload, config) {
  const pod = workload.spec?.template?.spec;
  if (
    pod?.automountServiceAccountToken !== false ||
    pod?.enableServiceLinks !== false ||
    pod?.os?.name !== 'linux' ||
    pod?.securityContext?.runAsNonRoot !== true ||
    pod?.securityContext?.runAsUser !== 10_001 ||
    pod?.securityContext?.seccompProfile?.type !== 'RuntimeDefault'
  ) {
    throw new Error('Workload pod security context is incomplete.');
  }
  for (const container of pod.containers ?? []) {
    if (
      !digestReferencePattern.test(container.image) ||
      container.securityContext?.allowPrivilegeEscalation !== false ||
      container.securityContext?.readOnlyRootFilesystem !== true ||
      container.securityContext?.capabilities?.drop?.[0] !== 'ALL' ||
      container.resources?.requests === undefined ||
      container.resources?.limits === undefined ||
      pod.imagePullSecrets?.length !== 1 ||
      pod.volumes?.some((volume) => volume.hostPath !== undefined)
    ) {
      throw new Error('Workload container violates the restricted runtime contract.');
    }
  }
  if (workload.kind === 'Deployment') {
    const component = workload.metadata.labels['app.kubernetes.io/component'];
    if (workload.spec.replicas !== config.replicas[component]) {
      throw new Error('Rendered deployment replica count differs from target config.');
    }
    const container = pod.containers[0];
    if (container.startupProbe === undefined || container.livenessProbe === undefined || container.readinessProbe === undefined) {
      throw new Error('Application deployment lacks required probes.');
    }
  }
}

function validateImages(images) {
  assertObject(images, 'images');
  assertExactKeys(images, componentNames, 'images');
  if (new Set(Object.values(images)).size !== 3 || Object.values(images).some((image) => !digestReferencePattern.test(image))) {
    throw new Error('Every workload requires a unique digest-only image reference.');
  }
}

function validateReplicas(replicas) {
  assertObject(replicas, 'replicas');
  assertExactKeys(replicas, componentNames, 'replicas');
  if (replicas.director !== 1 || replicas.gateway !== 1 || !Number.isSafeInteger(replicas.edge) || replicas.edge < 2 || replicas.edge > 20) {
    throw new Error('Pilot requires one stateful Director/Gateway and 2-20 Edge replicas.');
  }
}

function validatePublic(publicConfig, schemaVersion) {
  assertObject(publicConfig, 'public');
  const legacyKeys = ['host', 'max_body_size', 'load_balancer_source_ranges', 'load_balancer_annotations'];
  if (schemaVersion === 1) {
    assertExactKeys(publicConfig, legacyKeys, 'public');
    publicConfig.exposure = 'load-balancer';
  } else {
    assertExactKeys(publicConfig, ['exposure', ...legacyKeys], 'public');
  }
  if (!hostname(publicConfig.host) || !/^[1-9][0-9]*(?:k|m|g)$/i.test(publicConfig.max_body_size)) {
    throw new Error('Public host or body size is invalid.');
  }
  if (!['internal', 'load-balancer'].includes(publicConfig.exposure)) {
    throw new Error('Edge exposure must be internal or load-balancer.');
  }
  validateCidrs(publicConfig.load_balancer_source_ranges, 'load_balancer_source_ranges');
  if (publicConfig.load_balancer_source_ranges.includes('0.0.0.0/0')) {
    throw new Error('Public load balancer source ranges must be explicit.');
  }
  assertStringMap(publicConfig.load_balancer_annotations, 'load_balancer_annotations');
  if (
    publicConfig.exposure === 'internal' &&
    Object.keys(publicConfig.load_balancer_annotations).length > 0
  ) {
    throw new Error('Internal edge exposure must not include load balancer annotations.');
  }
}

function validateNetworking(networking, schemaVersion, internalProviderEnabled) {
  assertObject(networking, 'networking');
  const cidrKeys = [
    'cluster_domain', 'dns_namespace', 'trusted_proxy_cidrs', 'postgresql_cidrs',
    'postgresql_port', 'oidc_egress_cidrs', 'internal_provider_egress_cidrs',
    'ai_provider_egress_cidrs',
  ];
  if (schemaVersion < 3) {
    assertExactKeys(networking, cidrKeys, 'networking');
    networking.oidc_egress_fqdns = [];
    networking.ai_provider_egress_fqdns = [];
  } else {
    assertExactKeys(networking, [
      ...cidrKeys,
      'oidc_egress_fqdns',
      'ai_provider_egress_fqdns',
    ], 'networking');
  }
  if (!hostname(networking.cluster_domain) || !dnsLabelPattern.test(networking.dns_namespace)) {
    throw new Error('Cluster DNS configuration is invalid.');
  }
  for (const key of ['trusted_proxy_cidrs', 'postgresql_cidrs', 'internal_provider_egress_cidrs']) {
    validateCidrs(networking[key], key, {
      allowEmpty: key === 'internal_provider_egress_cidrs' && schemaVersion >= 4,
    });
  }
  if (!internalProviderEnabled && networking.internal_provider_egress_cidrs.length !== 0) {
    throw new Error('External-only target must not allow internal provider egress.');
  }
  validateFqdns(networking.oidc_egress_fqdns, 'oidc_egress_fqdns');
  validateFqdns(networking.ai_provider_egress_fqdns, 'ai_provider_egress_fqdns');
  for (const [cidrKey, fqdnKey] of [
    ['oidc_egress_cidrs', 'oidc_egress_fqdns'],
    ['ai_provider_egress_cidrs', 'ai_provider_egress_fqdns'],
  ]) {
    validateCidrs(networking[cidrKey], cidrKey, { allowEmpty: schemaVersion >= 3 });
    if (networking[cidrKey].length === 0 && networking[fqdnKey].length === 0) {
      throw new Error(`${cidrKey} or ${fqdnKey} must allow the provider endpoint.`);
    }
  }
  if (!Number.isSafeInteger(networking.postgresql_port) || networking.postgresql_port < 1 || networking.postgresql_port > 65_535) {
    throw new Error('PostgreSQL port is invalid.');
  }
}

function validatePostgresql(postgresql) {
  assertObject(postgresql, 'postgresql');
  assertExactKeys(postgresql, ['database_name', 'runtime_role'], 'postgresql');
  const identifierPattern = /^[A-Za-z_][A-Za-z0-9_-]{0,62}$/;
  if (
    !identifierPattern.test(postgresql.database_name) ||
    !identifierPattern.test(postgresql.runtime_role)
  ) {
    throw new Error('PostgreSQL database name or runtime role is invalid.');
  }
}

function validateInternalProvider(provider, schemaVersion) {
  if (provider === null) {
    if (schemaVersion < 4) throw new Error('Internal provider is required before schema v4.');
    return;
  }
  assertObject(provider, 'internal_provider');
  assertExactKeys(provider, ['origin', 'models'], 'internal_provider');
  let origin;
  try {
    origin = new URL(provider.origin);
  } catch {
    throw new Error('Internal provider origin is invalid.');
  }
  if (
    origin.protocol !== 'https:' ||
    origin.username.length > 0 ||
    origin.password.length > 0 ||
    origin.pathname !== '/' ||
    origin.search.length > 0 ||
    origin.hash.length > 0 ||
    !hostname(origin.hostname) ||
    isIP(origin.hostname) !== 0
  ) {
    throw new Error('Internal provider must use an exact HTTPS DNS origin.');
  }
  if (
    !Array.isArray(provider.models) ||
    provider.models.length === 0 ||
    provider.models.length > 100 ||
    new Set(provider.models).size !== provider.models.length ||
    provider.models.some((model) => typeof model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(model))
  ) {
    throw new Error('Internal provider models must be a unique non-empty allowlist.');
  }
}

function validateOidc(oidc, publicHost) {
  assertObject(oidc, 'oidc');
  assertExactKeys(oidc, ['issuer_url', 'client_id', 'scopes', 'id_token_signing_algorithm'], 'oidc');
  if (!isHttpsUrl(oidc.issuer_url) || typeof oidc.client_id !== 'string' || oidc.client_id.length < 2) {
    throw new Error('OIDC target configuration is invalid.');
  }
  if (!Array.isArray(oidc.scopes) || !oidc.scopes.includes('openid') || oidc.scopes.some((scope) => !/^[A-Za-z0-9._:-]+$/.test(scope))) {
    throw new Error('OIDC scopes are invalid.');
  }
  if (!['RS256', 'PS256', 'ES256', 'EdDSA'].includes(oidc.id_token_signing_algorithm) || !hostname(publicHost)) {
    throw new Error('OIDC signing algorithm is invalid.');
  }
}

function validateAgentRoutes(routes, internalModels, internalProviderEnabled) {
  if (!Array.isArray(routes) || routes.length === 0) throw new Error('At least one agent route is required.');
  const agentTypes = new Set();
  for (const route of routes) {
    assertObject(route, 'agent route');
    assertExactKeys(route, ['agent_type', 'provider', 'model', 'deployment_class', 'provider_data_profile_version'], 'agent route');
    if (
      !/^[a-z][a-z0-9_-]{1,63}$/.test(route.agent_type) ||
      agentTypes.has(route.agent_type) ||
      !['internal', 'openai'].includes(route.provider) ||
      typeof route.model !== 'string' ||
      route.model.length < 2 ||
      !['internal', 'external'].includes(route.deployment_class) ||
      (route.provider_data_profile_version !== null && typeof route.provider_data_profile_version !== 'string')
    ) {
      throw new Error('Agent route is invalid or duplicated.');
    }
    if (!internalProviderEnabled && route.provider === 'internal') {
      throw new Error('External-only target must not contain internal agent routes.');
    }
    if (
      (route.provider === 'internal' &&
        (route.deployment_class !== 'internal' ||
          route.provider_data_profile_version !== null ||
          !internalModels.includes(route.model))) ||
      (route.provider === 'openai' &&
        (route.deployment_class !== 'external' ||
          typeof route.provider_data_profile_version !== 'string' ||
          route.provider_data_profile_version.length === 0))
    ) {
      throw new Error('Agent route violates provider deployment-class policy.');
    }
    agentTypes.add(route.agent_type);
  }
  if (!routes.some((route) => route.provider === 'openai')) {
    throw new Error('Pilot target requires at least one external agent route.');
  }
  if (internalProviderEnabled && !routes.some((route) => route.provider === 'internal')) {
    throw new Error('Configured internal provider requires an internal agent route.');
  }
}

function validateSecrets(secrets, internalProviderEnabled) {
  assertObject(secrets, 'secrets');
  const keys = [
    'image_pull', 'director_workload_identity', 'gateway_workload_identity', 'director_runtime', 'director_database', 'director_tls',
    'director_gateway_client_tls', 'gateway_runtime', 'gateway_tls',
    'gateway_director_client_tls', 'gateway_probe_client_tls', 'edge_tls',
    'gateway_internal_provider_tls', 'edge_director_ca', 'postgres_ca', 'migration_database',
  ];
  assertExactKeys(secrets, keys, 'secrets');
  if (internalProviderEnabled && !dnsLabelPattern.test(secrets.gateway_internal_provider_tls)) {
    throw new Error('Configured internal provider requires its TLS Secret.');
  }
  if (!internalProviderEnabled && secrets.gateway_internal_provider_tls !== null) {
    throw new Error('External-only target must not reference an internal provider TLS Secret.');
  }
  const names = Object.values(secrets).filter((name) => name !== null);
  if (new Set(names).size !== names.length || names.some((name) => !dnsLabelPattern.test(name))) {
    throw new Error('Secret object names must be unique DNS labels.');
  }
}

function validateWorkloadIdentity(workloadIdentity) {
  assertObject(workloadIdentity, 'workload_identity');
  assertExactKeys(
    workloadIdentity,
    ['director_signing_key_id', 'gateway_signing_key_id', 'token_ttl_seconds'],
    'workload_identity',
  );
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(workloadIdentity.director_signing_key_id) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(workloadIdentity.gateway_signing_key_id) ||
    workloadIdentity.director_signing_key_id === workloadIdentity.gateway_signing_key_id ||
    !Number.isSafeInteger(workloadIdentity.token_ttl_seconds) ||
    workloadIdentity.token_ttl_seconds < 10 ||
    workloadIdentity.token_ttl_seconds > 300
  ) {
    throw new Error('Workload identity key IDs or token TTL are invalid.');
  }
}

function validateStorage(storage) {
  assertObject(storage, 'storage');
  assertExactKeys(storage, ['director', 'gateway'], 'storage');
  for (const component of ['director', 'gateway']) {
    const value = storage[component];
    assertObject(value, `${component} storage`);
    assertExactKeys(value, ['storage_class_name', 'size'], `${component} storage`);
    if (!dnsLabelPattern.test(value.storage_class_name) || !/^[1-9][0-9]*Gi$/.test(value.size)) {
      throw new Error('Persistent storage configuration is invalid.');
    }
  }
}

function validateResources(resources) {
  assertObject(resources, 'resources');
  assertExactKeys(resources, resourceNames, 'resources');
  for (const name of resourceNames) {
    const value = resources[name];
    assertObject(value, `${name} resources`);
    assertExactKeys(value, ['requests', 'limits'], `${name} resources`);
    for (const type of ['requests', 'limits']) {
      assertObject(value[type], `${name} ${type}`);
      assertExactKeys(value[type], ['cpu', 'memory', 'ephemeral-storage'], `${name} ${type}`);
      if (Object.values(value[type]).some((quantity) => typeof quantity !== 'string' || !quantityPattern.test(quantity))) {
        throw new Error('Resource quantities must be explicit CPU/memory values.');
      }
    }
  }
}

function namespacedResource(apiVersion, kind, namespace, name, spec, resourceLabels, extras = {}) {
  return {
    apiVersion,
    kind,
    metadata: {
      name,
      namespace,
      labels: resourceLabels,
      ...(extras.metadata ?? {}),
    },
    ...(extras.data === undefined ? {} : { data: extras.data }),
    ...(spec === undefined ? {} : { spec }),
  };
}

function list(items) {
  return { apiVersion: 'v1', kind: 'List', items };
}

function labels(component) {
  return {
    'app.kubernetes.io/name': 'dirizhor',
    'app.kubernetes.io/component': component,
    'app.kubernetes.io/part-of': 'dirizhor',
    'app.kubernetes.io/managed-by': 'dirizhor-target-renderer',
  };
}

function selector(component) {
  return {
    'app.kubernetes.io/name': 'dirizhor',
    'app.kubernetes.io/component': component,
  };
}

function deploymentAnnotations(config, image) {
  return {
    'dirizhor.io/deployment-id': config.deployment_id,
    'dirizhor.io/image-digest': image.slice(image.indexOf('@') + 1),
  };
}

function podSecurityContext() {
  return {
    runAsNonRoot: true,
    runAsUser: 10_001,
    runAsGroup: 10_001,
    fsGroup: 10_001,
    fsGroupChangePolicy: 'OnRootMismatch',
    seccompProfile: { type: 'RuntimeDefault' },
  };
}

function containerSecurityContext() {
  return {
    allowPrivilegeEscalation: false,
    capabilities: { drop: ['ALL'] },
    privileged: false,
    readOnlyRootFilesystem: true,
    runAsNonRoot: true,
    runAsUser: 10_001,
    runAsGroup: 10_001,
  };
}

function secretVolume(name, secretName) {
  return { name, secret: { secretName, defaultMode: 0o440 } };
}

function pvcVolume(name, claimName) {
  return { name, persistentVolumeClaim: { claimName, readOnly: false } };
}

function validatePersistentRuntimeDirectories(workloads) {
  for (const [component, volumeName] of [['director', 'documents'], ['gateway', 'state']]) {
    const workload = workloads.find((resource) =>
      resource.kind === 'Deployment' &&
      resource.metadata.labels['app.kubernetes.io/component'] === component
    );
    const mount = workload?.spec?.template?.spec?.containers?.[0]?.volumeMounts
      ?.find((candidate) => candidate.name === volumeName);
    if (mount?.mountPath !== '/var/lib/dirizhor' || mount.subPath !== undefined) {
      throw new Error(`${component} persistent volume must contain, not replace, its runtime directory.`);
    }
  }
}

function validateEdgeSecretProjection(workloads) {
  const edge = workloads.find((resource) =>
    resource.kind === 'Deployment' &&
    resource.metadata.labels['app.kubernetes.io/component'] === 'edge'
  );
  const secrets = edge?.spec?.template?.spec?.volumes
    ?.find((candidate) => candidate.name === 'edge-secrets');
  if (secrets?.projected?.defaultMode !== 0o440) {
    throw new Error('Edge projected TLS material must use mode 0440.');
  }
}

function secretFileEnv(name, value) {
  return { name, value };
}

function httpsProbe(pathValue, failureThreshold) {
  return {
    httpGet: { path: pathValue, port: 'https', scheme: 'HTTPS' },
    periodSeconds: 10,
    timeoutSeconds: 3,
    failureThreshold,
  };
}

function tcpProbe(failureThreshold) {
  return {
    tcpSocket: { port: 'https' },
    periodSeconds: 10,
    timeoutSeconds: 3,
    failureThreshold,
  };
}

function gatewayExecProbe(pathValue, serverName, failureThreshold) {
  const code = [
    "const fs=require('fs'),https=require('https')",
    `const r=https.get({host:'127.0.0.1',port:8443,path:'${pathValue}',servername:'${serverName}',timeout:2500,ca:fs.readFileSync('/run/secrets/gateway-probe-tls/ca.crt'),cert:fs.readFileSync('/run/secrets/gateway-probe-tls/tls.crt'),key:fs.readFileSync('/run/secrets/gateway-probe-tls/tls.key')},s=>{s.resume();s.on('end',()=>process.exit(s.statusCode===200?0:1))})`,
    "r.on('timeout',()=>r.destroy());r.on('error',()=>process.exit(1))",
  ].join(';');
  return {
    exec: { command: ['node', '-e', code] },
    periodSeconds: 10,
    timeoutSeconds: 4,
    failureThreshold,
  };
}

function networkPolicy(namespace, name, podSelector, spec) {
  return namespacedResource('networking.k8s.io/v1', 'NetworkPolicy', namespace, `dirizhor-${name}`, {
    podSelector: { matchLabels: podSelector },
    ...spec,
  }, labels('network'));
}

function podIngress(component, port) {
  return {
    from: [{ podSelector: { matchLabels: selector(component) } }],
    ports: [{ protocol: 'TCP', port }],
  };
}

function podEgress(component, port) {
  return {
    to: [{ podSelector: { matchLabels: selector(component) } }],
    ports: [{ protocol: 'TCP', port }],
  };
}

function serviceNames(namespace, clusterDomain) {
  const suffix = `${namespace}.svc.${clusterDomain}`;
  return {
    director: `dirizhor-director.${suffix}`,
    gateway: `dirizhor-gateway.${suffix}`,
  };
}

function findResource(resources, kind, name) {
  const resource = resources.find((candidate) => candidate.kind === kind && candidate.metadata?.name === name);
  if (resource === undefined) throw new Error(`Rendered target lacks ${kind}/${name}.`);
  return resource;
}

function validateCidrs(values, label, { allowEmpty = false } = {}) {
  if (!Array.isArray(values) || (!allowEmpty && values.length === 0) || new Set(values).size !== values.length || values.some((cidr) => !validCidr(cidr))) {
    throw new Error(`${label} must contain unique IPv4 CIDRs.`);
  }
}

function validateFqdns(values, label) {
  if (
    !Array.isArray(values) ||
    values.length > 50 ||
    new Set(values).size !== values.length ||
    values.some((value) => !hostname(value) || !value.includes('.') || isIP(value) !== 0)
  ) {
    throw new Error(`${label} must contain unique exact DNS names without wildcards.`);
  }
}

function validCidr(value) {
  if (typeof value !== 'string' || !cidrPattern.test(value)) return false;
  return value.split('/')[0].split('.').every((octet) => Number(octet) <= 255);
}

function hostname(value) {
  return typeof value === 'string' && value.length <= 253 && value.split('.').every((label) => dnsLabelPattern.test(label));
}

function isHttpsUrl(value) {
  try { return new URL(value).protocol === 'https:'; } catch { return false; }
}

function dnsSlug(value) {
  return value.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
}

function assertObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new Error(`${label} contains missing or unsupported fields.`);
  }
}

function assertStringMap(value, label) {
  assertObject(value, label);
  if (Object.entries(value).some(([key, item]) => !/^[a-z0-9][a-z0-9./_-]+$/.test(key) || typeof item !== 'string' || item.length === 0)) {
    throw new Error(`${label} must contain safe string annotations.`);
  }
}

async function writePrivateJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  await chmod(filePath, 0o600);
}

async function fileHash(filePath) {
  const metadata = await lstat(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error('Rendered output is not a regular file.');
  return `sha256:${createHash('sha256').update(await readFile(filePath)).digest('hex')}`;
}

function canonicalHash(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

function insidePath(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function main() {
  const [outputDirectory, configPath] = process.argv.slice(2);
  if (outputDirectory === undefined || configPath === undefined || process.argv.length !== 4) {
    process.stderr.write('Usage: node scripts/kubernetes-render.mjs <new-output-directory> <config.json>\n');
    process.exitCode = 2;
    return;
  }
  try {
    const config = JSON.parse(await readFile(path.resolve(configPath), 'utf8'));
    const evidence = await renderKubernetesTarget({ config, outputDirectory });
    process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown Kubernetes render error.';
    process.stderr.write(`Kubernetes render failed: ${message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
