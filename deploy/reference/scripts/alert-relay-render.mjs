import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const digestImage = /^[a-z0-9][a-z0-9.:-]*(?:\/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$/;
const dnsLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const zeroDigest = `sha256:${'0'.repeat(64)}`;

export function validateAlertRelayConfig(config) {
  exactObject(config, ['schema_version', 'namespace', 'image', 'sender', 'recipient', 'secrets']);
  if (config.schema_version !== 1) throw new Error('Unsupported alert relay schema.');
  label(config.namespace, 'namespace');
  if (
    typeof config.image !== 'string' ||
    !digestImage.test(config.image) ||
    config.image.endsWith(zeroDigest)
  ) {
    throw new Error('Relay image must be digest-pinned.');
  }
  email(config.sender, 'sender');
  email(config.recipient, 'recipient');
  exactObject(config.secrets, ['runtime'], 'secrets');
  label(config.secrets.runtime, 'runtime secret');
  return structuredClone(config);
}

export function renderAlertRelay(config) {
  const value = validateAlertRelayConfig(config);
  const labels = {
    'app.kubernetes.io/name': 'dirizhor-alert-relay',
    'app.kubernetes.io/component': 'alert-relay',
    'app.kubernetes.io/managed-by': 'dirizhor-render',
  };
  const podSecurityContext = {
    runAsNonRoot: true,
    runAsUser: 10_001,
    runAsGroup: 10_001,
    fsGroup: 10_001,
    seccompProfile: { type: 'RuntimeDefault' },
  };
  const containerSecurityContext = {
    allowPrivilegeEscalation: false,
    capabilities: { drop: ['ALL'] },
    privileged: false,
    readOnlyRootFilesystem: true,
    runAsNonRoot: true,
    runAsUser: 10_001,
    runAsGroup: 10_001,
  };
  const receiver = `${labels['app.kubernetes.io/name']}.${value.namespace}.svc.cluster.local`;
  return [
    resource('v1', 'ConfigMap', value.namespace, 'dirizhor-alert-relay-config', {
      'RESEND_API_URL': 'https://api.resend.com/emails',
      'RESEND_FROM': value.sender,
      'RESEND_TO': value.recipient,
      'REQUEST_TIMEOUT_MS': '8000',
      'RETRY_DELAYS_MS': '300,1200',
    }, labels),
    resource('v1', 'Service', value.namespace, 'dirizhor-alert-relay', {
      type: 'ClusterIP',
      selector: labels,
      ports: [{ name: 'http', port: 8080, targetPort: 'http', protocol: 'TCP' }],
    }, labels),
    resource('apps/v1', 'Deployment', value.namespace, 'dirizhor-alert-relay', {
      replicas: 1,
      strategy: { type: 'Recreate' },
      selector: { matchLabels: labels },
      template: {
        metadata: { labels },
        spec: {
          automountServiceAccountToken: false,
          enableServiceLinks: false,
          securityContext: podSecurityContext,
          containers: [{
            name: 'relay',
            image: value.image,
            imagePullPolicy: 'IfNotPresent',
            ports: [{ name: 'http', containerPort: 8080, protocol: 'TCP' }],
            envFrom: [{ configMapRef: { name: 'dirizhor-alert-relay-config' } }],
            env: [
              { name: 'ALERT_RELAY_WEBHOOK_TOKEN_FILE', value: '/run/secrets/runtime/webhook-token' },
              { name: 'RESEND_API_KEY_FILE', value: '/run/secrets/runtime/resend-api-key' },
            ],
            volumeMounts: [
              { name: 'runtime', mountPath: '/run/secrets/runtime', readOnly: true },
              { name: 'tmp', mountPath: '/tmp' },
            ],
            readinessProbe: { httpGet: { path: '/health/ready', port: 'http' }, periodSeconds: 10, timeoutSeconds: 2, failureThreshold: 12 },
            livenessProbe: { httpGet: { path: '/health/live', port: 'http' }, periodSeconds: 20, timeoutSeconds: 2, failureThreshold: 3 },
            resources: {
              requests: { cpu: '25m', memory: '64Mi', 'ephemeral-storage': '64Mi' },
              limits: { cpu: '100m', memory: '128Mi', 'ephemeral-storage': '128Mi' },
            },
            securityContext: containerSecurityContext,
          }],
          volumes: [
            { name: 'runtime', secret: { secretName: value.secrets.runtime, defaultMode: 256 } },
            { name: 'tmp', emptyDir: { sizeLimit: '32Mi' } },
          ],
        },
      },
    }, labels),
    resource('networking.k8s.io/v1', 'NetworkPolicy', value.namespace, 'dirizhor-alert-relay', {
      podSelector: { matchLabels: labels },
      policyTypes: ['Ingress'],
      ingress: [{
        from: [{ podSelector: { matchLabels: { 'app.kubernetes.io/name': 'alertmanager' } } }],
        ports: [{ protocol: 'TCP', port: 8080 }],
      }],
    }, labels),
    resource('cilium.io/v2', 'CiliumNetworkPolicy', value.namespace, 'dirizhor-alert-relay-egress', {
      endpointSelector: { matchLabels: labels },
      ingress: [{
        fromEndpoints: [{ matchLabels: { 'k8s:app.kubernetes.io/name': 'alertmanager' } }],
        toPorts: [{ ports: [{ port: '8080', protocol: 'TCP' }] }],
      }],
      egress: [
        {
          toEndpoints: [{ matchLabels: { 'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns' } }],
          toPorts: [{ ports: [{ port: '53', protocol: 'UDP' }, { port: '53', protocol: 'TCP' }] }],
        },
        {
          toFQDNs: [{ matchName: 'api.resend.com' }],
          toPorts: [{ ports: [{ port: '443', protocol: 'TCP' }] }],
        },
      ],
    }, labels),
    resource('monitoring.coreos.com/v1alpha1', 'AlertmanagerConfig', value.namespace, 'dirizhor-resend-critical-webhook', {
      route: {
        receiver: 'dirizhor-resend-critical-webhook',
        groupBy: ['alertname', 'service'],
        groupWait: '30s',
        groupInterval: '5m',
        repeatInterval: '4h',
        matchers: [{ name: 'severity', value: 'critical', matchType: '=' }],
      },
      receivers: [{
        name: 'dirizhor-resend-critical-webhook',
        webhookConfigs: [{
          url: `http://${receiver}:8080/v1/alerts`,
          sendResolved: true,
          httpConfig: { authorization: { type: 'Bearer', credentials: { name: value.secrets.runtime, key: 'webhook-token' } } },
        }],
      }],
    }, labels),
  ];
}

export async function writeAlertRelayManifest(configPath, outputDirectory) {
  const output = path.resolve(outputDirectory);
  await mkdir(output, { recursive: false, mode: 0o700 });
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  const manifest = `${renderAlertRelay(config).map((entry) => JSON.stringify(entry, null, 2)).join('\n---\n')}\n`;
  const target = path.join(output, 'alert-relay-manifest.json');
  await writeFile(target, manifest, { mode: 0o600, flag: 'wx' });
  return target;
}

function resource(apiVersion, kind, namespace, name, specOrData, labels) {
  return kind === 'ConfigMap'
    ? { apiVersion, kind, metadata: { name, namespace, labels }, data: specOrData }
    : { apiVersion, kind, metadata: { name, namespace, labels }, spec: specOrData };
}

function exactObject(value, keys, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${name} contains unsupported or missing fields.`);
  }
}

function label(value, name) {
  if (typeof value !== 'string' || !dnsLabel.test(value)) throw new Error(`${name} is invalid.`);
}

function email(value, name) {
  if (typeof value !== 'string' || value.length > 254 || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value)) {
    throw new Error(`${name} must be an email address.`);
  }
}

async function main() {
  const [, , configPath, outputDirectory] = process.argv;
  if (!configPath || !outputDirectory) throw new Error('Usage: alert-relay-render.mjs <config.json> <new-output-directory>');
  process.stdout.write(`${await writeAlertRelayManifest(configPath, outputDirectory)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await main();
}
