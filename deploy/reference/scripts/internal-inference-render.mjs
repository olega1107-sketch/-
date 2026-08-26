import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const digestImage = /^[a-z0-9][a-z0-9.:-]*(?:\/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$/;
const dnsLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const qualifiedLabel = /^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\/)?[a-z0-9](?:[a-z0-9_.-]{0,61}[a-z0-9])?$/;

export function validateInternalInferenceConfig(config) {
  object(config, 'config');
  exact(config, ['schema_version', 'deployment_id', 'namespace', 'images', 'model', 'service_name', 'secrets', 'scheduling', 'resources'], 'config');
  if (config.schema_version !== 1) throw new Error('Unsupported internal inference schema.');
  label(config.deployment_id, 'deployment_id', 128);
  label(config.namespace, 'namespace');
  label(config.service_name, 'service_name');
  exactObject(config.images, ['adapter', 'model_runtime'], 'images');
  for (const [name, image] of Object.entries(config.images)) {
    if (typeof image !== 'string' || !digestImage.test(image)) throw new Error(`${name} image must be digest-pinned.`);
  }
  exactObject(config.model, ['id', 'path'], 'model');
  if (config.model.id !== 'Qwen3-4B-Q4_K_M' || config.model.path !== '/model-work/Qwen3-4B-Q4_K_M.gguf') {
    throw new Error('Pilot model identity or path is not approved.');
  }
  exactObject(config.secrets, ['runtime', 'tls'], 'secrets');
  Object.values(config.secrets).forEach((name) => label(name, 'secret'));
  exactObject(config.scheduling, ['label_key', 'label_value', 'taint_effect'], 'scheduling');
  if (!qualifiedLabel.test(config.scheduling.label_key) || config.scheduling.label_value !== 'internal-inference' || config.scheduling.taint_effect !== 'NoSchedule') {
    throw new Error('Dedicated inference scheduling is invalid.');
  }
  exactObject(config.resources, ['adapter', 'model_runtime'], 'resources');
  resourceSet(config.resources.adapter, 'adapter resources');
  resourceSet(config.resources.model_runtime, 'model runtime resources');
  return structuredClone(config);
}

export function renderInternalInference(config) {
  const value = validateInternalInferenceConfig(config);
  const labels = {
    'app.kubernetes.io/name': 'dirizhor-inference',
    'app.kubernetes.io/component': 'internal-model',
    'app.kubernetes.io/managed-by': 'dirizhor-render',
  };
  const securityContext = {
    allowPrivilegeEscalation: false,
    readOnlyRootFilesystem: true,
    runAsNonRoot: true,
    capabilities: { drop: ['ALL'] },
  };
  return [
    resource('v1', 'Service', value.namespace, value.service_name, {
      selector: labels,
      ports: [{ name: 'https', port: 8443, targetPort: 'https', protocol: 'TCP' }],
      type: 'ClusterIP',
    }, labels),
    resource('apps/v1', 'Deployment', value.namespace, 'dirizhor-inference', {
      replicas: 1,
      strategy: { type: 'Recreate' },
      selector: { matchLabels: labels },
      template: {
        metadata: { labels },
        spec: {
          automountServiceAccountToken: false,
          enableServiceLinks: false,
          nodeSelector: { [value.scheduling.label_key]: value.scheduling.label_value },
          tolerations: [{ key: value.scheduling.label_key, operator: 'Equal', value: value.scheduling.label_value, effect: value.scheduling.taint_effect }],
          securityContext: { runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, fsGroup: 10001, seccompProfile: { type: 'RuntimeDefault' } },
          terminationGracePeriodSeconds: 30,
          containers: [
            {
              name: 'adapter',
              image: value.images.adapter,
              imagePullPolicy: 'IfNotPresent',
              ports: [{ name: 'https', containerPort: 8443, protocol: 'TCP' }],
              env: [
                { name: 'INFERENCE_MODEL', value: value.model.id },
                { name: 'LLAMA_UPSTREAM_ORIGIN', value: 'http://127.0.0.1:8080' },
                { name: 'INFERENCE_TOKEN_FILE', value: '/run/secrets/runtime/token' },
                { name: 'INFERENCE_TLS_CERT_PATH', value: '/run/secrets/tls/tls.crt' },
                { name: 'INFERENCE_TLS_KEY_PATH', value: '/run/secrets/tls/tls.key' },
                { name: 'INFERENCE_TLS_CA_PATH', value: '/run/secrets/tls/ca.crt' },
              ],
              volumeMounts: [
                { name: 'runtime', mountPath: '/run/secrets/runtime', readOnly: true },
                { name: 'tls', mountPath: '/run/secrets/tls', readOnly: true },
                { name: 'tmp', mountPath: '/tmp' },
              ],
              readinessProbe: { exec: { command: ['node', '-e', "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"] }, initialDelaySeconds: 5, periodSeconds: 10, timeoutSeconds: 3, failureThreshold: 18 },
              livenessProbe: { tcpSocket: { port: 'https' }, initialDelaySeconds: 10, periodSeconds: 20, timeoutSeconds: 2, failureThreshold: 3 },
              resources: value.resources.adapter,
              securityContext,
            },
            {
              name: 'model-runtime',
              image: value.images.model_runtime,
              imagePullPolicy: 'IfNotPresent',
              command: ['/bin/sh', '-ec'],
              args: [`cat /model-parts/part-* > ${value.model.path}\nexec /app/llama-server --model ${value.model.path} --alias ${value.model.id} --host 127.0.0.1 --port 8080 --threads 4 --threads-batch 4 --ctx-size 8192 --parallel 1 --batch-size 512 --ubatch-size 128 --offline --no-webui`],
              volumeMounts: [{ name: 'tmp', mountPath: '/tmp' }, { name: 'model-work', mountPath: '/model-work' }],
              // llama.cpp is intentionally bound to loopback; kubelet HTTP probes use the Pod IP.
              startupProbe: { exec: { command: ['/bin/sh', '-ec', 'curl --fail --silent --show-error --output /dev/null http://127.0.0.1:8080/health'] }, periodSeconds: 10, timeoutSeconds: 3, failureThreshold: 60 },
              livenessProbe: { exec: { command: ['/bin/sh', '-ec', 'curl --fail --silent --show-error --output /dev/null http://127.0.0.1:8080/health'] }, periodSeconds: 30, timeoutSeconds: 3, failureThreshold: 3 },
              resources: value.resources.model_runtime,
              securityContext,
            },
          ],
          volumes: [
            { name: 'runtime', secret: { secretName: value.secrets.runtime, defaultMode: 256 } },
            { name: 'tls', secret: { secretName: value.secrets.tls, defaultMode: 256 } },
            { name: 'tmp', emptyDir: { sizeLimit: '256Mi' } },
            { name: 'model-work', emptyDir: { sizeLimit: '3Gi' } },
          ],
        },
      },
    }, labels),
    resource('networking.k8s.io/v1', 'NetworkPolicy', value.namespace, 'dirizhor-inference', {
      podSelector: { matchLabels: labels },
      policyTypes: ['Ingress', 'Egress'],
      ingress: [{
        from: [{ podSelector: { matchLabels: { 'app.kubernetes.io/name': 'dirizhor-gateway' } } }],
        ports: [{ protocol: 'TCP', port: 8443 }],
      }],
      egress: [],
    }, labels),
  ];
}

export async function writeInternalInferenceManifest(configPath, outputDirectory) {
  const output = path.resolve(outputDirectory);
  await mkdir(output, { recursive: false, mode: 0o700 });
  await chmod(output, 0o700);
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  const resources = renderInternalInference(config);
  const manifest = `${resources.map((entry) => JSON.stringify(entry, null, 2)).join('\n---\n')}\n`;
  const target = path.join(output, 'internal-inference-manifest.json');
  await writeFile(target, manifest, { mode: 0o600, flag: 'wx' });
  return target;
}

function resource(apiVersion, kind, namespace, name, spec, labels) {
  return { apiVersion, kind, metadata: { name, namespace, labels }, spec };
}

function resourceSet(value, name) {
  exactObject(value, ['requests', 'limits'], name);
  for (const side of ['requests', 'limits']) {
    exactObject(value[side], ['cpu', 'memory', 'ephemeral-storage'], `${name}.${side}`);
    for (const quantity of Object.values(value[side])) {
      if (typeof quantity !== 'string' || !/^[1-9][0-9]*(?:m|Mi|Gi)$/.test(quantity)) throw new Error(`${name} contains an invalid quantity.`);
    }
  }
}

function exactObject(value, keys, name) {
  object(value, name);
  exact(value, keys, name);
}

function object(value, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object.`);
}

function exact(value, keys, name) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${name} contains unsupported or missing fields.`);
}

function label(value, name, max = 63) {
  if (typeof value !== 'string' || value.length > max || !dnsLabel.test(value)) throw new Error(`${name} is invalid.`);
}

async function main() {
  const [, , configPath, outputDirectory] = process.argv;
  if (!configPath || !outputDirectory) throw new Error('Usage: internal-inference-render.mjs <config.json> <new-output-directory>');
  process.stdout.write(`${await writeInternalInferenceManifest(configPath, outputDirectory)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await main();
}
