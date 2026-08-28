import { readFile } from 'node:fs/promises';
import { Agent } from 'undici';

import { buildGatewayApp } from './app.js';
import { loadGatewayConfig } from './config.js';
import { EncryptedFileExecutionStore } from './encrypted-file-execution-store.js';
import { FixtureProviderAdapter } from './fixture-provider-adapter.js';
import { GatewayService } from './gateway-service.js';
import { HttpDirectorClient } from './http-director-client.js';
import { InternalInferenceAdapter } from './internal-inference-adapter.js';
import { closeMetricsServer, PrometheusMetrics, startMetricsServer } from './metrics.js';
import { OpenAIResponsesAdapter } from './openai-responses-adapter.js';
import type { ProviderAdapter } from './ports.js';
import {
  StaticBearerAuthenticator,
  WorkloadIdentityAuthenticator,
} from './service-auth.js';
import {
  Ed25519WorkloadTokenIssuer,
  Ed25519WorkloadTokenVerifier,
} from './workload-identity.js';

async function main(): Promise<void> {
  const config = loadGatewayConfig();
  const metrics = new PrometheusMetrics('gateway');
  const store = new EncryptedFileExecutionStore(
    config.stateDirectory,
    EncryptedFileExecutionStore.keyFromBase64(config.spoolKeyBase64),
  );
  await store.initialize();
  const directorDispatcher =
    config.directorClientTls === undefined
      ? undefined
      : new Agent({
          connect: {
            cert: await readFile(config.directorClientTls.certPath),
            key: await readFile(config.directorClientTls.keyPath),
            ca: await readFile(config.directorClientTls.caPath),
            rejectUnauthorized: true,
          },
        });
  const outboundWorkloadIssuer =
    config.serviceIdentity.mode === 'workload'
      ? new Ed25519WorkloadTokenIssuer({
          issuer: 'agent-gateway',
          audience: 'director-api',
          keyId: config.serviceIdentity.signingKeyId,
          privateKeyBase64: config.serviceIdentity.signingPrivateKeyBase64,
          ttlSeconds: config.serviceIdentity.tokenTtlSeconds,
        })
      : undefined;
  const director = new HttpDirectorClient({
    baseUrl: config.directorBaseUrl,
    tokenProvider: () =>
      outboundWorkloadIssuer?.issue() ??
      (config.serviceIdentity.mode === 'static-development'
        ? config.serviceIdentity.outboundToken
        : (() => { throw new Error('Gateway workload token issuer is unavailable.'); })()),
    allowHttpForDevelopment: config.allowInsecureDevelopment,
    ...(directorDispatcher === undefined ? {} : { dispatcher: directorDispatcher }),
  });
  const adapters: ProviderAdapter[] = [];
  const internalProviderDispatcher =
    config.internalProvider?.clientTls === undefined
      ? undefined
      : new Agent({
          connect: {
            cert: await readFile(config.internalProvider.clientTls.certPath),
            key: await readFile(config.internalProvider.clientTls.keyPath),
            ca: await readFile(config.internalProvider.clientTls.caPath),
            rejectUnauthorized: true,
          },
        });
  if (config.internalProvider !== undefined) {
    adapters.push(
      new InternalInferenceAdapter({
        origin: config.internalProvider.origin,
        models: config.internalProvider.models,
        tokenProvider: () => config.internalProvider!.token,
        allowHttpForDevelopment: config.allowInsecureDevelopment,
        ...(internalProviderDispatcher === undefined
          ? {}
          : { dispatcher: internalProviderDispatcher }),
      }),
    );
  }
  if (config.openAiApiKey !== undefined) {
    adapters.push(new OpenAIResponsesAdapter({ apiKey: config.openAiApiKey }));
  }
  if (config.enableFixtureProvider) {
    adapters.push(new FixtureProviderAdapter());
  }
  if (adapters.length === 0) {
    throw new Error('At least one provider adapter must be enabled.');
  }

  const service = new GatewayService({
    store,
    director,
    adapters,
    onBackgroundError: (_error, agentRunId) => {
      process.stderr.write(`Gateway processing stopped for run ${agentRunId}.\n`);
    },
  });
  const https =
    config.tls === undefined
      ? null
      : {
          cert: await readFile(config.tls.certPath),
          key: await readFile(config.tls.keyPath),
          ca: await readFile(config.tls.caPath),
          requestCert: true,
          rejectUnauthorized: true,
        };
  const app = buildGatewayApp({
    service,
    readiness: () => store.checkReady(),
    authenticator:
      config.serviceIdentity.mode === 'workload'
        ? new WorkloadIdentityAuthenticator({
            verifier: new Ed25519WorkloadTokenVerifier({
              issuer: 'director-api',
              audience: 'agent-gateway',
              keys: config.serviceIdentity.verificationKeys,
            }),
            requireMutualTls: !config.allowInsecureDevelopment,
            allowedPeerCommonNames: config.tls?.allowedPeerCommonNames ?? [],
          })
        : new StaticBearerAuthenticator({
            token: config.serviceIdentity.inboundToken,
            requireMutualTls: false,
    }),
    https,
    ...(config.metrics === undefined ? {} : { metrics }),
  });

  await service.resumePending();
  await app.listen({ host: config.host, port: config.port });
  let metricsServer;
  try {
    metricsServer = config.metrics === undefined
      ? undefined
      : await startMetricsServer({ ...config.metrics, metrics });
  } catch (error) {
    await app.close();
    await internalProviderDispatcher?.close();
    await directorDispatcher?.close();
    throw error;
  }
  const scheme = config.allowInsecureDevelopment ? 'http' : 'https';
  process.stdout.write(`Agent Gateway listening at ${scheme}://${config.host}:${config.port}\n`);

  let shutdownStarted = false;
  const shutdown = async (signal: 'SIGINT' | 'SIGTERM'): Promise<void> => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    try {
      await closeMetricsServer(metricsServer);
      await app.close();
      await internalProviderDispatcher?.close();
      await directorDispatcher?.close();
      process.stdout.write(`Agent Gateway graceful shutdown complete (${signal}).\n`);
    } catch {
      process.stderr.write('Agent Gateway graceful shutdown failed.\n');
      process.exitCode = 1;
    }
  };
  process.once('SIGINT', () => void shutdown('SIGINT'));
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown startup error.';
  process.stderr.write(`Agent Gateway failed to start: ${message}\n`);
  process.exitCode = 1;
});
