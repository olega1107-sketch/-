import { readFile } from 'node:fs/promises';
import { Agent } from 'undici';

import { AgentResultService } from './agent-result-service.js';
import { StaticAgentRouteResolver } from './agent-routing.js';
import { buildDirectorApp } from './app.js';
import { HmacCapabilityTokenIssuer } from './capability-token.js';
import { ConfirmationService } from './confirmation-service.js';
import { loadDirectorConfig } from './config.js';
import { DecisionService } from './decision-service.js';
import { assertDatabaseMigrationsCurrent } from './db-migrations.js';
import { DirectorService } from './director-service.js';
import { FileDocumentStore } from './file-document-store.js';
import { HttpAgentGatewayClient } from './http-agent-gateway-client.js';
import { MemoryIngestService } from './memory-ingest-service.js';
import { OidcService } from './oidc-service.js';
import { createOpenidClientProvider } from './openid-client-provider.js';
import { PostgresDatabase } from './postgres-database.js';
import { PostgresDirectorRepository } from './postgres-director-repository.js';
import { PostgresMemoryIngestRepository } from './postgres-memory-ingest-repository.js';
import { PostgresOidcLoginTransactionRepository } from './postgres-oidc-repository.js';
import { PostgresConfirmationRepository } from './postgres-confirmation-repository.js';
import { PostgresDecisionRepository } from './postgres-decision-repository.js';
import { PostgresAgentResultRepository } from './postgres-agent-result-repository.js';
import { PostgresAuthorizationAuditRecorder } from './postgres-authorization-audit-recorder.js';
import { PostgresPublicQueryRepository } from './postgres-public-query-repository.js';
import { PostgresSessionRepository } from './postgres-session-repository.js';
import { PostgresTaskRepository } from './postgres-task-repository.js';
import { PostgresUserSessionAuthenticator } from './postgres-user-session-authenticator.js';
import { PublicQueryService } from './public-query-service.js';
import {
  StaticBearerAuthenticator,
  WorkloadIdentityAuthenticator,
} from './service-auth.js';
import { SessionService } from './session-service.js';
import { TaskService } from './task-service.js';
import { StaticUserBearerAuthenticator } from './user-auth.js';
import {
  Ed25519WorkloadTokenIssuer,
  Ed25519WorkloadTokenVerifier,
} from './workload-identity.js';

async function main(): Promise<void> {
  const config = loadDirectorConfig();
  const databaseCa =
    config.databaseCaPath === undefined
      ? undefined
      : await readFile(config.databaseCaPath, 'utf8');
  const database = new PostgresDatabase({
    connectionString: config.databaseUrl,
    max: config.databasePoolSize,
    ...(databaseCa === undefined
      ? {}
      : { ssl: { ca: databaseCa, rejectUnauthorized: true } }),
  });
  try {
    await database.query('SELECT 1');
    await assertDatabaseMigrationsCurrent(database);
  } catch (error) {
    await database.close();
    throw error;
  }
  const documentStore = new FileDocumentStore(config.documentStoreRoot);
  await documentStore.initialize();
  const capabilityTokens = new HmacCapabilityTokenIssuer(
    HmacCapabilityTokenIssuer.keyFromBase64(config.capabilityKeyBase64),
  );
  const gatewayDispatcher =
    config.gatewayClientTls === undefined
      ? undefined
      : new Agent({
          connect: {
            cert: await readFile(config.gatewayClientTls.certPath),
            key: await readFile(config.gatewayClientTls.keyPath),
            ca: await readFile(config.gatewayClientTls.caPath),
            rejectUnauthorized: true,
          },
        });
  const outboundWorkloadIssuer =
    config.serviceIdentity.mode === 'workload'
      ? new Ed25519WorkloadTokenIssuer({
          issuer: 'director-api',
          audience: 'agent-gateway',
          keyId: config.serviceIdentity.signingKeyId,
          privateKeyBase64: config.serviceIdentity.signingPrivateKeyBase64,
          ttlSeconds: config.serviceIdentity.tokenTtlSeconds,
        })
      : undefined;
  const agentGateway = new HttpAgentGatewayClient({
    baseUrl: config.gatewayBaseUrl,
    tokenProvider: () =>
      outboundWorkloadIssuer?.issue() ??
      (config.serviceIdentity.mode === 'static-development'
        ? config.serviceIdentity.outboundToken
        : (() => { throw new Error('Director workload token issuer is unavailable.'); })()),
    timeoutMs: config.gatewayRequestTimeoutMs,
    allowHttpForDevelopment: config.allowInsecureDevelopment,
    ...(gatewayDispatcher === undefined ? {} : { dispatcher: gatewayDispatcher }),
  });
  const routeResolver = new StaticAgentRouteResolver(config.agentRouting);
  const userAuthenticator =
    config.publicAuthentication.mode === 'session'
      ? new PostgresUserSessionAuthenticator({
          database,
          ...(config.oidcAuthentication === undefined
            ? {}
            : {
                cookieOrigin: new URL(
                  config.oidcAuthentication.postLoginRedirectUri,
                ).origin,
              }),
        })
      : new StaticUserBearerAuthenticator({
          token: config.publicAuthentication.token,
          userId: config.publicAuthentication.userId,
        });
  const sessionRepository =
    config.publicAuthentication.mode === 'session'
      ? new PostgresSessionRepository(database)
      : undefined;
  const sessionService =
    sessionRepository === undefined
      ? undefined
      : new SessionService({
          repository: sessionRepository,
          sessionTtlMs: config.userSessionTtlMs,
        });
  const oidcProvider =
    config.oidcAuthentication === undefined
      ? undefined
      : await createOpenidClientProvider({
          issuerUrl: config.oidcAuthentication.issuerUrl,
          clientId: config.oidcAuthentication.clientId,
          clientSecret: config.oidcAuthentication.clientSecret,
          redirectUri: config.oidcAuthentication.redirectUri,
          scopes: config.oidcAuthentication.scopes,
          tokenEndpointAuthMethod:
            config.oidcAuthentication.tokenEndpointAuthMethod,
          idTokenSigningAlgorithm:
            config.oidcAuthentication.idTokenSigningAlgorithm,
          ...(config.oidcAuthentication.postLogoutRedirectUri === undefined
            ? {}
            : {
                postLogoutRedirectUri:
                  config.oidcAuthentication.postLogoutRedirectUri,
              }),
          timeoutSeconds: config.oidcAuthentication.discoveryTimeoutMs / 1_000,
        });
  const oidcService =
    config.oidcAuthentication === undefined ||
    oidcProvider === undefined ||
    sessionService === undefined
      ? undefined
      : new OidcService({
          providerCode: config.oidcAuthentication.providerCode,
          issuerUrl: config.oidcAuthentication.issuerUrl,
          redirectUri: config.oidcAuthentication.redirectUri,
          repository: new PostgresOidcLoginTransactionRepository(database),
          provider: oidcProvider,
          sessions: sessionService,
          transactionTtlMs: config.oidcAuthentication.transactionTtlMs,
        });
  const service = new DirectorService({
    repository: new PostgresDirectorRepository(database),
    documentStore,
    resultTtlMs: config.resultTtlMs,
  });
  const https =
    config.tls === undefined
      ? null
      : {
          cert: await readFile(config.tls.certPath),
          key: await readFile(config.tls.keyPath),
          ca: await readFile(config.tls.caPath),
          requestCert: true,
          // Internal authenticators require socket.authorized; public routes do not require mTLS.
          rejectUnauthorized: false,
        };
  const app = buildDirectorApp({
    service,
    readiness: async () => {
      await Promise.all([database.query('SELECT 1'), documentStore.checkReady()]);
    },
    trustedProxies: config.trustedProxyCidrs,
    authenticator:
      config.serviceIdentity.mode === 'workload'
        ? new WorkloadIdentityAuthenticator({
            verifier: new Ed25519WorkloadTokenVerifier({
              issuer: 'agent-gateway',
              audience: 'director-api',
              keys: config.serviceIdentity.verificationKeys,
            }),
            requireMutualTls: !config.allowInsecureDevelopment,
            allowedPeerCommonNames: config.tls?.allowedPeerCommonNames ?? [],
          })
        : new StaticBearerAuthenticator({
            token: config.serviceIdentity.inboundToken,
            requireMutualTls: false,
          }),
    publicApi: {
      memoryIngest: new MemoryIngestService({
        repository: new PostgresMemoryIngestRepository(database),
        documentStore,
      }),
      authenticator: userAuthenticator,
      authorizationAudit: new PostgresAuthorizationAuditRecorder({ database }),
      ...(sessionService === undefined
        ? {}
        : {
            sessions: {
              service: sessionService,
              allowLocalPasswordIssuance: config.localPasswordLoginEnabled,
              ...(oidcService === undefined || config.oidcAuthentication === undefined
                ? {}
                : {
                    oidc: {
                      service: oidcService,
                      postLoginRedirectUri:
                        config.oidcAuthentication.postLoginRedirectUri,
                    },
                  }),
            },
          }),
      maxUploadBytes: config.maxDocumentUploadBytes,
      agentResults: new AgentResultService({
        repository: new PostgresAgentResultRepository(database),
        documentStore,
        confirmationTtlMs: config.confirmationTtlMs,
      }),
      tasks: new TaskService({
        repository: new PostgresTaskRepository(database),
        gateway: agentGateway,
        capabilityTokens,
        routeResolver,
        runDeadlineMs: config.agentRunDeadlineMs,
        capabilityTtlMs: config.capabilityTtlMs,
        confirmationTtlMs: config.confirmationTtlMs,
      }),
      confirmations: new ConfirmationService({
        repository: new PostgresConfirmationRepository(database),
        gateway: agentGateway,
        capabilityTokens,
        runDeadlineMs: config.agentRunDeadlineMs,
        capabilityTtlMs: config.capabilityTtlMs,
      }),
      decisions: new DecisionService({
        repository: new PostgresDecisionRepository(database),
      }),
      queries: new PublicQueryService({
        repository: new PostgresPublicQueryRepository(database),
      }),
    },
    https,
  });
  await app.listen({ host: config.host, port: config.port });
  const scheme = config.allowInsecureDevelopment ? 'http' : 'https';
  process.stdout.write(`Reference Director listening at ${scheme}://${config.host}:${config.port}\n`);

  let shutdownStarted = false;
  const shutdown = async (signal: 'SIGINT' | 'SIGTERM'): Promise<void> => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    try {
      await app.close();
      await gatewayDispatcher?.close();
      await database.close();
      process.stdout.write(`Reference Director graceful shutdown complete (${signal}).\n`);
    } catch {
      process.stderr.write('Reference Director graceful shutdown failed.\n');
      process.exitCode = 1;
    }
  };
  process.once('SIGINT', () => void shutdown('SIGINT'));
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown startup error.';
  process.stderr.write(`Reference Director failed to start: ${message}\n`);
  process.exitCode = 1;
});
