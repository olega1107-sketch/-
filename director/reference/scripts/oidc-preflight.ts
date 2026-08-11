import { loadOidcAuthenticationConfig } from '../src/config.js';
import { createOpenidClientProviderWithReport } from '../src/openid-client-provider.js';

async function main(): Promise<void> {
  const config = loadOidcAuthenticationConfig();
  const result = await createOpenidClientProviderWithReport({
    issuerUrl: config.issuerUrl,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: config.redirectUri,
    scopes: config.scopes,
    tokenEndpointAuthMethod: config.tokenEndpointAuthMethod,
    idTokenSigningAlgorithm: config.idTokenSigningAlgorithm,
    ...(config.postLogoutRedirectUri === undefined
      ? {}
      : { postLogoutRedirectUri: config.postLogoutRedirectUri }),
    timeoutSeconds: config.discoveryTimeoutMs / 1_000,
  });
  process.stdout.write(`${JSON.stringify(result.conformance, null, 2)}\n`);
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'OIDC preflight failed.';
  process.stderr.write(`OIDC preflight failed: ${message}\n`);
  process.exitCode = 1;
});
