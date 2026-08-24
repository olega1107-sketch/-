import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  OidcProvisioner,
  parseOidcProvisioningInput,
} from './oidc-provisioning.js';
import {
  createOidcOperatorDatabase,
  readOperatorJson,
  requiredEnvironment,
} from './oidc-operator-cli.js';

export async function runOidcProvisionCli(): Promise<void> {
  const input = parseOidcProvisioningInput(await readOperatorJson());
  const database = await createOidcOperatorDatabase('dirizhor-oidc-provisioner');
  try {
    const result = await new OidcProvisioner({
      database,
      providerCode: process.env.DIRECTOR_OIDC_PROVIDER_CODE ?? 'corporate',
      issuerUrl: requiredEnvironment('DIRECTOR_OIDC_ISSUER_URL'),
    }).provision(input);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await database.close();
  }
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void runOidcProvisionCli().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'OIDC provisioning failed.';
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
