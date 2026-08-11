import {
  OidcProvisioner,
  parseOidcProvisioningInput,
} from '../src/oidc-provisioning.js';
import {
  createOidcOperatorDatabase,
  readOperatorJson,
  requiredEnvironment,
} from './oidc-operator-io.js';

async function main(): Promise<void> {
  const input = parseOidcProvisioningInput(await readOperatorJson());
  const database = await createOidcOperatorDatabase('dirizhor-oidc-provisioner');
  try {
    const provisioner = new OidcProvisioner({
      database,
      providerCode: process.env.DIRECTOR_OIDC_PROVIDER_CODE ?? 'corporate',
      issuerUrl: requiredEnvironment('DIRECTOR_OIDC_ISSUER_URL'),
    });
    process.stdout.write(`${JSON.stringify(await provisioner.provision(input))}\n`);
  } finally {
    await database.close();
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'OIDC provisioning failed.';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
