import {
  OidcAccessRevoker,
  parseOidcAccessRevocationInput,
} from '../src/oidc-access-revocation.js';
import {
  createOidcOperatorDatabase,
  readOperatorJson,
} from './oidc-operator-io.js';

async function main(): Promise<void> {
  const input = parseOidcAccessRevocationInput(await readOperatorJson());
  const database = await createOidcOperatorDatabase('dirizhor-oidc-revoker');
  try {
    const result = await new OidcAccessRevoker(database).revoke(input);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await database.close();
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'OIDC access revocation failed.';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
