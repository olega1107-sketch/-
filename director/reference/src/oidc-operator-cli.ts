import { readFile } from 'node:fs/promises';

import type { PoolConfig } from 'pg';

import { PostgresDatabase } from './postgres-database.js';
import { requiredSecret } from './secret-config.js';

export async function createOidcOperatorDatabase(
  applicationName: string,
): Promise<PostgresDatabase> {
  const caPath = process.env.DIRECTOR_PROVISIONING_DATABASE_CA_PATH;
  const config: PoolConfig = {
    connectionString: requiredSecret(process.env, 'DIRECTOR_PROVISIONING_DATABASE_URL'),
    application_name: applicationName,
    max: 1,
    ...(caPath === undefined
      ? {}
      : { ssl: { ca: await readFile(caPath, 'utf8'), rejectUnauthorized: true } }),
  };
  return new PostgresDatabase(config);
}

export async function readOperatorJson(): Promise<unknown> {
  if (process.stdin.isTTY || process.argv.length > 2) {
    throw new Error('Read one JSON document from stdin; arguments are not accepted.');
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > 16 * 1024) throw new Error('Operator input exceeds 16 KiB.');
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value.length === 0) throw new Error(`${name} is required.`);
  return value;
}
