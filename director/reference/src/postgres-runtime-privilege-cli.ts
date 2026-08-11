import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { Client, type ClientConfig } from 'pg';

import { inspectRuntimePrivileges } from './postgres-runtime-privilege-probe.js';
import type { SqlQueryable } from './ports.js';
import { requiredSecret } from './secret-config.js';

export async function runRuntimePrivilegeCli(
  environment: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const client = new Client(await clientConfig(environment));
  await client.connect();
  try {
    const database: SqlQueryable = {
      query: async <Row>(text: string, parameters?: readonly unknown[]) => {
        const result = await client.query(
          text,
          parameters === undefined ? undefined : [...parameters],
        );
        return { rows: result.rows as Row[], rowCount: result.rowCount ?? 0 };
      },
    };
    const report = await inspectRuntimePrivileges({
      database,
      expectedDatabase: requiredEnvironment(environment, 'DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_DATABASE'),
      expectedRole: requiredEnvironment(environment, 'DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_ROLE'),
    });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (report.status !== 'PASS') process.exitCode = 1;
  } finally {
    await client.end();
  }
}

async function clientConfig(environment: NodeJS.ProcessEnv): Promise<ClientConfig> {
  const caPath = environment.DIRECTOR_DATABASE_CA_PATH;
  return {
    connectionString: requiredSecret(environment, 'DATABASE_URL'),
    application_name: 'dirizhor-runtime-privilege-probe',
    ...(caPath === undefined
      ? {}
      : {
          ssl: {
            ca: await readFile(caPath, 'utf8'),
            rejectUnauthorized: true,
          },
        }),
  };
}

function requiredEnvironment(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name]?.trim();
  if (value === undefined || value.length === 0) throw new Error(`${name} is required.`);
  return value;
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void runRuntimePrivilegeCli().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'Unknown runtime privilege error.';
    process.stderr.write(`PostgreSQL runtime privilege probe failed: ${message}\n`);
    process.exitCode = 2;
  });
}
