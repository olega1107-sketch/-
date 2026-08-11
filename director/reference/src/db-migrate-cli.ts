import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { Client, type ClientConfig } from 'pg';

import {
  DatabaseMigrationRunner,
  loadMigrationPlan,
  type MigrationQueryable,
  type MigrationStatus,
} from './db-migrations.js';
import { requiredSecret } from './secret-config.js';

type Command = 'status' | 'migrate' | 'adopt-v1';

export async function runDatabaseMigrationCli(
  argv: readonly string[] = process.argv,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const command = parseCommand(argv[2]);
  const allowContract = argv.includes('--allow-contract');
  if (command === 'adopt-v1' && !argv.includes('--confirm-existing-schema-v1')) {
    throw new Error(
      'adopt-v1 requires --confirm-existing-schema-v1 after backup and schema verification.',
    );
  }
  const client = new Client(await clientConfig(environment));
  await client.connect();
  try {
    const connection: MigrationQueryable = {
      query: async <Row>(text: string, parameters?: readonly unknown[]) => {
        const result = await client.query(
          text,
          parameters === undefined ? undefined : [...parameters],
        );
        return { rows: result.rows as Row[], rowCount: result.rowCount };
      },
    };
    const runner = new DatabaseMigrationRunner(connection, await loadMigrationPlan());
    const status = command === 'status'
      ? await runner.inspect()
      : command === 'adopt-v1'
        ? await runner.adoptBaseline()
        : await runner.migrate({ allowContract });
    printStatus(status);
    if (status.pending.length > 0) process.exitCode = 2;
  } finally {
    await client.end();
  }
}

async function clientConfig(environment: NodeJS.ProcessEnv): Promise<ClientConfig> {
  const caPath = environment.DIRECTOR_MIGRATION_DATABASE_CA_PATH;
  return {
    connectionString: requiredSecret(
      environment,
      'DIRECTOR_MIGRATION_DATABASE_URL',
    ),
    application_name: 'dirizhor-migrator',
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

function parseCommand(value: string | undefined): Command {
  if (value === 'status' || value === 'migrate' || value === 'adopt-v1') return value;
  throw new Error('Usage: db-migrate-cli.js <status|migrate|adopt-v1> [safety flag]');
}

function printStatus(status: MigrationStatus): void {
  const applied = status.applied.map((migration) => migration.migrationId).join(', ');
  const pending = status.pending
    .map((migration) => `${migration.id}:${migration.phase}`)
    .join(', ');
  process.stdout.write(`Applied migrations: ${applied.length === 0 ? 'none' : applied}\n`);
  process.stdout.write(`Pending migrations: ${pending.length === 0 ? 'none' : pending}\n`);
  if (status.pending.some((migration) => migration.phase === 'contract')) {
    process.stdout.write('Contract phase requires a separate migrate --allow-contract run.\n');
  }
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void runDatabaseMigrationCli().catch(reportFailure);
}

export function reportFailure(error: unknown): void {
  const message = error instanceof Error ? error.message : 'Unknown migration error.';
  process.stderr.write(`Database migration failed: ${message}\n`);
  process.exitCode = 1;
}
