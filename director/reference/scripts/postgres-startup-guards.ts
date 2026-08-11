import { readFile } from 'node:fs/promises';

import { Client, type ClientConfig } from 'pg';

import {
  assertDatabaseMigrationsCurrent,
  DatabaseMigrationRunner,
  loadMigrationPlan,
  type LoadedMigration,
} from '../src/db-migrations.js';
import type { SqlQueryable } from '../src/ports.js';
import { requiredSecret } from '../src/secret-config.js';

interface GuardResult {
  scenario: 'dirty_history' | 'checksum_drift' | 'pending_history';
  refused_startup: true;
}

async function main(): Promise<void> {
  const expectedDatabase = requiredEnvironment('DIRECTOR_STARTUP_GUARD_EXPECT_DATABASE');
  const client = new Client({
    ...(await testDatabaseConfig()),
    application_name: 'dirizhor-startup-guard-evidence',
  });
  let disposableDatabaseVerified = false;
  await client.connect();
  try {
    await assertDisposableDatabase(client, expectedDatabase);
    disposableDatabaseVerified = true;

    const database = migrationQueryable(client);
    const plan = await loadMigrationPlan();
    const migrationStatus = await new DatabaseMigrationRunner(database, plan).migrate({
      allowContract: true,
    });
    if (migrationStatus.pending.length > 0) {
      throw new Error('Startup-guard evidence database has pending migrations after setup.');
    }
    await assertDatabaseMigrationsCurrent(database, plan);

    const results = await verifyRefusalScenarios(client, database, plan);
    process.stdout.write(
      `${JSON.stringify({
        schema_version: 1,
        status: 'PASS',
        check: 'postgres.migration_startup_guards',
        scenarios: results,
      })}\n`,
    );
  } finally {
    if (disposableDatabaseVerified) {
      await client.query('DROP SCHEMA IF EXISTS dirizhor CASCADE');
      await client.query('DROP SCHEMA IF EXISTS dirizhor_migrations CASCADE');
    }
    await client.end();
  }
}

async function verifyRefusalScenarios(
  client: Client,
  database: SqlQueryable,
  plan: readonly LoadedMigration[],
): Promise<GuardResult[]> {
  const latest = plan.at(-1);
  if (latest === undefined) {
    throw new Error('Migration plan must contain at least one migration.');
  }
  const driftChecksum =
    latest.checksum === `sha256:${'f'.repeat(64)}`
      ? `sha256:${'0'.repeat(64)}`
      : `sha256:${'f'.repeat(64)}`;

  return [
    await expectStartupRefusal(
      client,
      database,
      plan,
      'dirty_history',
      /left in applying state/,
      async () => {
        await client.query(
          `
            UPDATE dirizhor_migrations.schema_migrations
            SET status = 'applying', applied_at = NULL, execution_ms = NULL
            WHERE version = $1
          `,
          [latest.version],
        );
      },
    ),
    await expectStartupRefusal(
      client,
      database,
      plan,
      'checksum_drift',
      /differs from the release manifest/,
      async () => {
        await client.query(
          `UPDATE dirizhor_migrations.schema_migrations SET checksum = $2 WHERE version = $1`,
          [latest.version, driftChecksum],
        );
      },
    ),
    await expectStartupRefusal(
      client,
      database,
      plan,
      'pending_history',
      /pending migration\(s\)/,
      async () => {
        await client.query(
          `DELETE FROM dirizhor_migrations.schema_migrations WHERE version = $1`,
          [latest.version],
        );
      },
    ),
  ];
}

async function expectStartupRefusal(
  client: Client,
  database: SqlQueryable,
  plan: readonly LoadedMigration[],
  scenario: GuardResult['scenario'],
  expectedMessage: RegExp,
  mutate: () => Promise<void>,
): Promise<GuardResult> {
  await client.query('BEGIN');
  try {
    await mutate();
    let refusal: unknown;
    try {
      await assertDatabaseMigrationsCurrent(database, plan);
    } catch (error) {
      refusal = error;
    }
    if (!(refusal instanceof Error) || !expectedMessage.test(refusal.message)) {
      throw new Error(`Startup guard did not reject the ${scenario} scenario as expected.`);
    }
    return { scenario, refused_startup: true };
  } finally {
    await client.query('ROLLBACK');
  }
}

async function assertDisposableDatabase(client: Client, expectedDatabase: string): Promise<void> {
  const identity = await client.query<{
    databaseName: string;
    serverVersion: string;
    userObjectCount: string;
  }>(`
    SELECT
      current_database() AS "databaseName",
      current_setting('server_version_num') AS "serverVersion",
      (
        SELECT count(*)::text
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema')
          AND namespace.nspname !~ '^pg_toast'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
      ) AS "userObjectCount"
  `);
  const row = identity.rows[0];
  if (row === undefined || row.databaseName !== expectedDatabase) {
    throw new Error('Startup-guard database name does not match the explicit safety value.');
  }
  if (['postgres', 'template0', 'template1'].includes(row.databaseName)) {
    throw new Error('Startup-guard harness refuses a PostgreSQL administrative database.');
  }
  if (Number(row.serverVersion) < 150_000) {
    throw new Error('Startup-guard harness requires PostgreSQL 15 or newer.');
  }
  if (row.userObjectCount !== '0') {
    throw new Error('Startup-guard harness requires a dedicated database with no user objects.');
  }
}

function migrationQueryable(client: Client): SqlQueryable {
  return {
    query: async <Row>(text: string, parameters?: readonly unknown[]) => {
      const result = await client.query(
        text,
        parameters === undefined ? undefined : [...parameters],
      );
      return { rows: result.rows as Row[], rowCount: result.rowCount ?? 0 };
    },
  };
}

async function testDatabaseConfig(): Promise<ClientConfig> {
  const caPath = process.env.DIRECTOR_STARTUP_GUARD_DATABASE_CA_PATH;
  return {
    connectionString: requiredSecret(process.env, 'DIRECTOR_STARTUP_GUARD_DATABASE_URL'),
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

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown startup-guard error.';
  process.stderr.write(`PostgreSQL startup-guard evidence failed: ${message}\n`);
  process.exitCode = 1;
});
