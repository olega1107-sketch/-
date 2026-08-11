import { readFile } from 'node:fs/promises';

import { Client, type ClientConfig } from 'pg';

import { verifyDocumentStoreBackup } from '../src/backup-integrity.js';
import { assertDatabaseMigrationsCurrent } from '../src/db-migrations.js';
import type { SqlQueryable } from '../src/ports.js';
import { requiredSecret } from '../src/secret-config.js';

async function main(): Promise<void> {
  const expectedDatabase = requiredEnvironment('DIRECTOR_EVIDENCE_EXPECT_DATABASE');
  const documentStoreRoot = requiredEnvironment(
    'DIRECTOR_EVIDENCE_DOCUMENT_STORE_ROOT',
  );
  const expectedManifest = optionalEnvironment(
    'DIRECTOR_EVIDENCE_EXPECT_DOCUMENT_MANIFEST_HASH',
  );
  if (
    expectedManifest !== undefined &&
    !/^sha256:[0-9a-f]{64}$/.test(expectedManifest)
  ) {
    throw new Error(
      'DIRECTOR_EVIDENCE_EXPECT_DOCUMENT_MANIFEST_HASH must be a SHA-256 hash.',
    );
  }
  const client = new Client(await clientConfig());
  await client.connect();
  try {
    const identity = await client.query<{
      databaseName: string;
      serverVersion: string;
    }>(
      `
        SELECT
          current_database() AS "databaseName",
          current_setting('server_version_num') AS "serverVersion"
      `,
    );
    const row = identity.rows[0];
    if (
      row === undefined ||
      row.databaseName !== expectedDatabase ||
      Number(row.serverVersion) < 150_000
    ) {
      throw new Error('Evidence verifier connected to an unexpected database.');
    }
    const database = queryable(client);
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try {
      await assertDatabaseMigrationsCurrent(database);
      const verified = await verifyDocumentStoreBackup(database, documentStoreRoot);
      if (
        expectedManifest !== undefined &&
        verified.evidence.manifestHash !== expectedManifest
      ) {
        throw new Error('Document Store manifest does not match expected evidence.');
      }
      await client.query('COMMIT');
      process.stdout.write(
        `${JSON.stringify(
          {
            status: 'ok',
            database: row.databaseName,
            postgresql_major: Math.floor(Number(row.serverVersion) / 10_000),
            document_store: {
              reference_count: verified.evidence.referenceCount,
              unique_file_count: verified.evidence.uniqueFileCount,
              total_bytes: verified.evidence.totalBytes,
              manifest_hash: verified.evidence.manifestHash,
            },
          },
          null,
          2,
        )}\n`,
      );
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    }
  } finally {
    await client.end();
  }
}

async function clientConfig(): Promise<ClientConfig> {
  const caPath = optionalEnvironment('DIRECTOR_EVIDENCE_DATABASE_CA_PATH');
  return {
    connectionString: requiredSecret(process.env, 'DIRECTOR_EVIDENCE_DATABASE_URL'),
    application_name: 'dirizhor-document-store-evidence',
    ...(caPath === undefined
      ? {}
      : { ssl: { ca: await readFile(caPath, 'utf8'), rejectUnauthorized: true } }),
  };
}

function queryable(client: Client): SqlQueryable {
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

function optionalEnvironment(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value === undefined || value.length === 0 ? undefined : value;
}

function requiredEnvironment(name: string): string {
  const value = optionalEnvironment(name);
  if (value === undefined) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Evidence verification failed.';
  process.stderr.write(`Evidence verification failed: ${message}\n`);
  process.exitCode = 1;
});
