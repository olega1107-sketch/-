import { randomUUID } from 'node:crypto';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';

import { Client, type ClientConfig } from 'pg';

import {
  copyVerifiedDocumentStore,
  verifyDocumentStoreBackup,
  type DocumentStoreEvidence,
} from '../src/backup-integrity.js';
import { hashCanonical, sha256Bytes } from '../src/canonical.js';
import {
  assertDatabaseMigrationsCurrent,
  DatabaseMigrationRunner,
  loadMigrationPlan,
} from '../src/db-migrations.js';
import { FileDocumentStore } from '../src/file-document-store.js';
import type { SqlQueryable } from '../src/ports.js';
import { connectionStringForStrictTls } from '../src/postgres-tls.js';
import { requiredSecret } from '../src/secret-config.js';

interface DatabaseIdentity {
  databaseName: string;
  serverVersion: number;
}

interface DatabaseEvidence {
  tableCount: number;
  totalRows: number;
  manifestHash: string;
}

interface BackupCanary {
  userId: string;
  projectId: string;
  memoryObjectId: string;
  documentVersionId: string;
}

interface ProcessResult {
  stdout: string;
}

async function main(): Promise<void> {
  const confirmation = process.env.DIRECTOR_BACKUP_SMOKE_CONFIRM_DISPOSABLE;
  if (confirmation !== 'true') {
    throw new Error('DIRECTOR_BACKUP_SMOKE_CONFIRM_DISPOSABLE=true is required.');
  }

  const expectedSource = requiredEnvironment('DIRECTOR_BACKUP_SMOKE_EXPECT_SOURCE_DATABASE');
  const expectedTarget = requiredEnvironment('DIRECTOR_BACKUP_SMOKE_EXPECT_TARGET_DATABASE');
  if (expectedSource === expectedTarget) {
    throw new Error('Backup smoke source and target database names must differ.');
  }

  const workspace = await mkdtemp(path.join(tmpdir(), 'dirizhor-backup-smoke-'));
  await chmod(workspace, 0o700);
  const sourceDocuments = path.join(workspace, 'source-documents');
  const backupDocuments = path.join(workspace, 'backup-documents');
  const targetDocuments = path.join(workspace, 'target-documents');
  const dumpPath = path.join(workspace, 'database.dump');
  const restoreSqlPath = path.join(workspace, 'restore.sql');

  const sourceSettings = await databaseSettings(
    'DIRECTOR_BACKUP_SMOKE_SOURCE_DATABASE_URL',
    'DIRECTOR_BACKUP_SMOKE_SOURCE_DATABASE_CA_PATH',
    'dirizhor-backup-smoke-source',
  );
  const targetSettings = await databaseSettings(
    'DIRECTOR_BACKUP_SMOKE_TARGET_DATABASE_URL',
    'DIRECTOR_BACKUP_SMOKE_TARGET_DATABASE_CA_PATH',
    'dirizhor-backup-smoke-target',
  );
  const source = new Client(sourceSettings.client);
  const target = new Client(targetSettings.client);
  let sourceTouched = false;
  let targetTouched = false;

  try {
    await Promise.all([source.connect(), target.connect()]);
    const [sourceIdentity, targetIdentity] = await Promise.all([
      assertDisposableDatabase(source, expectedSource),
      assertDisposableDatabase(target, expectedTarget),
    ]);
    if (targetIdentity.serverVersion < sourceIdentity.serverVersion) {
      throw new Error('Backup smoke target PostgreSQL must not be older than the source.');
    }
    await assertPostgresTools(sourceIdentity.serverVersion);

    sourceTouched = true;
    const sourceQueryable = migrationQueryable(source);
    const migrationStatus = await new DatabaseMigrationRunner(
      sourceQueryable,
      await loadMigrationPlan(),
    ).migrate();
    if (migrationStatus.pending.length > 0) {
      throw new Error('Backup smoke source database has pending migrations.');
    }
    const canary = await seedCanary(source, sourceDocuments);

    await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    let sourceDatabaseEvidence;
    let sourceDocumentEvidence;
    try {
      const snapshot = await source.query<{ snapshotId: string }>(
        `SELECT pg_export_snapshot() AS "snapshotId"`,
      );
      const snapshotId = snapshot.rows[0]?.snapshotId;
      if (snapshotId === undefined || snapshotId.length === 0) {
        throw new Error('PostgreSQL did not export a backup snapshot.');
      }
      await assertDatabaseMigrationsCurrent(sourceQueryable);
      sourceDatabaseEvidence = await databaseEvidence(sourceQueryable, canary);
      const verifiedSource = await verifyDocumentStoreBackup(
        sourceQueryable,
        sourceDocuments,
      );
      sourceDocumentEvidence = verifiedSource.evidence;
      await runCommand(
        'pg_dump',
        [
          '--format=custom',
          '--no-owner',
          '--no-acl',
          `--snapshot=${snapshotId}`,
          `--file=${dumpPath}`,
        ],
        sourceSettings.environment,
      );
      await chmod(dumpPath, 0o600);
      await copyVerifiedDocumentStore(verifiedSource.files, backupDocuments);
      await source.query('COMMIT');
    } catch (error) {
      await source.query('ROLLBACK').catch(() => undefined);
      throw error;
    }

    await runCommand(
      'pg_restore',
      [
        '--no-owner',
        '--no-acl',
        '--single-transaction',
        `--file=${restoreSqlPath}`,
        dumpPath,
      ],
      process.env,
    );
    await chmod(restoreSqlPath, 0o600);
    targetTouched = true;
    await runCommand(
      'psql',
      ['-X', '--set=ON_ERROR_STOP=1', `--file=${restoreSqlPath}`],
      targetSettings.environment,
    );

    const verifiedBackup = await verifyDocumentStoreBackup(
      sourceQueryable,
      backupDocuments,
    );
    await copyVerifiedDocumentStore(verifiedBackup.files, targetDocuments);
    const targetQueryable = migrationQueryable(target);
    await assertDatabaseMigrationsCurrent(targetQueryable);
    const [targetDatabaseEvidence, verifiedTarget] = await Promise.all([
      databaseEvidence(targetQueryable, canary),
      verifyDocumentStoreBackup(targetQueryable, targetDocuments),
    ]);
    assertEqualEvidence('database', sourceDatabaseEvidence, targetDatabaseEvidence);
    assertEqualEvidence(
      'Document Store',
      sourceDocumentEvidence,
      verifiedTarget.evidence,
    );

    process.stdout.write(
      `${JSON.stringify(
        {
          status: 'ok',
          source_database: sourceIdentity.databaseName,
          target_database: targetIdentity.databaseName,
          source_postgresql_major: Math.floor(sourceIdentity.serverVersion / 10_000),
          target_postgresql_major: Math.floor(targetIdentity.serverVersion / 10_000),
          database: snakeCaseDatabaseEvidence(targetDatabaseEvidence),
          document_store: snakeCaseDocumentEvidence(verifiedTarget.evidence),
        },
        null,
        2,
      )}\n`,
    );
  } finally {
    await cleanupDatabase(target, targetTouched);
    await cleanupDatabase(source, sourceTouched);
    await Promise.allSettled([target.end(), source.end()]);
    await rm(workspace, { recursive: true, force: true });
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Backup restore smoke failed.';
  process.stderr.write(`Backup restore smoke failed: ${message}\n`);
  process.exitCode = 1;
});

async function seedCanary(
  client: Client,
  documentRoot: string,
): Promise<BackupCanary> {
  const userId = randomUUID();
  const projectId = randomUUID();
  const memoryObjectId = randomUUID();
  const documentVersionId = randomUUID();
  const content = Buffer.from('Dirizhor backup and restore canary.\n', 'utf8');
  const contentHash = sha256Bytes(content);
  const storageUri = `backup-smoke/${documentVersionId}.txt`;
  const store = new FileDocumentStore(documentRoot);
  await store.initialize();
  await store.stageImmutableDocument(storageUri, content, 'text/plain', contentHash);

  await client.query('BEGIN');
  try {
    await client.query(
      `
        INSERT INTO dirizhor.app_users (id, login, display_name, status)
        VALUES ($1::uuid, 'backup-smoke@example.invalid', 'Backup Smoke', 'active')
      `,
      [userId],
    );
    await client.query(
      `
        INSERT INTO dirizhor.projects (id, title, owner_user_id)
        VALUES ($1::uuid, 'Backup restore smoke', $2::uuid)
      `,
      [projectId, userId],
    );
    await client.query(
      `
        INSERT INTO dirizhor.memory_objects (
          id, type, title, project_id, author_user_id, sensitivity_level
        )
        VALUES ($1::uuid, 'document', 'Backup canary', $2::uuid, $3::uuid, 'internal')
      `,
      [memoryObjectId, projectId, userId],
    );
    await client.query(
      `
        INSERT INTO dirizhor.document_versions (
          id, memory_object_id, version_number, storage_uri, file_name,
          file_type, content_hash, size_bytes, created_by_user_id
        )
        VALUES (
          $1::uuid, $2::uuid, 1, $3, 'backup-canary.txt', 'text/plain',
          $4, $5, $6::uuid
        )
      `,
      [
        documentVersionId,
        memoryObjectId,
        storageUri,
        contentHash,
        content.byteLength,
        userId,
      ],
    );
    await client.query(
      `
        UPDATE dirizhor.memory_objects
        SET current_version_id = $2::uuid
        WHERE id = $1::uuid
      `,
      [memoryObjectId, documentVersionId],
    );
    await client.query('COMMIT');
    return { userId, projectId, memoryObjectId, documentVersionId };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
}

async function databaseEvidence(
  database: SqlQueryable,
  canary: BackupCanary,
): Promise<DatabaseEvidence> {
  const tables = await database.query<{ schemaName: string; tableName: string }>(
    `
      SELECT schemaname AS "schemaName", tablename AS "tableName"
      FROM pg_catalog.pg_tables
      WHERE schemaname IN ('dirizhor', 'dirizhor_migrations')
      ORDER BY schemaname, tablename
    `,
  );
  const counts = [];
  let totalRows = 0;
  for (const table of tables.rows) {
    if (!safeIdentifier(table.schemaName) || !safeIdentifier(table.tableName)) {
      throw new Error('Database catalog returned an unsafe identifier.');
    }
    const result = await database.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM "${table.schemaName}"."${table.tableName}"`,
    );
    const count = Number(result.rows[0]?.count);
    if (!Number.isSafeInteger(count) || count < 0) {
      throw new Error('Database row count is outside the supported range.');
    }
    totalRows += count;
    if (!Number.isSafeInteger(totalRows)) {
      throw new Error('Database total row count is outside the supported range.');
    }
    counts.push({ schema: table.schemaName, table: table.tableName, rows: count });
  }
  const canaryResult = await database.query<Record<string, unknown>>(
    `
      SELECT
        u.id::text AS user_id,
        u.login,
        u.display_name,
        u.status,
        p.id::text AS project_id,
        p.title AS project_title,
        p.owner_user_id::text AS owner_user_id,
        m.id::text AS memory_object_id,
        m.type AS memory_object_type,
        m.title AS memory_object_title,
        m.project_id::text AS memory_object_project_id,
        m.author_user_id::text AS author_user_id,
        m.sensitivity_level,
        m.current_version_id::text AS current_version_id,
        d.id::text AS document_version_id,
        d.memory_object_id::text AS document_memory_object_id,
        d.version_number,
        d.storage_uri,
        d.file_name,
        d.file_type,
        d.content_hash,
        d.size_bytes::text AS size_bytes,
        d.created_by_user_id::text AS created_by_user_id
      FROM dirizhor.app_users u
      JOIN dirizhor.projects p ON p.id = $2::uuid
      JOIN dirizhor.memory_objects m ON m.id = $3::uuid
      JOIN dirizhor.document_versions d ON d.id = $4::uuid
      WHERE u.id = $1::uuid
    `,
    [
      canary.userId,
      canary.projectId,
      canary.memoryObjectId,
      canary.documentVersionId,
    ],
  );
  if (canaryResult.rowCount !== 1 || canaryResult.rows[0] === undefined) {
    throw new Error('Backup restore canary is incomplete.');
  }
  return {
    tableCount: counts.length,
    totalRows,
    manifestHash: hashCanonical({
      version: 1,
      tables: counts,
      canary: canaryResult.rows[0],
    }),
  };
}

async function assertDisposableDatabase(
  client: Client,
  expectedDatabase: string,
): Promise<DatabaseIdentity> {
  const result = await client.query<{
    databaseName: string;
    serverVersion: string;
    applicationSchema: string | null;
    migrationSchema: string | null;
    userObjectCount: string;
  }>(
    `
      SELECT
        current_database() AS "databaseName",
        current_setting('server_version_num') AS "serverVersion",
        to_regnamespace('dirizhor')::text AS "applicationSchema",
        to_regnamespace('dirizhor_migrations')::text AS "migrationSchema",
        (
          SELECT count(*)::text
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname !~ '^pg_'
            AND n.nspname <> 'information_schema'
            AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
        ) AS "userObjectCount"
    `,
  );
  const row = result.rows[0];
  const serverVersion = Number(row?.serverVersion);
  if (
    row === undefined ||
    row.databaseName !== expectedDatabase ||
    !safeIdentifier(expectedDatabase) ||
    !Number.isSafeInteger(serverVersion) ||
    serverVersion < 150_000 ||
    row.applicationSchema !== null ||
    row.migrationSchema !== null ||
    Number(row.userObjectCount) !== 0
  ) {
    throw new Error('Backup smoke requires the exact empty disposable PostgreSQL 15+ database.');
  }
  return { databaseName: row.databaseName, serverVersion };
}

async function assertPostgresTools(serverVersion: number): Promise<void> {
  for (const command of ['pg_dump', 'pg_restore', 'psql']) {
    const result = await runCommand(command, ['--version'], process.env);
    const match = result.stdout.match(/(\d+)\.(\d+)/);
    const major = Number(match?.[1]);
    if (!Number.isSafeInteger(major) || major < Math.floor(serverVersion / 10_000)) {
      throw new Error(`${command} must be at least as new as the source PostgreSQL server.`);
    }
  }
}

async function runCommand(
  command: string,
  arguments_: string[],
  environment: NodeJS.ProcessEnv,
): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, {
      env: { ...environment, PGCONNECT_TIMEOUT: '10' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.resume();
    child.once('error', () => reject(new Error(`${command} could not be executed.`)));
    child.once('close', (code) => {
      if (code !== 0) {
        reject(new Error(`${command} failed with exit code ${code ?? 'unknown'}.`));
        return;
      }
      resolve({ stdout: Buffer.concat(stdout).toString('utf8') });
    });
  });
}

async function databaseSettings(
  secretName: string,
  caPathName: string,
  applicationName: string,
): Promise<{ client: ClientConfig; environment: NodeJS.ProcessEnv }> {
  const connectionString = requiredSecret(process.env, secretName);
  const caPath = process.env[caPathName]?.trim();
  const ssl =
    caPath === undefined || caPath.length === 0
      ? undefined
      : { ca: await readFile(caPath, 'utf8'), rejectUnauthorized: true };
  return {
    client: {
      connectionString: ssl === undefined
        ? connectionString
        : connectionStringForStrictTls(connectionString),
      application_name: applicationName,
      ...(ssl === undefined ? {} : { ssl }),
    },
    environment: {
      ...process.env,
      PGDATABASE: connectionString,
      ...(caPath === undefined || caPath.length === 0
        ? {}
        : { PGSSLMODE: 'verify-full', PGSSLROOTCERT: caPath }),
    },
  };
}

async function cleanupDatabase(client: Client, touched: boolean): Promise<void> {
  if (!touched) return;
  await client.query('DROP SCHEMA IF EXISTS dirizhor CASCADE').catch(() => undefined);
  await client
    .query('DROP SCHEMA IF EXISTS dirizhor_migrations CASCADE')
    .catch(() => undefined);
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

function assertEqualEvidence(
  label: string,
  source: DatabaseEvidence | DocumentStoreEvidence,
  target: DatabaseEvidence | DocumentStoreEvidence,
): void {
  if (JSON.stringify(source) !== JSON.stringify(target)) {
    throw new Error(`${label} restore evidence does not match the source snapshot.`);
  }
}

function snakeCaseDatabaseEvidence(evidence: DatabaseEvidence) {
  return {
    table_count: evidence.tableCount,
    total_rows: evidence.totalRows,
    manifest_hash: evidence.manifestHash,
  };
}

function snakeCaseDocumentEvidence(evidence: DocumentStoreEvidence) {
  return {
    reference_count: evidence.referenceCount,
    unique_file_count: evidence.uniqueFileCount,
    total_bytes: evidence.totalBytes,
    manifest_hash: evidence.manifestHash,
  };
}

function safeIdentifier(value: string): boolean {
  return /^[a-z_][a-z0-9_]*$/.test(value);
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
}
