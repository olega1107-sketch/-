import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { Client, Pool, type ClientConfig, type PoolClient, type PoolConfig } from 'pg';

import {
  DatabaseMigrationRunner,
  loadMigrationPlan,
  type MigrationQueryable,
} from '../src/db-migrations.js';
import { DirectorProtocolError } from '../src/errors.js';
import { PostgresDatabase } from '../src/postgres-database.js';
import { PostgresTaskRepository } from '../src/postgres-task-repository.js';
import type { SqlDatabase, SqlQueryable, SqlResult } from '../src/ports.js';
import { requiredSecret } from '../src/secret-config.js';

const userId = randomUUID();
const projectId = randomUUID();

async function main(): Promise<void> {
  const expectedDatabase = requiredEnvironment('DIRECTOR_CONTENTION_EXPECT_DATABASE');
  const connectionConfig = await testDatabaseConfig();
  const control = new Client({
    ...connectionConfig,
    application_name: 'dirizhor-contention-control',
  });
  let initialized = false;
  await control.connect();
  try {
    await assertDisposableDatabase(control, expectedDatabase);
    const migrationConnection = migrationQueryable(control);
    const migrationStatus = await new DatabaseMigrationRunner(
      migrationConnection,
      await loadMigrationPlan(),
    ).migrate();
    if (migrationStatus.pending.length > 0) {
      throw new Error('Contention database has pending migrations.');
    }
    initialized = true;
    await seedProject(control);
    await verifyRevocationWaitsForAuthorizedCommit(connectionConfig, control);
    await verifyCommittedRevocationDeniesNewWork(connectionConfig, control);
    process.stdout.write(
      'Real PostgreSQL contention passed: authorized commit and role revocation are lock-ordered.\n',
    );
  } finally {
    if (initialized) {
      await control.query('DROP SCHEMA IF EXISTS dirizhor CASCADE');
      await control.query('DROP SCHEMA IF EXISTS dirizhor_migrations CASCADE');
    }
    await control.end();
  }
}

async function verifyRevocationWaitsForAuthorizedCommit(
  config: ClientConfig,
  control: Client,
): Promise<void> {
  const database = new PermissionPauseDatabase({
    ...config,
    application_name: 'dirizhor-contention-business',
    max: 1,
  });
  const revoker = new Client({
    ...config,
    application_name: 'dirizhor-contention-revoker',
  });
  let taskCreation: Promise<unknown> | undefined;
  let revocation: Promise<void> | undefined;
  await revoker.connect();
  try {
    const repository = new PostgresTaskRepository(database);
    taskCreation = repository.createTask(taskCommand());
    await withTimeout(database.permissionLockAcquired, 5_000, 'permission lock acquisition');

    revocation = revokeOwnerAssignment(revoker);
    await waitForLockWait(control, 'dirizhor-contention-revoker');

    database.releasePermissionLock();
    await withTimeout(taskCreation, 5_000, 'authorized task commit');
    await withTimeout(revocation, 5_000, 'role revocation commit');

    const committed = await control.query<{ taskCount: string; auditCount: string }>(
      `
        SELECT
          (SELECT count(*)::text FROM dirizhor.tasks WHERE project_id = $1::uuid)
            AS "taskCount",
          (SELECT count(*)::text FROM dirizhor.audit_events
             WHERE project_id = $1::uuid AND action = 'task.created')
            AS "auditCount"
      `,
      [projectId],
    );
    if (
      committed.rows[0]?.taskCount !== '1' ||
      committed.rows[0]?.auditCount !== '1'
    ) {
      throw new Error('Authorized transaction did not commit task and audit atomically.');
    }
  } finally {
    database.releasePermissionLock();
    await Promise.allSettled(
      [taskCreation, revocation].filter(
        (operation): operation is Promise<unknown> => operation !== undefined,
      ),
    );
    await database.close();
    await revoker.end();
  }
}

async function verifyCommittedRevocationDeniesNewWork(
  config: ClientConfig,
  control: Client,
): Promise<void> {
  const assignmentId = randomUUID();
  await control.query(
    `
      INSERT INTO dirizhor.role_assignments (
        id, principal_type, principal_id, role_id, scope_type, scope_id,
        granted_by_user_id
      )
      SELECT
        $1::uuid, 'user', $2::uuid, role.id, 'project', $3::uuid, $2::uuid
      FROM dirizhor.roles AS role
      WHERE role.code = 'project_owner'
    `,
    [assignmentId, userId, projectId],
  );
  await control.query(
    `
      UPDATE dirizhor.role_assignments
      SET revoked_at = clock_timestamp()
      WHERE id = $1::uuid
    `,
    [assignmentId],
  );

  const database = new PostgresDatabase(
    new Pool({
      ...config,
      application_name: 'dirizhor-contention-post-revoke',
      max: 1,
    }),
  );
  const taskId = randomUUID();
  try {
    const repository = new PostgresTaskRepository(database);
    let denial: unknown;
    try {
      await repository.createTask(taskCommand(taskId));
    } catch (error) {
      denial = error;
    }
    if (
      !(denial instanceof DirectorProtocolError) ||
      denial.statusCode !== 404 ||
      denial.code !== 'not_found'
    ) {
      throw new Error('A revocation committed first did not conceal and deny new work.');
    }
    const result = await control.query<{ taskCount: string }>(
      `SELECT count(*)::text AS "taskCount" FROM dirizhor.tasks WHERE id = $1::uuid`,
      [taskId],
    );
    if (result.rows[0]?.taskCount !== '0') {
      throw new Error('Denied task transaction left a persisted task.');
    }
  } finally {
    await database.close();
  }
}

async function revokeOwnerAssignment(client: Client): Promise<void> {
  await client.query('BEGIN');
  try {
    await client.query(`SET LOCAL lock_timeout = '5s'`);
    const result = await client.query(
      `
        UPDATE dirizhor.role_assignments
        SET revoked_at = clock_timestamp()
        WHERE principal_type = 'user'
          AND principal_id = $1::uuid
          AND scope_type = 'project'
          AND scope_id = $2::uuid
          AND revoked_at IS NULL
      `,
      [userId, projectId],
    );
    if (result.rowCount !== 1) {
      throw new Error('Expected exactly one active project-owner assignment.');
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
}

async function waitForLockWait(control: Client, applicationName: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const result = await control.query<{ waitEventType: string | null; state: string }>(
      `
        SELECT wait_event_type AS "waitEventType", state
        FROM pg_stat_activity
        WHERE application_name = $1
          AND pid <> pg_backend_pid()
      `,
      [applicationName],
    );
    if (
      result.rows.some(
        (row) => row.state === 'active' && row.waitEventType === 'Lock',
      )
    ) {
      return;
    }
    await delay(25);
  }
  throw new Error('Concurrent role revocation was not observed waiting on a row lock.');
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
    throw new Error('Contention test database name does not match the explicit safety value.');
  }
  if (['postgres', 'template0', 'template1'].includes(row.databaseName)) {
    throw new Error('Contention test refuses a PostgreSQL administrative database.');
  }
  if (Number(row.serverVersion) < 150_000) {
    throw new Error('Contention test requires PostgreSQL 15 or newer.');
  }
  if (row.userObjectCount !== '0') {
    throw new Error('Contention test requires a dedicated database with no user objects.');
  }
}

async function seedProject(client: Client): Promise<void> {
  await client.query('BEGIN');
  try {
    await client.query(
      `
        INSERT INTO dirizhor.app_users (id, login, display_name, status)
        VALUES ($1::uuid, $2, 'Contention Owner', 'active')
      `,
      [userId, `contention-${userId}@example.test`],
    );
    await client.query(
      `
        INSERT INTO dirizhor.projects (id, title, owner_user_id)
        VALUES ($1::uuid, 'Contention Test', $2::uuid)
      `,
      [projectId, userId],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
}

function taskCommand(taskId = randomUUID()) {
  return {
    taskId,
    userId,
    requestId: randomUUID(),
    input: {
      project_id: projectId,
      title: 'Contention proof',
      user_request: 'Verify role revocation ordering.',
    },
  };
}

class PermissionPauseDatabase implements SqlDatabase {
  private readonly pool: Pool;
  private readonly observed = deferred<void>();
  private readonly released = deferred<void>();
  private pauseUsed = false;

  constructor(config: PoolConfig) {
    this.pool = new Pool(config);
  }

  get permissionLockAcquired(): Promise<void> {
    return this.observed.promise;
  }

  releasePermissionLock(): void {
    this.released.resolve();
  }

  async query<Row>(text: string, parameters?: readonly unknown[]): Promise<SqlResult<Row>> {
    const result = await this.pool.query(
      text,
      parameters === undefined ? undefined : [...parameters],
    );
    return { rows: result.rows as Row[], rowCount: result.rowCount ?? 0 };
  }

  async transaction<T>(operation: (transaction: SqlQueryable) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const transaction: SqlQueryable = {
        query: async <Row>(text: string, parameters?: readonly unknown[]) => {
          const result = await queryClient<Row>(client, text, parameters);
          if (!this.pauseUsed && text.includes('FOR SHARE OF assignment')) {
            this.pauseUsed = true;
            this.observed.resolve();
            await this.released.promise;
          }
          return result;
        },
      };
      const result = await operation(transaction);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

async function queryClient<Row>(
  client: PoolClient,
  text: string,
  parameters?: readonly unknown[],
): Promise<SqlResult<Row>> {
  const result = await client.query(
    text,
    parameters === undefined ? undefined : [...parameters],
  );
  return { rows: result.rows as Row[], rowCount: result.rowCount ?? 0 };
}

function migrationQueryable(client: Client): MigrationQueryable {
  return {
    query: async <Row>(text: string, parameters?: readonly unknown[]) => {
      const result = await client.query(
        text,
        parameters === undefined ? undefined : [...parameters],
      );
      return { rows: result.rows as Row[], rowCount: result.rowCount };
    },
  };
}

async function testDatabaseConfig(): Promise<ClientConfig> {
  const caPath = process.env.DIRECTOR_CONTENTION_DATABASE_CA_PATH;
  return {
    connectionString: requiredSecret(process.env, 'DIRECTOR_CONTENTION_DATABASE_URL'),
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

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

async function withTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out.`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown contention test error.';
  process.stderr.write(`PostgreSQL contention test failed: ${message}\n`);
  process.exitCode = 1;
});
