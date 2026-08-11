import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { SqlQueryable } from './ports.js';

export type MigrationPhase = 'baseline' | 'expand' | 'backfill' | 'validate' | 'contract';
export type MigrationTransaction = 'migration' | 'self' | 'none';

export interface LoadedMigration {
  version: number;
  id: string;
  name: string;
  change: string;
  phase: MigrationPhase;
  transaction: MigrationTransaction;
  checksum: string;
  sql: string;
  adoptionVerifySql?: string;
}

export interface AppliedMigration {
  version: number;
  migrationId: string;
  name: string;
  change: string;
  phase: MigrationPhase;
  transactionMode: MigrationTransaction;
  checksum: string;
  status: 'applying' | 'applied';
}

export interface MigrationStatus {
  applied: AppliedMigration[];
  pending: LoadedMigration[];
}

export interface MigrationQueryable {
  query<Row>(
    text: string,
    parameters?: readonly unknown[],
  ): Promise<{ rows: Row[]; rowCount?: number | null }>;
}

interface ManifestMigration {
  version: number;
  id: string;
  name: string;
  change: string;
  phase: MigrationPhase;
  file: string;
  adoption_verify_file?: string;
  transaction: MigrationTransaction;
  checksum: string;
}

interface MigrationRunnerOptions {
  useAdvisoryLock?: boolean;
  advisoryLockTimeoutMs?: number;
  lockTimeoutMs?: number;
  statementTimeoutMs?: number;
}

interface MigrateOptions {
  allowContract?: boolean;
}

const defaultManifestUrl = new URL('../../../db/migrations/manifest.json', import.meta.url);
const migrationLockKeys = [1_144_632_906, 1_298_758_578] as const;
const checksumPattern = /^sha256:[0-9a-f]{64}$/;
const idPattern = /^\d{4}_[a-z][a-z0-9_]*$/;
const changePattern = /^[a-z][a-z0-9_]*$/;
const phaseOrder: Record<Exclude<MigrationPhase, 'baseline'>, number> = {
  expand: 0,
  backfill: 1,
  validate: 2,
  contract: 3,
};

export async function loadMigrationPlan(
  manifestUrl: URL = defaultManifestUrl,
): Promise<LoadedMigration[]> {
  const manifestPath = fileURLToPath(manifestUrl);
  const databaseRoot = resolve(dirname(manifestPath), '..');
  const raw = JSON.parse(await readFile(manifestUrl, 'utf8')) as unknown;
  const manifest = parseManifest(raw);
  const loaded: LoadedMigration[] = [];
  for (const migration of manifest) {
    const sqlUrl = safeMigrationUrl(manifestUrl, migration.file, databaseRoot);
    const sql = await readFile(sqlUrl, 'utf8');
    const actualChecksum = migrationChecksum(migration, sql);
    if (actualChecksum !== migration.checksum) {
      throw new Error(
        `Migration ${migration.id} checksum mismatch: expected ${migration.checksum}, got ${actualChecksum}.`,
      );
    }
    const adoptionVerifySql =
      migration.adoption_verify_file === undefined
        ? undefined
        : await readFile(
            safeMigrationUrl(manifestUrl, migration.adoption_verify_file, databaseRoot),
            'utf8',
          );
    loaded.push({
      version: migration.version,
      id: migration.id,
      name: migration.name,
      change: migration.change,
      phase: migration.phase,
      transaction: migration.transaction,
      checksum: migration.checksum,
      sql,
      ...(adoptionVerifySql === undefined ? {} : { adoptionVerifySql }),
    });
  }
  validatePlan(loaded);
  return loaded;
}

export function pendingMigrations(
  plan: readonly LoadedMigration[],
  applied: readonly AppliedMigration[],
  requireCurrent = false,
): LoadedMigration[] {
  if (applied.length > plan.length) {
    throw new Error('Database contains migrations that are absent from this release.');
  }
  for (const [index, record] of applied.entries()) {
    const migration = plan[index];
    if (migration === undefined || record.version !== migration.version) {
      throw new Error(`Database migration history diverges at position ${index + 1}.`);
    }
    if (record.status !== 'applied') {
      throw new Error(`Migration ${record.migrationId} is left in applying state.`);
    }
    if (
      record.migrationId !== migration.id ||
      record.name !== migration.name ||
      record.change !== migration.change ||
      record.phase !== migration.phase ||
      record.transactionMode !== migration.transaction ||
      record.checksum !== migration.checksum
    ) {
      throw new Error(`Applied migration ${migration.id} differs from the release manifest.`);
    }
  }
  const pending = plan.slice(applied.length);
  if (requireCurrent && pending.length > 0) {
    throw new Error(`Database has ${pending.length} pending migration(s).`);
  }
  return pending;
}

export async function assertDatabaseMigrationsCurrent(
  database: SqlQueryable,
  plan?: readonly LoadedMigration[],
): Promise<void> {
  const expectedPlan = plan ?? (await loadMigrationPlan());
  const metadata = await database.query<{ registry: string | null }>(
    `SELECT to_regclass('dirizhor_migrations.schema_migrations')::text AS registry`,
  );
  if (metadata.rows[0]?.registry === null || metadata.rows[0] === undefined) {
    throw new Error('Database migration registry is missing. Run db:migrate or db:adopt-v1.');
  }
  const applied = await readAppliedMigrations(database);
  pendingMigrations(expectedPlan, applied, true);
}

export class DatabaseMigrationRunner {
  private readonly useAdvisoryLock: boolean;
  private readonly advisoryLockTimeoutMs: number;
  private readonly lockTimeoutMs: number;
  private readonly statementTimeoutMs: number;

  constructor(
    private readonly connection: MigrationQueryable,
    private readonly plan: readonly LoadedMigration[],
    options: MigrationRunnerOptions = {},
  ) {
    validatePlan(plan);
    this.useAdvisoryLock = options.useAdvisoryLock ?? true;
    this.advisoryLockTimeoutMs = positiveDuration(
      options.advisoryLockTimeoutMs ?? 30_000,
      'advisory lock timeout',
    );
    this.lockTimeoutMs = positiveDuration(options.lockTimeoutMs ?? 5_000, 'lock timeout');
    this.statementTimeoutMs = positiveDuration(
      options.statementTimeoutMs ?? 300_000,
      'statement timeout',
    );
  }

  async inspect(): Promise<MigrationStatus> {
    const metadata = await this.connection.query<{ registry: string | null }>(
      `SELECT to_regclass('dirizhor_migrations.schema_migrations')::text AS registry`,
    );
    const applied =
      metadata.rows[0]?.registry === null || metadata.rows[0] === undefined
        ? []
        : await readAppliedMigrations(this.connection);
    return { applied, pending: pendingMigrations(this.plan, applied) };
  }

  async migrate(options: MigrateOptions = {}): Promise<MigrationStatus> {
    return this.withAdvisoryLock(async () => {
      await this.bootstrapRegistry();
      const applied = await readAppliedMigrations(this.connection);
      const pending = pendingMigrations(this.plan, applied);
      for (const migration of pending) {
        if (migration.phase === 'contract' && options.allowContract !== true) {
          break;
        }
        await this.applyMigration(migration);
      }
      const current = await readAppliedMigrations(this.connection);
      return { applied: current, pending: pendingMigrations(this.plan, current) };
    });
  }

  async adoptBaseline(): Promise<MigrationStatus> {
    return this.withAdvisoryLock(async () => {
      await this.bootstrapRegistry();
      const applied = await readAppliedMigrations(this.connection);
      if (applied.length > 0) {
        throw new Error('Baseline adoption requires an empty migration registry.');
      }
      const baseline = this.plan[0];
      if (baseline === undefined || baseline.phase !== 'baseline') {
        throw new Error('The migration plan does not start with a baseline.');
      }
      if (baseline.adoptionVerifySql === undefined) {
        throw new Error(`Migration ${baseline.id} does not provide an adoption verifier.`);
      }
      const namespace = await this.connection.query<{ schemaName: string | null }>(
        `SELECT to_regnamespace('dirizhor')::text AS "schemaName"`,
      );
      if (namespace.rows[0]?.schemaName === null || namespace.rows[0] === undefined) {
        throw new Error('Baseline adoption requires an existing dirizhor schema.');
      }
      await this.withSessionTimeouts(() => this.connection.query(baseline.adoptionVerifySql!));
      await this.recordSelfManagedMigration(baseline, 0);
      const current = await readAppliedMigrations(this.connection);
      return { applied: current, pending: pendingMigrations(this.plan, current) };
    });
  }

  private async applyMigration(migration: LoadedMigration): Promise<void> {
    const startedAt = Date.now();
    if (migration.phase === 'baseline') {
      const namespace = await this.connection.query<{ schemaName: string | null }>(
        `SELECT to_regnamespace('dirizhor')::text AS "schemaName"`,
      );
      if (namespace.rows[0]?.schemaName !== null && namespace.rows[0] !== undefined) {
        throw new Error(
          'Existing dirizhor schema is not tracked. Verify it, back it up, then run db:adopt-v1.',
        );
      }
    }
    switch (migration.transaction) {
      case 'migration':
        await this.applyTransactionalMigration(migration, startedAt);
        return;
      case 'self':
        await this.withSessionTimeouts(() => this.connection.query(migration.sql));
        if (migration.adoptionVerifySql !== undefined) {
          await this.withSessionTimeouts(() =>
            this.connection.query(migration.adoptionVerifySql!),
          );
        }
        await this.recordSelfManagedMigration(migration, Date.now() - startedAt);
        return;
      case 'none':
        await this.applyNonTransactionalMigration(migration, startedAt);
        return;
    }
  }

  private async applyTransactionalMigration(
    migration: LoadedMigration,
    startedAt: number,
  ): Promise<void> {
    await this.connection.query('BEGIN');
    try {
      await this.setTimeouts(true);
      await this.insertApplying(migration);
      await this.connection.query(migration.sql);
      await this.markApplied(migration.version, Date.now() - startedAt);
      await this.connection.query('COMMIT');
    } catch (error) {
      await rollbackQuietly(this.connection);
      throw error;
    }
  }

  private async applyNonTransactionalMigration(
    migration: LoadedMigration,
    startedAt: number,
  ): Promise<void> {
    await this.connection.query('BEGIN');
    try {
      await this.insertApplying(migration);
      await this.connection.query('COMMIT');
    } catch (error) {
      await rollbackQuietly(this.connection);
      throw error;
    }
    await this.withSessionTimeouts(() => this.connection.query(migration.sql));
    await this.connection.query('BEGIN');
    try {
      await this.markApplied(migration.version, Date.now() - startedAt);
      await this.connection.query('COMMIT');
    } catch (error) {
      await rollbackQuietly(this.connection);
      throw error;
    }
  }

  private async recordSelfManagedMigration(
    migration: LoadedMigration,
    executionMs: number,
  ): Promise<void> {
    await this.connection.query('BEGIN');
    try {
      await this.insertApplying(migration);
      await this.markApplied(migration.version, executionMs);
      await this.connection.query('COMMIT');
    } catch (error) {
      await rollbackQuietly(this.connection);
      throw error;
    }
  }

  private async insertApplying(migration: LoadedMigration): Promise<void> {
    await this.connection.query(
      `
        INSERT INTO dirizhor_migrations.schema_migrations (
          version, migration_id, name, change_name, phase, transaction_mode,
          checksum, status
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'applying')
      `,
      [
        migration.version,
        migration.id,
        migration.name,
        migration.change,
        migration.phase,
        migration.transaction,
        migration.checksum,
      ],
    );
  }

  private async markApplied(version: number, executionMs: number): Promise<void> {
    const result = await this.connection.query(
      `
        UPDATE dirizhor_migrations.schema_migrations
        SET status = 'applied',
            applied_at = clock_timestamp(),
            execution_ms = $2
        WHERE version = $1
          AND status = 'applying'
      `,
      [version, executionMs],
    );
    if (result.rowCount !== undefined && result.rowCount !== 1) {
      throw new Error(`Migration version ${version} did not transition to applied exactly once.`);
    }
  }

  private async bootstrapRegistry(): Promise<void> {
    await this.connection.query(`CREATE SCHEMA IF NOT EXISTS dirizhor_migrations`);
    await this.connection.query(`
      CREATE TABLE IF NOT EXISTS dirizhor_migrations.schema_migrations (
        version integer PRIMARY KEY CHECK (version > 0),
        migration_id text NOT NULL UNIQUE,
        name text NOT NULL,
        change_name text NOT NULL,
        phase text NOT NULL CHECK (
          phase IN ('baseline', 'expand', 'backfill', 'validate', 'contract')
        ),
        transaction_mode text NOT NULL CHECK (
          transaction_mode IN ('migration', 'self', 'none')
        ),
        checksum text NOT NULL CHECK (checksum ~ '^sha256:[0-9a-f]{64}$'),
        status text NOT NULL CHECK (status IN ('applying', 'applied')),
        applied_at timestamptz,
        execution_ms bigint,
        applied_by name NOT NULL DEFAULT CURRENT_USER,
        CONSTRAINT schema_migrations_applied_shape CHECK (
          (status = 'applying' AND applied_at IS NULL AND execution_ms IS NULL)
          OR
          (status = 'applied' AND applied_at IS NOT NULL AND execution_ms >= 0)
        )
      )
    `);
  }

  private async withAdvisoryLock<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.useAdvisoryLock) {
      return operation();
    }
    let locked = false;
    await this.connection.query(
      `SELECT set_config('lock_timeout', $1, false), set_config('statement_timeout', $1, false)`,
      [`${this.advisoryLockTimeoutMs}ms`],
    );
    try {
      await this.connection.query(`SELECT pg_advisory_lock($1::integer, $2::integer)`, [
        ...migrationLockKeys,
      ]);
      locked = true;
      await this.resetTimeouts();
      return await operation();
    } finally {
      if (locked) {
        await this.connection.query(`SELECT pg_advisory_unlock($1::integer, $2::integer)`, [
          ...migrationLockKeys,
        ]);
      }
      await this.resetTimeouts();
    }
  }

  private async withSessionTimeouts<T>(operation: () => Promise<T>): Promise<T> {
    await this.setTimeouts(false);
    try {
      return await operation();
    } finally {
      await this.resetTimeouts();
    }
  }

  private async setTimeouts(local: boolean): Promise<void> {
    await this.connection.query(
      `SELECT set_config('lock_timeout', $1, $3), set_config('statement_timeout', $2, $3)`,
      [`${this.lockTimeoutMs}ms`, `${this.statementTimeoutMs}ms`, local],
    );
  }

  private async resetTimeouts(): Promise<void> {
    await this.connection.query(`RESET lock_timeout`);
    await this.connection.query(`RESET statement_timeout`);
  }
}

function parseManifest(value: unknown): ManifestMigration[] {
  if (!isRecord(value) || value.format_version !== 1 || !Array.isArray(value.migrations)) {
    throw new Error('Migration manifest must use format_version 1 and contain migrations.');
  }
  return value.migrations.map((entry, index) => parseManifestMigration(entry, index));
}

function parseManifestMigration(value: unknown, index: number): ManifestMigration {
  if (!isRecord(value)) {
    throw new Error(`Migration manifest entry ${index + 1} must be an object.`);
  }
  const phase = value.phase;
  const transaction = value.transaction;
  const migration: ManifestMigration = {
    version: requiredPositiveInteger(value.version, `migration ${index + 1} version`),
    id: requiredPattern(value.id, idPattern, `migration ${index + 1} id`),
    name: requiredText(value.name, `migration ${index + 1} name`),
    change: requiredPattern(value.change, changePattern, `migration ${index + 1} change`),
    phase: isMigrationPhase(phase)
      ? phase
      : invalid(`migration ${index + 1} phase is invalid`),
    file: requiredText(value.file, `migration ${index + 1} file`),
    transaction: isMigrationTransaction(transaction)
      ? transaction
      : invalid(`migration ${index + 1} transaction is invalid`),
    checksum: requiredPattern(
      value.checksum,
      checksumPattern,
      `migration ${index + 1} checksum`,
    ),
  };
  if (value.adoption_verify_file !== undefined) {
    migration.adoption_verify_file = requiredText(
      value.adoption_verify_file,
      `migration ${index + 1} adoption verifier`,
    );
  }
  return migration;
}

function validatePlan(plan: readonly LoadedMigration[]): void {
  if (plan.length === 0 || plan[0]?.phase !== 'baseline') {
    throw new Error('Migration plan must start with exactly one baseline migration.');
  }
  const seenIds = new Set<string>();
  const changePhases = new Map<string, number>();
  for (const [index, migration] of plan.entries()) {
    if (migration.version !== index + 1) {
      throw new Error('Migration versions must be contiguous and start at 1.');
    }
    if (seenIds.has(migration.id)) {
      throw new Error(`Migration id ${migration.id} is duplicated.`);
    }
    if (!migration.id.startsWith(`${String(migration.version).padStart(4, '0')}_`)) {
      throw new Error(`Migration id ${migration.id} does not match its version.`);
    }
    seenIds.add(migration.id);
    if (index > 0 && migration.phase === 'baseline') {
      throw new Error('Only the first migration may use the baseline phase.');
    }
    if (migration.phase === 'baseline') {
      if (migration.transaction !== 'self') {
        throw new Error('The baseline migration must manage its own transaction.');
      }
      continue;
    }
    if (migration.transaction === 'self') {
      throw new Error('Only the baseline may manage its own transaction.');
    }
    const rank = phaseOrder[migration.phase];
    const previous = changePhases.get(migration.change);
    if (previous === undefined && migration.phase !== 'expand') {
      throw new Error(`Change ${migration.change} must start with an expand migration.`);
    }
    if (previous !== undefined && rank < previous) {
      throw new Error(`Change ${migration.change} has phases in an unsafe order.`);
    }
    if (migration.phase === 'contract' && previous !== phaseOrder.validate) {
      throw new Error(`Change ${migration.change} must validate before contract.`);
    }
    changePhases.set(migration.change, rank);
  }
}

function migrationChecksum(migration: ManifestMigration, sql: string): string {
  const digest = createHash('sha256')
    .update(migration.id)
    .update('\0')
    .update(migration.name)
    .update('\0')
    .update(migration.change)
    .update('\0')
    .update(migration.phase)
    .update('\0')
    .update(migration.transaction)
    .update('\0')
    .update(sql)
    .digest('hex');
  return `sha256:${digest}`;
}

function safeMigrationUrl(manifestUrl: URL, file: string, databaseRoot: string): URL {
  const url = new URL(file, manifestUrl);
  if (url.protocol !== 'file:') {
    throw new Error('Migration files must use local file paths.');
  }
  const path = resolve(fileURLToPath(url));
  if (path !== databaseRoot && !path.startsWith(`${databaseRoot}${sep}`)) {
    throw new Error('Migration file resolves outside the database directory.');
  }
  return url;
}

async function readAppliedMigrations(
  database: MigrationQueryable,
): Promise<AppliedMigration[]> {
  const result = await database.query<AppliedMigration>(`
    SELECT
      version,
      migration_id AS "migrationId",
      name,
      change_name AS change,
      phase,
      transaction_mode AS "transactionMode",
      checksum,
      status
    FROM dirizhor_migrations.schema_migrations
    ORDER BY version
  `);
  return result.rows;
}

async function rollbackQuietly(connection: MigrationQueryable): Promise<void> {
  try {
    await connection.query('ROLLBACK');
  } catch {
    // Preserve the migration error that triggered rollback.
  }
}

function positiveDuration(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive safe integer.`);
  }
  return value;
}

function requiredPositiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value as number;
}

function requiredText(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${label} must be non-empty text.`);
  }
  return value;
}

function requiredPattern(value: unknown, pattern: RegExp, label: string): string {
  const text = requiredText(value, label);
  if (!pattern.test(text)) {
    throw new Error(`${label} has an invalid format.`);
  }
  return text;
}

function isMigrationPhase(value: unknown): value is MigrationPhase {
  return ['baseline', 'expand', 'backfill', 'validate', 'contract'].includes(String(value));
}

function isMigrationTransaction(value: unknown): value is MigrationTransaction {
  return ['migration', 'self', 'none'].includes(String(value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function invalid(message: string): never {
  throw new Error(message);
}
