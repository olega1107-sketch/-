import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  assertDatabaseMigrationsCurrent,
  DatabaseMigrationRunner,
  loadMigrationPlan,
  pendingMigrations,
  type AppliedMigration,
  type LoadedMigration,
} from '../src/db-migrations.js';
import { createDirectorFixture, PGliteDatabase } from './helpers.js';

describe('database migrations', () => {
  it('loads the immutable baseline manifest and verifies its checksum', async () => {
    const plan = await loadMigrationPlan();

    expect(plan).toHaveLength(1);
    expect(plan[0]).toMatchObject({
      version: 1,
      id: '0001_schema_v1',
      phase: 'baseline',
      transaction: 'self',
    });
    expect(plan[0]?.adoptionVerifySql).toContain('schema v1 verification failed');
  });

  it('runs the baseline adoption verifier against the full PGlite schema', async () => {
    const fixture = await createDirectorFixture();
    try {
      const verifier = (await loadMigrationPlan())[0]?.adoptionVerifySql;
      if (verifier === undefined) throw new Error('Baseline verifier is missing.');
      const withoutUnavailableExtension = verifier.replace(
        /\n {4}IF NOT EXISTS \(SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'\) THEN[\s\S]*?\n {4}END IF;\n/,
        '\n',
      );
      expect(withoutUnavailableExtension).not.toBe(verifier);

      await expect(fixture.database.query(withoutUnavailableExtension)).resolves.toBeDefined();
    } finally {
      await fixture.close();
    }
  });

  it('rejects checksum drift, dirty state, and unknown database history', () => {
    const plan = [baseline()];
    const applied = [appliedMigration(plan[0]!)];

    expect(pendingMigrations(plan, applied, true)).toEqual([]);
    expect(() =>
      pendingMigrations(plan, [{ ...applied[0]!, checksum: checksum('changed') }]),
    ).toThrow(/differs from the release manifest/);
    expect(() =>
      pendingMigrations(plan, [{ ...applied[0]!, status: 'applying' }]),
    ).toThrow(/left in applying state/);
    expect(() => pendingMigrations(plan, [...applied, applied[0]!])).toThrow(
      /absent from this release/,
    );
  });

  it('applies a fresh baseline, records it, and satisfies the startup guard', async () => {
    const database = new PGliteDatabase();
    try {
      const plan = [baseline()];
      const runner = new DatabaseMigrationRunner(database, plan, {
        useAdvisoryLock: false,
      });

      const status = await runner.migrate();

      expect(status.pending).toEqual([]);
      expect(status.applied).toHaveLength(1);
      await expect(assertDatabaseMigrationsCurrent(database, plan)).resolves.toBeUndefined();
    } finally {
      await database.close();
    }
  });

  it('adopts only an existing verified baseline', async () => {
    const database = new PGliteDatabase();
    try {
      await database.query('CREATE SCHEMA dirizhor');
      const plan = [baseline()];
      const runner = new DatabaseMigrationRunner(database, plan, {
        useAdvisoryLock: false,
      });

      const status = await runner.adoptBaseline();

      expect(status.applied[0]?.migrationId).toBe('0001_schema_v1');
      await expect(runner.adoptBaseline()).rejects.toThrow(/empty migration registry/);
    } finally {
      await database.close();
    }
  });

  it('stops before contract until destructive compatibility removal is explicit', async () => {
    const database = new PGliteDatabase();
    try {
      const plan = [
        baseline(),
        migration(2, '0002_expand_example', 'expand', 'CREATE TABLE dirizhor.next_value(id int)'),
        migration(3, '0003_validate_example', 'validate', 'SELECT 1'),
        migration(4, '0004_contract_example', 'contract', 'DROP TABLE dirizhor.next_value'),
      ];
      const runner = new DatabaseMigrationRunner(database, plan, {
        useAdvisoryLock: false,
      });

      const compatible = await runner.migrate();
      expect(compatible.applied.map((item) => item.version)).toEqual([1, 2, 3]);
      expect(compatible.pending.map((item) => item.phase)).toEqual(['contract']);

      const contracted = await runner.migrate({ allowContract: true });
      expect(contracted.pending).toEqual([]);
    } finally {
      await database.close();
    }
  });

  it('rejects a change whose first phase is not expand', async () => {
    const database = new PGliteDatabase();
    try {
      expect(
        () =>
          new DatabaseMigrationRunner(
            database,
            [baseline(), migration(2, '0002_validate_bad', 'validate', 'SELECT 1')],
            { useAdvisoryLock: false },
          ),
      ).toThrow(/must start with an expand migration/);
    } finally {
      await database.close();
    }
  });
});

function baseline(): LoadedMigration {
  return {
    version: 1,
    id: '0001_schema_v1',
    name: 'Initial schema',
    change: 'schema_v1',
    phase: 'baseline',
    transaction: 'self',
    checksum: checksum('baseline'),
    sql: 'CREATE SCHEMA dirizhor',
    adoptionVerifySql: `
      DO $$
      BEGIN
        IF to_regnamespace('dirizhor') IS NULL THEN
          RAISE EXCEPTION 'missing schema';
        END IF;
      END;
      $$
    `,
  };
}

function migration(
  version: number,
  id: string,
  phase: 'expand' | 'validate' | 'contract',
  sql: string,
): LoadedMigration {
  return {
    version,
    id,
    name: id,
    change: 'example',
    phase,
    transaction: 'migration',
    checksum: checksum(id),
    sql,
  };
}

function appliedMigration(migration: LoadedMigration): AppliedMigration {
  return {
    version: migration.version,
    migrationId: migration.id,
    name: migration.name,
    change: migration.change,
    phase: migration.phase,
    transactionMode: migration.transaction,
    checksum: migration.checksum,
    status: 'applied',
  };
}

function checksum(seed: string): string {
  return `sha256:${createHash('sha256').update(seed).digest('hex')}`;
}
