import { describe, expect, it } from 'vitest';

import { runDatabaseMigrationCli } from '../src/db-migrate-cli.js';

describe('runtime database migration CLI', () => {
  it('rejects unknown commands before opening a database connection', async () => {
    await expect(
      runDatabaseMigrationCli(['node', 'db-migrate-cli.js', 'unknown'], {}),
    ).rejects.toThrow(/Usage: db-migrate-cli\.js/);
  });

  it('requires explicit baseline adoption confirmation before database access', async () => {
    await expect(
      runDatabaseMigrationCli(['node', 'db-migrate-cli.js', 'adopt-v1'], {}),
    ).rejects.toThrow(/requires --confirm-existing-schema-v1/);
  });

  it('requires the dedicated migration credential through secret config', async () => {
    await expect(
      runDatabaseMigrationCli(['node', 'db-migrate-cli.js', 'status'], {}),
    ).rejects.toThrow(/DIRECTOR_MIGRATION_DATABASE_URL or DIRECTOR_MIGRATION_DATABASE_URL_FILE is required/);
  });
});
