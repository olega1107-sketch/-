import { describe, expect, it } from 'vitest';

import { inspectRuntimePrivileges } from '../src/postgres-runtime-privilege-probe.js';
import type { SqlQueryable } from '../src/ports.js';

const safeRow = {
  databaseName: 'dirizhor_pilot',
  roleName: 'dirizhor_runtime',
  serverVersionNum: '150012',
  sessionMatchesCurrent: true,
  superuser: false,
  createRole: false,
  createDatabase: false,
  replication: false,
  bypassRls: false,
  privilegedMembershipCount: '0',
  databaseOwnerMembership: false,
  databaseCreate: false,
  publicSchemaCreate: false,
  targetSchemaCount: '2',
  targetRelationCount: '42',
  targetSchemaUsageMissingCount: '0',
  targetSchemaCreateCount: '0',
  unapprovedSchemaCreateCount: '0',
  targetSchemaOwnerMembershipCount: '0',
  targetRelationOwnerMembershipCount: '0',
  targetRoutineOwnerMembershipCount: '0',
  securityDefinerExecuteCount: '0',
  extensionOwnerMembershipCount: '0',
  dangerousTablePrivilegeCount: '0',
  migrationSelect: true,
  migrationWrite: false,
};

describe('PostgreSQL runtime privilege probe', () => {
  it('passes a least-privilege runtime role without exposing target names', async () => {
    const report = await inspectRuntimePrivileges({
      database: fixtureDatabase(safeRow),
      expectedDatabase: 'dirizhor_pilot',
      expectedRole: 'dirizhor_runtime',
      clock: () => new Date('2026-08-12T12:00:00.000Z'),
    });

    expect(report.status).toBe('PASS');
    expect(report.checks).toHaveLength(15);
    expect(report.checks.every((check) => check.status === 'PASS')).toBe(true);
    expect(report.target.database_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(report)).not.toContain('dirizhor_runtime');
    expect(JSON.stringify(report)).not.toContain('dirizhor_pilot');
    expect(report.report_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('fails closed for privileged membership, ownership, DDL, dangerous table rights, and migration writes', async () => {
    const report = await inspectRuntimePrivileges({
      database: fixtureDatabase({
        ...safeRow,
        privilegedMembershipCount: '1',
        databaseOwnerMembership: true,
        targetSchemaCreateCount: '1',
        unapprovedSchemaCreateCount: '1',
        targetRelationOwnerMembershipCount: '2',
        targetRoutineOwnerMembershipCount: '1',
        extensionOwnerMembershipCount: '1',
        securityDefinerExecuteCount: '1',
        dangerousTablePrivilegeCount: '3',
        migrationWrite: true,
      }),
      expectedDatabase: 'dirizhor_pilot',
      expectedRole: 'dirizhor_runtime',
    });

    expect(report.status).toBe('FAIL');
    expect(report.checks.filter((check) => check.status === 'FAIL').map((check) => check.id)).toEqual([
      'role.no_privileged_memberships',
      'database.not_owned_or_creatable',
      'schema.target_not_owned_or_creatable',
      'schema.no_unapproved_create',
      'objects.target_relations_not_owned',
      'objects.target_routines_not_owned',
      'objects.extensions_not_owned',
      'routines.no_security_definer_execute',
      'tables.no_truncate_reference_or_trigger',
      'migration_history.select_only',
    ]);
  });

  it('rejects a wrong database or assumed role and missing target objects', async () => {
    const report = await inspectRuntimePrivileges({
      database: fixtureDatabase({
        ...safeRow,
        sessionMatchesCurrent: false,
        targetSchemaCount: '1',
        targetRelationCount: '0',
      }),
      expectedDatabase: 'other_database',
      expectedRole: 'other_role',
    });

    expect(report.status).toBe('FAIL');
    expect(report.checks.find((check) => check.id === 'identity.exact_runtime_login')?.status).toBe('FAIL');
    expect(report.checks.find((check) => check.id === 'catalog.target_objects_present')?.status).toBe('FAIL');
  });
});

function fixtureDatabase(row: Record<string, unknown>): SqlQueryable {
  return {
    query: async <Row>(text: string) => {
      expect(text).toContain("to_regclass('dirizhor_migrations.schema_migrations')");
      expect(text).toContain("has_table_privilege(current_user, relation.oid, 'TRUNCATE')");
      return { rows: [row as Row], rowCount: 1 };
    },
  };
}
