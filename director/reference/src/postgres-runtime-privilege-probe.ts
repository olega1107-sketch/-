import { createHash } from 'node:crypto';

import type { SqlQueryable } from './ports.js';

export interface RuntimePrivilegeProbeOptions {
  database: SqlQueryable;
  expectedDatabase: string;
  expectedRole: string;
  clock?: () => Date;
}

export interface RuntimePrivilegeCheck {
  id: string;
  status: 'PASS' | 'FAIL';
}

export interface RuntimePrivilegeReport {
  schema_version: 1;
  status: 'PASS' | 'FAIL';
  check: 'postgres.runtime_privileges';
  observed_at: string;
  target: {
    database_sha256: string;
    role_sha256: string;
    server_version_num: number;
  };
  checks: RuntimePrivilegeCheck[];
  report_sha256: string;
}

interface RuntimePrivilegeCatalogRow {
  databaseName: string;
  roleName: string;
  serverVersionNum: string;
  sessionMatchesCurrent: boolean;
  superuser: boolean;
  createRole: boolean;
  createDatabase: boolean;
  replication: boolean;
  bypassRls: boolean;
  privilegedMembershipCount: string;
  databaseOwnerMembership: boolean;
  databaseCreate: boolean;
  publicSchemaCreate: boolean;
  targetSchemaCount: string;
  targetRelationCount: string;
  targetSchemaUsageMissingCount: string;
  targetSchemaCreateCount: string;
  unapprovedSchemaCreateCount: string;
  targetSchemaOwnerMembershipCount: string;
  targetRelationOwnerMembershipCount: string;
  targetRoutineOwnerMembershipCount: string;
  securityDefinerExecuteCount: string;
  extensionOwnerMembershipCount: string;
  dangerousTablePrivilegeCount: string;
  migrationSelect: boolean;
  migrationWrite: boolean;
}

export async function inspectRuntimePrivileges(
  options: RuntimePrivilegeProbeOptions,
): Promise<RuntimePrivilegeReport> {
  const expectedDatabase = requiredIdentity(options.expectedDatabase, 'expected database');
  const expectedRole = requiredIdentity(options.expectedRole, 'expected role');
  const result = await options.database.query<RuntimePrivilegeCatalogRow>(catalogQuery);
  const row = result.rows[0];
  if (result.rowCount !== 1 || row === undefined) {
    throw new Error('PostgreSQL runtime privilege catalog query returned an invalid result.');
  }
  const serverVersionNum = integer(row.serverVersionNum, 'server version');
  if (serverVersionNum < 150_000) {
    throw new Error('PostgreSQL runtime privilege probe requires PostgreSQL 15 or newer.');
  }

  const checks: RuntimePrivilegeCheck[] = [
    check('identity.exact_runtime_login', row.databaseName === expectedDatabase && row.roleName === expectedRole && row.sessionMatchesCurrent),
    check('role.no_privileged_attributes', !row.superuser && !row.createRole && !row.createDatabase && !row.replication && !row.bypassRls),
    check('role.no_privileged_memberships', count(row.privilegedMembershipCount) === 0),
    check('database.not_owned_or_creatable', !row.databaseOwnerMembership && !row.databaseCreate),
    check('schema.public_not_creatable', !row.publicSchemaCreate),
    check('catalog.target_objects_present', count(row.targetSchemaCount) === 2 && count(row.targetRelationCount) > 0),
    check('schema.target_usage_present', count(row.targetSchemaUsageMissingCount) === 0),
    check('schema.target_not_owned_or_creatable', count(row.targetSchemaCreateCount) === 0 && count(row.targetSchemaOwnerMembershipCount) === 0),
    check('schema.no_unapproved_create', count(row.unapprovedSchemaCreateCount) === 0),
    check('objects.target_relations_not_owned', count(row.targetRelationOwnerMembershipCount) === 0),
    check('objects.target_routines_not_owned', count(row.targetRoutineOwnerMembershipCount) === 0),
    check('objects.extensions_not_owned', count(row.extensionOwnerMembershipCount) === 0),
    check('routines.no_security_definer_execute', count(row.securityDefinerExecuteCount) === 0),
    check('tables.no_truncate_reference_or_trigger', count(row.dangerousTablePrivilegeCount) === 0),
    check('migration_history.select_only', row.migrationSelect && !row.migrationWrite),
  ];
  const reportWithoutHash = {
    schema_version: 1 as const,
    status: checks.every((candidate) => candidate.status === 'PASS')
      ? 'PASS' as const
      : 'FAIL' as const,
    check: 'postgres.runtime_privileges' as const,
    observed_at: (options.clock ?? (() => new Date()))().toISOString(),
    target: {
      database_sha256: sha256(row.databaseName),
      role_sha256: sha256(row.roleName),
      server_version_num: serverVersionNum,
    },
    checks,
  };
  return {
    ...reportWithoutHash,
    report_sha256: canonicalHash(reportWithoutHash),
  };
}

const catalogQuery = `
  WITH runtime_role AS (
    SELECT oid, rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
    FROM pg_roles
    WHERE rolname = current_user
  ), target_schemas AS (
    SELECT oid, nspname, nspowner
    FROM pg_namespace
    WHERE nspname IN ('dirizhor', 'dirizhor_migrations')
  ), target_relations AS (
    SELECT relation.oid, relation.relowner, relation.relkind, namespace.nspname, relation.relname
    FROM pg_class AS relation
    JOIN target_schemas AS namespace ON namespace.oid = relation.relnamespace
    WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
  )
  SELECT
    current_database() AS "databaseName",
    current_user AS "roleName",
    current_setting('server_version_num') AS "serverVersionNum",
    session_user = current_user AS "sessionMatchesCurrent",
    role.rolsuper AS superuser,
    role.rolcreaterole AS "createRole",
    role.rolcreatedb AS "createDatabase",
    role.rolreplication AS replication,
    role.rolbypassrls AS "bypassRls",
    (
      SELECT count(*)::text
      FROM pg_roles AS candidate
      WHERE (candidate.rolsuper OR candidate.rolcreaterole OR candidate.rolcreatedb
        OR candidate.rolreplication OR candidate.rolbypassrls
        OR left(candidate.rolname, 3) = 'pg_')
        AND pg_has_role(current_user, candidate.oid, 'MEMBER')
    ) AS "privilegedMembershipCount",
    pg_has_role(current_user, database.datdba, 'MEMBER') AS "databaseOwnerMembership",
    has_database_privilege(current_user, current_database(), 'CREATE') AS "databaseCreate",
    COALESCE(
      has_schema_privilege(current_user, to_regnamespace('public'), 'CREATE'),
      false
    ) AS "publicSchemaCreate",
    (SELECT count(*)::text FROM target_schemas) AS "targetSchemaCount",
    (SELECT count(*)::text FROM target_relations) AS "targetRelationCount",
    (
      SELECT count(*)::text FROM target_schemas AS schema
      WHERE NOT has_schema_privilege(current_user, schema.oid, 'USAGE')
    ) AS "targetSchemaUsageMissingCount",
    (
      SELECT count(*)::text FROM target_schemas AS schema
      WHERE has_schema_privilege(current_user, schema.oid, 'CREATE')
    ) AS "targetSchemaCreateCount",
    (
      SELECT count(*)::text FROM pg_namespace AS schema
      WHERE left(schema.nspname, 3) <> 'pg_'
        AND schema.nspname NOT IN ('information_schema', 'public', 'dirizhor', 'dirizhor_migrations')
        AND has_schema_privilege(current_user, schema.oid, 'CREATE')
    ) AS "unapprovedSchemaCreateCount",
    (
      SELECT count(*)::text FROM target_schemas AS schema
      WHERE pg_has_role(current_user, schema.nspowner, 'MEMBER')
    ) AS "targetSchemaOwnerMembershipCount",
    (
      SELECT count(*)::text FROM target_relations AS relation
      WHERE pg_has_role(current_user, relation.relowner, 'MEMBER')
    ) AS "targetRelationOwnerMembershipCount",
    (
      SELECT count(*)::text
      FROM pg_proc AS routine
      JOIN target_schemas AS schema ON schema.oid = routine.pronamespace
      WHERE pg_has_role(current_user, routine.proowner, 'MEMBER')
    ) AS "targetRoutineOwnerMembershipCount",
    (
      SELECT count(*)::text
      FROM pg_proc AS routine
      JOIN target_schemas AS schema ON schema.oid = routine.pronamespace
      WHERE routine.prosecdef
        AND has_function_privilege(current_user, routine.oid, 'EXECUTE')
    ) AS "securityDefinerExecuteCount",
    (
      SELECT count(*)::text
      FROM pg_extension AS extension
      WHERE pg_has_role(current_user, extension.extowner, 'MEMBER')
    ) AS "extensionOwnerMembershipCount",
    (
      SELECT count(*)::text FROM target_relations AS relation
      WHERE relation.nspname = 'dirizhor'
        AND relation.relkind IN ('r', 'p', 'f')
        AND (
          has_table_privilege(current_user, relation.oid, 'TRUNCATE')
          OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
          OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
        )
    ) AS "dangerousTablePrivilegeCount",
    COALESCE(
      has_table_privilege(
        current_user,
        to_regclass('dirizhor_migrations.schema_migrations'),
        'SELECT'
      ),
      false
    ) AS "migrationSelect",
    COALESCE(
      has_table_privilege(current_user, to_regclass('dirizhor_migrations.schema_migrations'), 'INSERT')
      OR has_table_privilege(current_user, to_regclass('dirizhor_migrations.schema_migrations'), 'UPDATE')
      OR has_table_privilege(current_user, to_regclass('dirizhor_migrations.schema_migrations'), 'DELETE')
      OR has_table_privilege(current_user, to_regclass('dirizhor_migrations.schema_migrations'), 'TRUNCATE')
      OR has_table_privilege(current_user, to_regclass('dirizhor_migrations.schema_migrations'), 'REFERENCES')
      OR has_table_privilege(current_user, to_regclass('dirizhor_migrations.schema_migrations'), 'TRIGGER'),
      false
    ) AS "migrationWrite"
  FROM runtime_role AS role
  JOIN pg_database AS database ON database.datname = current_database()
`;

function check(id: string, passed: boolean): RuntimePrivilegeCheck {
  return { id, status: passed ? 'PASS' : 'FAIL' };
}

function count(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error('PostgreSQL runtime privilege count is invalid.');
  }
  return parsed;
}

function integer(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`PostgreSQL ${label} is invalid.`);
  return parsed;
}

function requiredIdentity(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 128 || /[\0\r\n]/.test(normalized)) {
    throw new Error(`PostgreSQL ${label} is invalid.`);
  }
  return normalized;
}

function sha256(value: string): string {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function canonicalHash(value: unknown): string {
  return sha256(JSON.stringify(canonicalize(value)));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalize(item)]),
    );
  }
  return value;
}
