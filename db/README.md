# Database

[`schema-v1.sql`](schema-v1.sql) является неизменяемым baseline Director для
PostgreSQL 15+. Последующие изменения регистрируются в
[`migrations/manifest.json`](migrations/manifest.json) и применяются только
reference migration runner.

## Новая пустая база

```bash
cd director/reference
export DIRECTOR_MIGRATION_DATABASE_URL_FILE=/run/secrets/migration-database-url
export DIRECTOR_MIGRATION_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
pnpm db:checksums
pnpm db:migrate
pnpm db:status
```

Runner создаёт отдельный `dirizhor_migrations.schema_migrations`, берёт
session-level advisory lock, проверяет checksum и применяет baseline. Director
при старте требует полный и чистый migration history; незарегистрированная или
отстающая схема отклоняется.

Migration credential является отдельной операторской ролью с DDL-правами и не
монтируется в Director runtime. Runtime `DATABASE_URL(_FILE)` получает только
`USAGE` schema и `SELECT` на `dirizhor_migrations.schema_migrations`, помимо
необходимых DML-прав на application schema; менять migration history он не должен.

Effective права проверяются тем же runtime credential после migration и до
запуска workloads. Проверка только читает PostgreSQL catalogs и не выводит
database/role names:

```bash
export DATABASE_URL_FILE=/run/secrets/director-runtime/database-url
export DIRECTOR_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
export DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_DATABASE=dirizhor_pilot
export DIRECTOR_RUNTIME_PRIVILEGE_EXPECT_ROLE=dirizhor_runtime
node dist/postgres-runtime-privilege-cli.js
```

Только JSON report со `status=PASS` закрывает
`postgres.runtime_privileges`; локальный unit test не заменяет target evidence.

## Уже существующая schema v1

Сначала выполнить и проверить backup/restore, остановить schema changes и
сравнить фактическую БД с выпущенным baseline. Затем:

```bash
cd director/reference
export DIRECTOR_MIGRATION_DATABASE_URL_FILE=/run/secrets/migration-database-url
pnpm db:adopt-v1 -- --confirm-existing-schema-v1
pnpm db:status
```

Adoption не исполняет baseline повторно. Он проверяет PostgreSQL version,
`pgcrypto`, обязательные tables/columns/functions/triggers и RBAC seed, после
чего фиксирует checksum v1. Это защитная проверка известных инвариантов, а не
математическое доказательство полного совпадения каждого catalog definition.

Полный порядок deployment, фаз и rollback описан в
[`production-migration-runbook.md`](production-migration-runbook.md).
Правила файлов миграций находятся в [`migrations/README.md`](migrations/README.md).

## Real PostgreSQL contention

Harness использует настоящие параллельные соединения и только выделенную пустую
тестовую базу. Имя БД должно отдельно совпасть с safety-переменной:

```bash
cd director/reference
export DIRECTOR_CONTENTION_DATABASE_URL_FILE=/run/secrets/contention-database-url
export DIRECTOR_CONTENTION_EXPECT_DATABASE=dirizhor_contention_test
export DIRECTOR_CONTENTION_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
pnpm db:test-contention
```

Он применяет migrations, проверяет через `pg_stat_activity`, что конкурентный
revoke role assignment ждёт бизнес-транзакцию с `FOR SHARE`, затем доказывает
оба порядка: начатая разрешённая операция коммитится до revoke, а уже
закоммиченный revoke запрещает новую операцию. В конце test schemas удаляются.

## Synthetic backup/restore

Logical restore harness требует две разные заранее созданные пустые disposable
PostgreSQL 15+ databases и явное подтверждение очистки:

```bash
cd director/reference
export DIRECTOR_BACKUP_SMOKE_SOURCE_DATABASE_URL_FILE=/run/secrets/backup-smoke-source-url
export DIRECTOR_BACKUP_SMOKE_TARGET_DATABASE_URL_FILE=/run/secrets/backup-smoke-target-url
export DIRECTOR_BACKUP_SMOKE_EXPECT_SOURCE_DATABASE=dirizhor_backup_source_test
export DIRECTOR_BACKUP_SMOKE_EXPECT_TARGET_DATABASE=dirizhor_restore_target_test
export DIRECTOR_BACKUP_SMOKE_SOURCE_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
export DIRECTOR_BACKUP_SMOKE_TARGET_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
export DIRECTOR_BACKUP_SMOKE_CONFIRM_DISPOSABLE=true
pnpm db:test-backup-restore
```

Harness применяет migrations, создаёт SQL и filesystem canary, экспортирует
consistent PostgreSQL snapshot, выполняет `pg_dump`/`pg_restore`, проверяет
migration history, row counts, canary data и каждый Document Store hash. URLs
передаются client tools через environment; test schemas и временные artifacts
удаляются даже при ошибке.

Это provider compatibility smoke, а не PITR. Требования к base backup, WAL,
порядку snapshot PostgreSQL/Document Store, изолированному restore drill и
read-only evidence verifier описаны в
[Backup and restore v1](../docs/dirizhor/backup-restore-v1.md).

## Real startup refusal guards

Harness использует ещё одну заранее созданную пустую disposable PostgreSQL
15+ database:

```bash
cd director/reference
export DIRECTOR_STARTUP_GUARD_DATABASE_URL_FILE=/run/secrets/startup-guard-database-url
export DIRECTOR_STARTUP_GUARD_EXPECT_DATABASE=dirizhor_startup_guard_test
export DIRECTOR_STARTUP_GUARD_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
pnpm db:test-startup-guards
```

После exact name/version/empty-database guard он применяет весь current manifest,
проверяет чистый startup, а затем в откатываемых транзакциях доказывает
отказ того же production guard при `applying`, checksum drift и pending history.
Схемы удаляются в `finally`; успешная stdout-строка не содержит
connection URL или database name.
