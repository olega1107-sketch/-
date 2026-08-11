# Production database migration runbook

Этот runbook задаёт gate для миграции существующей Director database. Он не
заменяет процедуры конкретного PostgreSQL provider, backup policy и change
management организации.

## 1. Preflight

До окна изменений должны быть подтверждены:

- точная application release и migration manifest;
- PostgreSQL 15+ и TLS verification;
- успешный `pnpm db:checksums`;
- свежий backup и фактически выполненный test restore;
- доступный PITR point до миграции;
- отсутствие неизвестных или `applying` migration rows;
- достаточный запас disk/WAL и допустимый replica lag;
- отсутствие длительных транзакций, способных удерживать старый snapshot;
- dashboards для errors, lock waits, latency, pool saturation и replica lag;
- один назначенный migration operator и отдельный rollback owner.

Migration job использует отдельный
`DIRECTOR_MIGRATION_DATABASE_URL(_FILE)` с DDL-правами. Credential процесса
Director не повышается на время миграции и не получает право изменять
`dirizhor_migrations.schema_migrations`.

Для уже развёрнутой незарегистрированной v1 сначала применяется процедура
`db:adopt-v1` из [Database README](README.md). Запрещено вставлять baseline row
вручную без verifier и проверенного backup.

## 2. Expand

```bash
cd director/reference
pnpm db:migrate
pnpm db:status
```

Production Director image содержит скомпилированный runtime entrypoint без
development dependency `tsx`:

```bash
node dist/db-migrate-cli.js migrate
node dist/db-migrate-cli.js status
```

Kubernetes Job использует первый вызов с отдельным file-mounted DDL credential;
workloads применяются только после `condition=complete` и отдельного status gate.

Expand обязан сохранять работу текущей версии приложения. Новый column сначала
nullable или имеет metadata-only constant default. Долгий `CHECK`/foreign key
добавляется `NOT VALID`. Новый unique index на большой активной таблице сначала
создаётся отдельной `none`-миграцией через `CREATE UNIQUE INDEX CONCURRENTLY`,
а затем может быть присоединён как constraint.

При lock timeout миграция останавливается. Увеличивать timeout без анализа
blocker PID и ожидаемого lock level запрещено.

## 3. Dual compatibility and backfill

После expand разворачивается версия приложения, которая пишет обе модели и
умеет читать старые строки. Backfill запускается отдельным идемпотентным job:

- bounded batches с checkpoint;
- ограничение скорости по latency/WAL/replica lag;
- повторный запуск не меняет уже корректные строки;
- никакой одной транзакции на весь объём;
- итоговый запрос обязан показать `0` незаполненных/несогласованных строк.

Только после этого backfill migration фиксирует completion assertion в history.

## 4. Validate

Validate включает database constraints, reconciliation counts, выборочную
проверку hash/foreign keys и canary чтения только из новой модели. Для
`NOT VALID` constraints используется отдельный `VALIDATE CONSTRAINT`.

После validate старая версия приложения всё ещё должна запускаться и читать
данные. Это последняя точка обычного application rollback без восстановления БД.

## 5. Contract

Перед contract оператор подтверждает, что старые pods/processes, background
jobs и ad-hoc clients остановлены, а новая версия стабильно работает полный
наблюдаемый цикл.

```bash
pnpm db:migrate -- --allow-contract
pnpm db:status
```

Contract удаляет только доказанно неиспользуемый compatibility path. Он идёт
отдельным change window, никогда не совмещается с первым rollout новой версии и
не запускается автоматически при старте Director.

## 6. Rollback decision

До contract откат означает:

1. остановить rollout;
2. вернуть предыдущую совместимую application version;
3. сохранить additive schema и уже заполненные данные;
4. исправить проблему новой forward migration.

Удалять migration rows и запускать обратный destructive SQL запрещено: это
ломает воспроизводимость и может уничтожить данные, уже записанные новой версией.

После contract предыдущая application version несовместима. Допустимы только:

- срочная forward migration и исправленный application release;
- восстановление проверенного backup/PITR в новую БД с последующим переключением.

Решение о restore принимается по заранее заданным RTO/RPO. Перед переключением
проверяются migration history, row counts, последние audit events, object-store
references и отсутствие записей после выбранной recovery point, которые нужно
отдельно согласовать или воспроизвести.

## 7. Completion evidence

Change record должен содержать release id, migration checksums, время каждой
фазы, backup/PITR point, результаты reconciliation, максимальные lock wait и
replica lag, canary result, решение о contract и имя ответственного оператора.
Credentials, connection strings и содержимое пользовательских документов в
evidence не включаются.
