# Backup and restore v1

Статус: архитектурный и эксплуатационный черновик v1 с исполнимым synthetic
restore smoke для reference deployment.

Документ определяет минимальный production gate резервного копирования
«Дирижёра». Backup считается существующим только после успешного восстановления
в изолированную среду и проверки данных приложения. Наличие backup job или
объекта в storage само по себе доказательством не является.

## 1. Защищаемые активы

В один recovery set входят:

- PostgreSQL database и migration history;
- immutable Document Store, на который ссылаются `document_versions` и
  `agent_run_results`;
- конфигурация deployment без значений секретов;
- версии application images, migration manifest и OIDC/TLS profile;
- отдельно управляемые secrets/keys, необходимые для запуска восстановленной
  системы.

PostgreSQL без Document Store восстанавливает метаданные, но не документы.
Document Store без PostgreSQL не восстанавливает identity, RBAC, связи, audit и
текущие версии. Эти части проверяются как единая логическая пара.

## 2. RPO, RTO и владельцы

До pilot организация обязана утвердить:

- RPO для PostgreSQL и Document Store;
- RTO для полного восстановления и отдельного failover;
- срок хранения, geographic/account isolation и legal hold;
- владельца backup, владельца restore и лицо, принимающее решение о
  переключении;
- максимальный допустимый возраст последнего успешного restore drill.

Reference-проект намеренно не подставляет произвольные числовые значения. Gate
считается незавершённым, пока значения не утверждены владельцем данных.
Значения, backup/restore/failover owners, retention, maintenance window и
максимальный возраст restore drill фиксируются
в `deploy/reference/pilot-adoption-decision-template-v1.json` и проверяются:

```bash
cd deploy/reference
node scripts/pilot-adoption-decision.mjs \
  /secure/change/CHG-123/pilot-adoption-decision.json
```

RPO/alert thresholds для PostgreSQL и Document Store проверяются отдельно;
положительный общий RPO в итоговом conformance evidence не заменяет этот gate.

## 3. Стратегия PostgreSQL

Production baseline использует provider-native base backup + непрерывный WAL
archive или эквивалентный управляемый PITR. Требуются мониторинг archive lag,
неизменяемое хранение, защита от перезаписи WAL, шифрование, отдельный recovery
account и регулярное восстановление на новую database/cluster identity.

`pg_dump` является дополнительным переносимым логическим backup и механизмом
synthetic smoke. Он не заменяет base backup/WAL и не доказывает PITR. Logical
restore выполняется с `--no-owner`, `--no-acl`, `--single-transaction` и
остановкой при первой ошибке.

## 4. Согласованность Document Store

Reference FileDocumentStore записывает файл и синхронизирует его до SQL commit,
после чего файл неизменяем. Поэтому допустимый backup order:

1. Зафиксировать PostgreSQL recovery point/snapshot `T`.
2. После `T` снять snapshot/copy Document Store.
3. Хранить идентификаторы обоих artifacts как один recovery set.

При таком порядке любой файл, на который ссылается database в точке `T`, уже
существует в более позднем filesystem snapshot. Snapshot может содержать
лишние staged или более новые immutable files; они не становятся доступными без
SQL reference. Обратный порядок запрещён: database backup может захватить ссылку
на файл, отсутствующий в более раннем filesystem snapshot.

Restore verifier проверяет каждую SQL reference:

- relative key не выходит за Document Store root;
- target является обычным файлом, а не symlink;
- `size_bytes` и SHA-256 совпадают с database;
- файл не writable для group/others;
- один storage URI не имеет противоречивых metadata.

Manifest hash строится из всех references, их UUID, storage URI, size и hash.
Содержимое документов и абсолютные filesystem paths в evidence не попадают.

## 5. Synthetic provider smoke

Harness требует две заранее созданные пустые disposable PostgreSQL 15+
databases с разными именами, client tools не старше source server и явное
подтверждение destructive cleanup:

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

Harness применяет migrations к source, создаёт canary document, экспортирует
PostgreSQL snapshot, выполняет custom dump, копирует только проверенные
immutable files, восстанавливает target и сравнивает:

- migration history;
- список tables, точные row counts и hash значимых canary data;
- число SQL file references и unique files;
- total bytes и Document Store manifest hash.

Connection strings передаются `pg_dump`/`psql` через child environment, а не
arguments. Временный dump, SQL и файлы имеют закрытые permissions и удаляются.
Application schemas в обеих disposable databases удаляются в `finally`.

## 6. Реальный restore drill

Synthetic smoke проверяет клиентские инструменты и provider compatibility, но
не заменяет восстановление реального recovery set. Production drill выполняется
так:

1. Создать изолированную network/account среду без пользовательского ingress.
2. Восстановить provider base backup/PITR на новую database identity до
   выбранной точки и зафиксировать фактически достигнутое время.
3. Восстановить связанный Document Store snapshot, снятый не раньше database
   recovery point.
4. Использовать отдельный read-only verifier credential и выполнить:

```bash
cd director/reference
export DIRECTOR_EVIDENCE_DATABASE_URL_FILE=/run/secrets/restored-readonly-db-url
export DIRECTOR_EVIDENCE_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
export DIRECTOR_EVIDENCE_EXPECT_DATABASE=dirizhor_restore_drill
export DIRECTOR_EVIDENCE_DOCUMENT_STORE_ROOT=/restore/dirizhor-documents
pnpm db:document-store-evidence
```

Для повторной проверки можно закрепить выданный `manifest_hash` через
`DIRECTOR_EVIDENCE_EXPECT_DOCUMENT_MANIFEST_HASH`. Затем запускается Director с
новыми test-only secrets, проверяются readiness, OIDC canary, RBAC, чтение
выборочных документов всех sensitivity levels, task/timeline и audit continuity.

Восстановленную среду нельзя подключать к production IdP callbacks, Gateway,
email/webhooks или внешним AI до явного разрешения. Test secrets не совпадают с
production, а outbound network по умолчанию запрещена.

## 7. Проверка PITR

В каждой проверке создаётся именованная recovery point или canary transaction,
затем данные до и после неё. Restore должен доказать выбранную семантику:

- состояние до target присутствует;
- состояние после target отсутствует при point-in-time rollback;
- migration registry не содержит `applying`, unknown или pending rows;
- timeline/restore point и достигнутое время входят в evidence;
- WAL archive не перезаписывает отличный artifact с тем же именем.

Configuration files PostgreSQL и secret manager восстанавливаются отдельным
процессом: WAL/PITR не содержит `postgresql.conf`, `pg_hba.conf`, certificates
или application secrets.

## 8. Failover и rollback

Restore не становится production автоматически. До переключения проверяются
RPO gap, отсутствующие внешние side effects, последние audit IDs, object
manifest, DNS/TLS и OIDC callback registration. Решение о переключении и
необратимом прекращении старого writer принимается отдельно.

Одновременная запись старого и восстановленного Director запрещена. После
переключения старая сторона остаётся fenced. Возврат выполняется как новое
контролируемое переключение, а не как объединение двух разошедшихся databases.

## 9. Evidence и критерии завершения

Change record содержит:

- backup/recovery set ID и timestamps;
- PostgreSQL/provider version, application release и migration checksums;
- source/target identities без connection strings;
- requested и achieved recovery point;
- database и Document Store manifest hashes/counts;
- duration каждой фазы и сравнение с утверждённым RTO/RPO;
- canary request/audit IDs, решение о переключении и владельцев проверки.

В evidence запрещены database URLs, passwords, encryption keys, raw documents,
OIDC tokens/codes/sub и private certificate material. Любой `NOT_RUN`, mismatch,
missing file, pending migration или превышение утверждённых RPO/RTO означает
незавершённый gate.

## Нормативные основания

- [PostgreSQL: SQL Dump](https://www.postgresql.org/docs/current/backup-dump.html);
- [PostgreSQL: pg_restore](https://www.postgresql.org/docs/current/app-pgrestore.html);
- [PostgreSQL: Continuous Archiving and PITR](https://www.postgresql.org/docs/current/continuous-archiving.html).
