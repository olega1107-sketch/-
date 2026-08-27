# Pilot restore drill plan

Статус: безопасный план; выполнение не разрешено этим документом.

Цель — доказать PostgreSQL PITR и согласованное восстановление Document Store в
изолированную среду без изменения production writer, DNS, ingress, IdP callback,
Gateway, email/webhooks или внешнего AI.

## Stop conditions

Drill не начинается без отдельного change ID, recovery-set ID, выбранной PITR
point, подтверждения стоимости нового restore target и явного разрешения на
создание временных provider/Kubernetes ресурсов. Production credentials не
используются как runtime credentials восстановленной среды.

Любой missing artifact, mismatch, pending/unknown migration, manifest mismatch,
неготовый сервис, нарушение RBAC или превышение RPO/RTO означает `FAIL`.
Отсутствие запуска означает `NOT_RUN`, а не `PASS`.

## Phase 0 — frozen inputs

До изменений записать только безопасные identifiers:

- source release и image digests;
- recovery-set ID и timestamps PostgreSQL/Document Store;
- requested PITR point;
- migration checksums;
- source/target opaque identities;
- утверждённые RPO/RTO и владельцев drill/restore;
- baseline request/audit IDs и ожидаемые counts/hash без raw data.

Секреты, URLs, OIDC codes/tokens/sub, private keys и документы в evidence не
попадают.

## Phase 1 — isolated target

1. Создать новую PostgreSQL restore identity через provider-native PITR.
2. Создать отдельный namespace/network без пользовательского ingress.
3. Запретить outbound по умолчанию; не подключать production IdP callbacks,
   Gateway, webhooks, email или AI.
4. Создать test-only secrets и read-only verifier credential.
5. Восстановить Document Store snapshot из того же recovery set, снятый не
   раньше database recovery point.

Production database, PVC, workloads, DNS и secrets не изменяются.

## Phase 2 — PITR semantics

До выбранной point должны существовать именованная canary transaction и
контрольные данные; данные после point должны отсутствовать. Зафиксировать:

- requested и achieved recovery point;
- фактический PostgreSQL RPO gap;
- provider/version и timeline/restore identifier;
- отсутствие `applying`, unknown и pending migration rows;
- неизменность migration checksums.

## Phase 3 — Document Store verification

Запустить штатный read-only verifier с отдельным credential:

```bash
cd director/reference
export DIRECTOR_EVIDENCE_DATABASE_URL_FILE=/run/secrets/restored-readonly-db-url
export DIRECTOR_EVIDENCE_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
export DIRECTOR_EVIDENCE_EXPECT_DATABASE=dirizhor_restore_drill
export DIRECTOR_EVIDENCE_DOCUMENT_STORE_ROOT=/restore/dirizhor-documents
pnpm db:document-store-evidence
```

Проверить manifest hash, SQL reference count, unique file count, total bytes,
SHA-256/size каждой ссылки, отсутствие symlink/path escape и небезопасных file
permissions. Зафиксировать фактический Document Store RPO gap.

## Phase 4 — isolated application verification

Запустить Director только с test-only secrets. Последовательно проверить:

1. `/health/live` и `/health/ready`.
2. Изолированный OIDC canary без production callback.
3. Positive и negative RBAC для canary identities.
4. Чтение выборочных документов всех разрешённых sensitivity levels и
   ожидаемые deny/conceal результаты.
5. Task, context, timeline и agent-run/result provenance.
6. Audit continuity: последние baseline IDs присутствуют, post-PITR IDs
   отсутствуют, новые test events пишутся только в restored target.

Запрещены production switchover, DNS update и параллельная запись старого и
восстановленного Director.

## Phase 5 — RPO/RTO and evidence

Full Restore RTO измеряется от подтверждённого начала restore до завершения
readiness и всех обязательных application checks. Отдельно фиксируются duration
PITR, Document Store restore, verifier и application verification.

PASS требует одновременно:

- PostgreSQL RPO не более 900 секунд;
- Document Store RPO не более 3600 секунд;
- Full Restore RTO не более 3600 секунд;
- все проверки Phase 2–4 успешны;
- evidence не содержит секретов и проверен независимым reviewer.

## Phase 6 — controlled teardown

Удаление временной restored среды выполняется только после сохранения и review
evidence и отдельного подтверждения точных targets. Production resources не
являются targets teardown.

