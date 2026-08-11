# Target infrastructure conformance runbook

Статус: production gate draft. Этот runbook выполняется на целевой
инфраструктуре и не может быть закрыт результатами PGlite, fixture IdP или
ephemeral certificates.

## 1. Правило результата

Каждая проверка получает ровно один статус: `PASS`, `FAIL` или `NOT_RUN`.
`NOT_RUN` не считается успехом. Evidence хранится в защищённом change record;
секреты, connection strings, query с OIDC code и private keys туда не входят.

Перед началом фиксируются release/image digests, migration checksums, public и
internal DNS names, IdP issuer/client ID, PostgreSQL provider/version, approved
RPO/RTO, backup recovery set и ответственные за rollout/rollback.

Машиночитаемый registry находится в `conformance/checks-v2.json`. Для каждого
rollout создаётся защищённая рабочая копия
`conformance/evidence-template-v2.json`; исходный template намеренно содержит
невалидные placeholders. Произвольные поля запрещены. Фактические logs, screenshots
и provider reports хранятся отдельно, а `evidence_refs` содержит только opaque
идентификаторы с namespace `alert:`, `artifact:`, `backup:`, `change:`,
`dashboard:`, `run:` или `ticket:`.

После заполнения:

```bash
node scripts/conformance-evidence.mjs /secure/change/evidence.json
```

Exit code `0` означает полный `PASS`; `1` — валидный, но заблокированный gate;
`2` — структурно неверный или неполный evidence. Выходной manifest содержит
статусы, counts и canonical SHA-256 исходного отчёта, но не сами evidence refs,
DNS, issuer/client ID или recovery metadata.

## 2. Release gate

Для Director:

```bash
cd director/reference
pnpm install --frozen-lockfile
pnpm db:checksums
pnpm check
pnpm lint
pnpm test -- --maxWorkers=2
pnpm build
```

Аналогично выполняются `check`, `test`, `build` Gateway и UI. Не допускаются
локальные package updates между проверкой и сборкой release image.

В clean release builder эти команды собираются автоматически. Parent directory
создаётся заранее с mode `0700`, а указанный collector output ещё не существует:

```bash
cd deploy/reference
node scripts/release-evidence.mjs /secure/change/CHG-123/release-evidence CHG-123
```

Collector не наследует application secrets, удаляет старые `dist`, использует
`pnpm install --frozen-lockfile --offline`, сохраняет logs/manifests с mode
`0600`, хеширует source tree до и после запуска, package file, lockfile и каждый
build artifact. Изменение workspace во время сбора блокирует результат. `PASS`
переносится в основной evidence document вместе с выданным `artifact:` reference
только для того же source revision и опубликованного artifact. Image digests в
основном документе берутся из registry после публикации, а не вычисляются из
локального `dist`.

Registry IDs: `release.director`, `release.gateway`, `release.ui`.

До OCI build выполняется `node scripts/container-preflight.mjs` с тремя
approved base image references, закреплёнными `@sha256`, и точной версией pnpm.
Затем на clean approved builder выполняется:

```bash
node scripts/oci-release.mjs \
  /secure/change/CHG-123/oci-release \
  /secure/change/CHG-123/oci-release-config.json
```

Скрипт не принимает application secrets и требует внешнюю registry/signing
authentication. Фактические images строятся multi-stage Dockerfiles, получают
SBOM/provenance, проходят vulnerability policy и signature verification. Только
итоговый `oci-release-evidence.json` со статусом `PASS` разрешает перенести
registry digests Director, Gateway и Edge/UI в основной evidence. Synthetic
тесты скрипта и `oci-release-failed.json` не дают `PASS`. Runtime policy
сверяется с
[Container runtime contract v1](container-runtime-contract.md).

Target manifests создаются только из digest references успешного OCI evidence:

```bash
node scripts/kubernetes-render.mjs \
  /secure/change/CHG-123/kubernetes \
  /secure/change/CHG-123/kubernetes-target-config.json
```

Три bundles проходят `kubectl apply --dry-run=server`, после чего применяются
строго в порядке prerequisites -> external secrets -> completed migration Job ->
workloads. Полный secret/PKI inventory, NetworkPolicy и rollback порядок описаны
в [Kubernetes target deployment v1](kubernetes-target-runbook.md). Локальный
render без target API server остаётся `NOT_RUN` для deployment gate.

Registry ID: `deployment.kubernetes_contract`.

## 3. Nginx edge

Templates рендерятся только allowlisted переменными из deployment README.
На фактически запускаемом image/container:

```bash
nginx -t
```

Проверить с внешней точки:

- несовпадающий `Host` закрывает соединение;
- `/health/live` и `/health/ready` возвращают внешний `404`;
- UI и API имеют HSTS, CSP, `nosniff`, deny framing и `no-referrer`;
- OIDC callback query не появляется в access/error logs;
- upload проходит без proxy buffering и с утверждённым size limit;
- rate limits проверены для корпоративного NAT и IdP retry, а `429` не содержит
  upstream details.

Nginx обязан использовать `proxy_ssl_server_name on`, фиксированный
`proxy_ssl_name`, явный trusted CA и `proxy_ssl_verify on`. Успешный `nginx -t`
без live upstream handshake недостаточен.

Registry IDs: `edge.nginx_config`, `edge.external_contract`.

## 4. Реальные certificates и mTLS

В environment с теми же paths/URLs/allowlists, что у Director и Gateway:

```bash
cd deploy/reference
node scripts/certificate-preflight.mjs
```

Preflight проверяет Director/Gateway server, оба межсервисных outbound
client certificates и, при configured internal provider, dedicated Gateway client
identity. Требуются matching private key, закрытые key permissions,
достаточный validity horizon, exact DNS SAN, `serverAuth`/`clientAuth`, trusted
chain и CN в ingress allowlist.

После запуска services выполнить live handshake в обоих направлениях. Запрос с
правильными client certificate и свежим workload token проходит, отсутствие
любого из двух факторов отклоняется. Canary отдельно доказывает отказ для
истёкшего token и неверного audience. Signing key передаётся через protected
config file, не как literal process argument. Зафиксировать peer certificate
fingerprint, server DNS и request ID, но не token или signing material.

Эти проверки вместе с external edge и OIDC discovery автоматизированы
`scripts/target-canary.mjs`. Конфигурация, безопасный execution context и точная
граница переносимых registry updates описаны в
[automated target canary v2](target-canary-runbook.md).

Registry IDs: `mtls.certificate_profile`,
`mtls.live_director_to_gateway`, `mtls.live_gateway_to_director`,
`workload_identity.live_director_to_gateway`,
`workload_identity.live_gateway_to_director`.

## 5. PostgreSQL

Сначала migration gate из отдельной job:

```bash
cd director/reference
pnpm db:status
```

Затем на отдельной пустой database выполнить real lock-order harness:

```bash
pnpm db:test-contention
```

Harness обязан наблюдать реальный lock wait через `pg_stat_activity`, доказать
commit уже разрешённой операции перед revoke и запрет новой операции после
revocation. PGlite-тест не заменяет этот результат.

На ещё одной отдельной пустой database выполнить startup refusal harness:

```bash
pnpm db:test-startup-guards
```

Он вызывает production migration startup guard и доказывает отказ при dirty,
checksum-drift и pending history. Конфигурация и safety guards описаны в
[application failure canary runbook](application-failure-canary-runbook.md).

На двух других disposable databases выполнить:

```bash
pnpm db:test-backup-restore
```

Обе команды имеют exact database-name guards. Нельзя направлять их на рабочую
database. Production PITR drill выполняется отдельно по
[Backup and restore v1](../../docs/dirizhor/backup-restore-v1.md).

Registry IDs: `postgres.migration_status`, `postgres.contention`,
`postgres.logical_restore`, `postgres.pitr_restore`.

## 6. Corporate IdP

В production network/secret environment:

```bash
cd director/reference
pnpm oidc:preflight
```

Затем provision canary identity и пройти реальный browser flow:

1. Start URL выдаёт transaction cookie и redirect к exact IdP endpoint.
2. IdP применяет ожидаемую MFA/conditional access policy.
3. Callback принимает подпись, issuer, audience, expiry, state, nonce и PKCE.
4. Canary получает только ожидаемые Director projects/permissions.
5. Callback replay не создаёт вторую session.
6. Local logout немедленно даёт `401`; optional IdP logout URL работает по
   зарегистрированной политике provider.
7. Unknown `sub` не создаёт user и не появляется raw в audit/telemetry.
8. `oidc:revoke-access` отключает canary и все его Director sessions.

Registry IDs: `oidc.discovery`, `oidc.browser_canary`.

Target runner проверяет discovery, start redirect и project scope уже выданной
browser session, но не подменяет пункты 2-3 и 5-8. Поэтому его
`application.session_read=PASS` сам по себе не закрывает
`oidc.browser_canary`.

## 7. Application canary

Через public edge выполнить основной сценарий без прямого SQL seed операционных
сущностей: login, project list, document upload/read/search, task create,
internal и approved external agent run, result read/save confirmation и task
timeline. Проверить audit allow/deny/confirmation и отсутствие token/document
content в infrastructure logs.

Отдельно проверить readiness при недоступных PostgreSQL, Document Store и
Gateway, graceful shutdown, restart с текущей migration history и отказ запуска
при pending/dirty history в disposable environment.

Registry IDs: `application.primary_canary`, `application.failure_modes`.

Автоматизированный read-only project canary выполняется первым как быстрый
stop-ship signal. Затем отдельный `scripts/application-canary.mjs` выполняет
mutating public workflow без service identities. Его схема, persistent-artifact
boundary, confirmation replay и reviewer gate описаны в
[automated application canary v1](application-canary-runbook.md). Target runner
не выдаёт `application.primary_canary=PASS`, а application runner не закрывает
`application.failure_modes`.

После primary canary, в отдельном approved change window, запустить
`scripts/application-failure-canary.mjs`. Он проверяет PostgreSQL/Document
Store/Gateway-state readiness, isolation при остановке Gateway, graceful restart
и ссылается на disposable migration startup evidence. Его fault/restore граница
описана в [runbook](application-failure-canary-runbook.md).

## 8. Backup, rollback и наблюдаемость

До rollout должен существовать свежий recovery set и успешный restore drill в
пределах утверждённых RPO/RTO. Rollback owner подтверждает последнюю версию,
совместимую с additive schema. Contract migrations в первом rollout запрещены.

Dashboard/alerts минимум покрывают edge `4xx/5xx`, OIDC provider failures,
Director/Gateway latency/error, DB connections/locks/replica lag, WAL archive
lag, Document Store errors, queue age и audit write failures. Проверить тестовым
событием путь alert до ответственного, а не только наличие dashboard.

Registry IDs: `operations.rollback`, `operations.observability`.

## 9. Exit criteria

Pilot разрешён только когда все обязательные строки имеют `PASS`, evidence
проверен вторым человеком, backup/rollback owners доступны, а residual risks
явно приняты. Ошибка issuer/signature/PKCE, mTLS, migration history,
contention, restore manifest или audit является stop-ship и не обходится
временным insecure flag.

Независимый reviewer проверяет ссылки на исходные artifacts, сверяет manifest
hash с защищённым evidence document и только после этого ставит
`evidence.peer_review=PASS`. Reviewer не может совпадать с rollout owner.
Архитектурная часть peer review дополнительно должна иметь `PASS` от
[`architecture-review.mjs`](architecture-review-runbook.md); его report hash
сохраняется как отдельный opaque evidence reference. Этот gate не заменяет
проверку release и target evidence вторым человеком.
