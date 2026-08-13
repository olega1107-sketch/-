# Automated target canary v2

Статус: production-oriented evidence runner. Скрипт выполняет только live
проверки на целевой инфраструктуре; synthetic test не создаёт target evidence.

## 1. Назначение и граница

`scripts/target-canary.mjs` проверяет через реальные DNS и TLS endpoints:

- public UI, обязательные security headers и внешний `404` для health routes;
- закрытие соединения при несовпадающем `Host`;
- OIDC discovery и фактический redirect Director с state, nonce и PKCE S256;
- Director -> Gateway: правильные client certificate и свежий workload token доходят до
  доменного `404 not_found`, а отсутствующий, malformed, истёкший или
  wrong-audience token и отсутствие
  client certificate отклоняются;
- Gateway -> Director: правильные client certificate и свежий workload token доходят до
  `403 capability_invalid`, а отсутствующий, malformed, истёкший или
  wrong-audience token и отсутствие
  client certificate отклоняются;
- OIDC session cookie открывает ровно утверждённый набор canary projects, тогда
  как запрос без session получает `401`.

Фиктивные UUID и capability не создают agent run и не расходуют capability.
OIDC start создаёт короткоживущую login transaction, а project read создаёт
штатную authorization/audit запись.

Runner не заменяет `nginx -t`, certificate preflight, corporate MFA/callback,
logout/revoke-all, mutating primary scenario или failure-mode canary. Поэтому
его успешный отчёт предлагает обновления только для:

- `edge.external_contract`;
- `mtls.live_director_to_gateway`;
- `mtls.live_gateway_to_director`;
- `workload_identity.live_director_to_gateway`;
- `workload_identity.live_gateway_to_director`;
- `oidc.discovery`.

Эти строки переносятся в основной conformance evidence только после проверки,
что runner использовал credentials и сетевой путь текущего rollout. Сам файл
runner не редактирует основной evidence document.

## 2. Предусловия

До запуска:

1. Доступен Node.js `>=22.18`, как в остальных reference-компонентах.
2. OCI digests, Kubernetes render/server dry-run, migration Job и readiness
   соответствуют текущему change.
3. `scripts/certificate-preflight.mjs` прошёл на тех же CA/cert/key files.
4. Выделенная corporate canary identity прошла реальный browser login с MFA.
5. Opaque Director session token помещён secret manager в однострочный файл;
   в config, shell history и process arguments его значения нет.
6. Для identity утверждён полный ожидаемый список project UUID, максимум 100.
7. Создан opaque `run:`/`ticket:` reference на browser evidence без cookie,
   authorization code, state, subject и private IdP claims.

Запускать runner следует из короткоживущего изолированного Job/host с target DNS
и маршрутами. Service account token не нужен. Filesystem read-only, кроме
закрытого output; egress ограничен public edge, IdP, Director и Gateway. Job
монтирует CA/cert/key, workload signing key files и session token read-only и удаляется
после сохранения evidence. Агрегированный доступ к двум service identities
допустим только на время этого контролируемого запуска.

## 3. Конфигурация

Начать с `target-canary-config.example.json`. Конфигурация несекретная и имеет
строгую схему: неизвестные и отсутствующие поля блокируют запуск.

- `public.ca_path` и `oidc.ca_path` равны `null` при использовании системного
  trust store; для private CA задаётся абсолютный path.
- `server_name` обязан точно совпасть с DNS hostname internal origin.
- `schema_version=2`, `workload_token_ttl_seconds` находится в диапазоне
  `10..300`, а каждый direction задаёт точный signing `kid` и путь к private
  Ed25519 PKCS8 DER в canonical base64.
- private keys, workload signing/session files имеют mode `0400`, `0440`, `0600` или
  `0640`; CA и leaf certificate не могут быть group/world-writable.
- session token обязан соответствовать opaque 32-byte base64url contract.
- `expected_project_ids` задаёт точный, а не минимальный, набор доступных
  проектов; pagination в этом canary запрещена.

Config file может находиться в change workspace, но evidence output должен быть
новым каталогом за пределами source tree. Его parent создаётся заранее с
ограниченным доступом.

До чтения secret contents и сетевых обращений проверить весь локальный input set:

```bash
node scripts/target-canary-preflight.mjs \
  /secure/change/CHG-123/target-canary-preflight \
  /secure/change/CHG-123/target-canary-config.json
```

Preflight проверяет строгую config schema, Node `>=22.18`, отсутствие symlink,
regular-file type, доступность для чтения текущей identity, ненулевой
ограниченный size и permissions каждого
обязательного и configured optional material. Он использует только filesystem
metadata, не читает содержимое файлов, не обращается к DNS/endpoints и не
заменяет certificate preflight или live-canary. Отчёт не содержит filesystem
paths; output directory имеет mode `0700`, файл `target-canary-preflight.json` —
`0600`.

Preflight exit codes:

- `0`: все локальные prerequisites имеют `PASS`;
- `1`: отчёт создан со статусом `BLOCKED` и полным набором найденных причин;
- `2`: invocation/config/output некорректны, readiness не установлена.

Любой исход кроме `0` блокирует certificate preflight и live запуск. Повтор
получает новый output directory; исходный `BLOCKED` report не перезаписывается.

## 4. Live-запуск

Из `deploy/reference`:

```bash
node scripts/target-canary.mjs \
  /secure/change/CHG-123/target-canary \
  /secure/change/CHG-123/target-canary-config.json
```

Exit codes:

- `0`: все десять runner checks имеют `PASS`;
- `1`: отчёт создан, минимум одна live проверка имеет `FAIL`;
- `2`: invocation/config/output некорректны и результат нельзя трактовать как
  выполненный canary.

Output directory получает mode `0700`,
`target-canary-evidence.json` — `0600`. Отчёт содержит статусы, безопасные
наблюдения, client/server certificate fingerprints и canonical SHA-256. В нём
нет токенов, cookie values, private keys, response bodies, IP addresses или
filesystem paths.

## 5. Проверка результата

Reviewer сверяет:

1. `execution_id`, environment и report hash с change record.
2. Все десять `checks` имеют `PASS`; общий `status` равен `PASS`.
3. Client certificate fingerprints принадлежат текущим outbound identities.
4. Server fingerprints принадлежат текущим Director/Gateway/public/IdP chains.
5. `external_evidence_refs` ведёт к browser flow того же canary session.
6. Шесть `registry_updates` перенесены без изменения статуса и с исходным
   `run:<execution-id>/target-canary` reference.

`application.session_read=PASS` подтверждает session/RBAC/project-list boundary,
но не закрывает `oidc.browser_canary` или `application.primary_canary`: для них
нужны все сценарии разделов 6-7 общего target conformance runbook. Mutating
часть автоматизирована отдельным
[application canary v1](application-canary-runbook.md), который запускается без
service mTLS identities после этого read-only gate.

## 6. Stop-ship

Rollout блокируется, если edge отвечает на неверный Host, публикует health,
теряет security header, discovery issuer/endpoints/PKCE/algorithm расходятся,
любой internal endpoint принимает один фактор вместо mTLS+workload token, правильная
service identity не достигает ожидаемого доменного ответа или canary identity
видит лишний/не видит утверждённый project.

Повтор после исправления получает новый `execution_id` и новый output directory;
исходный `FAIL` не перезаписывается.
