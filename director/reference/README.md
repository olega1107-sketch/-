# Reference Director

Исполнимый эталон Director для первого вертикального среза. Он проверяет
публичную загрузку документа, создание и чтение task/agent run, временный
AI-результат, confirmation flow и внутреннюю Director-сторону
[Agent Gateway Protocol v1](../../gateway/openapi-v1.yaml), но не реализует
весь публичный Director API.

## Что реализовано

- `POST /api/v1/memory-objects:upload` с обязательными user bearer,
  `X-Request-Id` и потоковым разбором `multipart/form-data`;
- проверка active user, project scope и permissions `project.read`,
  `memory_object.create`, `document_version.create`;
- staging immutable bytes по ключу
  `document-versions/{project_id}/{memory_object_id}/{document_version_id}`;
- повторная проверка RBAC под SQL locks и атомарное создание `memory_object`,
  первой `document_version`, `memory_object.created` и
  `document_version.created`;
- отдельная публичная форма ошибок из Director OpenAPI;
- каждый permission/policy deny текущих public business endpoints фиксирует
  immutable `authorization_decision(decision=deny)` и связанный `access.denied`;
  concealed permission deny остаётся публичным `404`, но получает внутренний
  reason и server-resolved project scope;
- каждый успешный immediate/replay public business flow фиксирует
  `authorization_decision(decision=allow, reason_codes=['permissions_satisfied'])`:
  direct write-события ссылаются на него напрямую, а read/search/replay получают
  metadata-only `access.allowed` или связанный `memory_object.read`; query,
  document body, prompt и AI response в metadata не копируются;
- `POST /api/v1/auth/sessions` для явно включённого local password login:
  versioned scrypt verifier, одинаковый `401`, 256-bit opaque bearer и
  `Cache-Control: no-store`; raw password и session token в БД не попадают;
- `DELETE /api/v1/auth/sessions/current` немедленно отзывает текущую session;
  issuance/revocation и обязательные audit events коммитятся атомарно;
- `GET /api/v1/auth/oidc/start` и `/api/v1/auth/oidc/callback` реализуют
  corporate Authorization Code + PKCE S256 boundary через `openid-client`:
  state/nonce/browser binding одноразовые, external identity заранее provisioned
  по точной паре issuer/sub и ожидаемому provider code, а UI получает только Secure HttpOnly Director
  session cookie без токенов IdP или bearer в URL;
- discovery проходит fail-closed conformance по exact issuer, HTTPS endpoints,
  code flow, PKCE S256, token auth method, subject type и закреплённому
  асимметричному ID Token algorithm; `oidc:preflight` выдаёт безопасный report;
- `POST /api/v1/auth/oidc/logout` сначала отзывает локальную OIDC-session, затем
  возвращает optional RP-initiated logout URL; операторские `oidc:provision` и
  `oidc:revoke-access` атомарно управляют identity/access с audit без raw `sub`;
- `GET /api/v1/memory-objects/{memory_object_id}` с conditional sensitivity
  permissions, условной выдачей `current_version` и audit каждого чтения;
- `GET /api/v1/memory-objects/search` по карточке, теме, проекту и разрешённым
  связанным knowledge objects: visibility-фильтр выполняется до `LIMIT`, а
  opaque keyset cursor привязан к пользователю и запросу;
- `POST /api/v1/tasks` с project RBAC, атомарным `task.created` audit и
  идемпотентностью по `X-Request-Id`;
- `GET /api/v1/projects` возвращает только проекты с действующим assignment и
  `project.read`, с keyset pagination и metadata-only allow audit;
- `POST /api/v1/tasks/{task_id}/context:search` берёт project scope только из
  task и возвращает причины совпадения без полного текста документов;
- `GET /api/v1/tasks/{task_id}/timeline` объединяет связанные audit events,
  agent runs, сохранённые AI-результаты и решения с visibility-фильтрацией и
  keyset pagination;
- `GET /api/v1/tasks/{task_id}` и `GET /api/v1/agent-runs/{agent_run_id}` с
  server-derived project scope и concealment для пользователя вне проекта;
- `POST /api/v1/tasks/{task_id}/agent-runs` с точным startup-configured маршрутом
  `agent_type -> provider/model/deployment/profile`: выбранный маршрут, document
  versions, чувствительность и порядок замораживаются для всех retry;
- проверка `project_ai_policy`: external enablement, provider allowlist,
  точная provider profile version, maximum sensitivity и запрет external
  `restricted` context;
- `428 requires_confirmation` для external `internal`/`confidential` по policy и
  для context сверх `bulk_context_object_limit`;
- `GET /api/v1/confirmations` с project/status filter и opaque keyset cursor,
  а также `GET /api/v1/confirmations/{confirmation_id}`, `:approve` и `:reject` с
  повторной проверкой requester/approver RBAC, current policy, sensitivity и
  canonical `payload_hash`;
- approval agent context атомарно выпускает capability, переводит waiting
  run/task, фиксирует approval/dispatch/consumption audit и затем вызывает
  Gateway;
- `GET /api/v1/agent-runs/{agent_run_id}/result` проверяет права на весь
  frozen/current context, срок действия, размер, UTF-8 и content hash;
- `POST /api/v1/agent-runs/{agent_run_id}/result:save` всегда создаёт frozen
  `ai_result_save` confirmation; approval атомарно создаёт `ai_result`, первую
  `document_version`, relationships, завершает task и связывает временный result;
- reject, expiry и stale payload применяют operation-specific termination:
  context share отменяет waiting run/task, result save оставляет task в review;
- атомарное создание frozen run, contexts, capability/resources,
  `context_set_hash`, request fingerprint, task transitions и dispatch audit;
- детерминированный opaque capability token на HMAC-SHA-256: в БД
  хранится только его hash, а retry восстанавливает тот же token;
- HTTP dispatch в Agent Gateway с короткоживущим Ed25519 workload token, origin-scoped outbound mTLS,
  capability, idempotency key и проверкой receipt; при сетевом сбое frozen run
  остаётся в `queued` для retry;
- Fastify ingress для `context-bundle:redeem` и Gateway events с TypeBox-схемами;
- issuer/audience/expiry-bound workload identity и обязательный mTLS для внутренних маршрутов в защищённом режиме;
- `/health/live` и `/health/ready`: readiness проверяет PostgreSQL и read/write
  доступ к Document Store, не раскрывая exception details;
- versioned database migration runner с immutable checksum, session advisory
  lock, dirty-state detection, явным baseline adoption и отдельным gate для
  destructive `contract`; runtime не стартует с missing/pending/diverged history;
- PostgreSQL adapter на `pg` с короткими транзакциями и row locks;
- двухфазное context redemption: inspect, чтение и проверка байтов,
  повторная проверка под lock, `used_at` и `agent_context.redeemed` в одной
  SQL-транзакции;
- event preflight до Document Store staging и повторная проверка под
  `FOR UPDATE`;
- idempotent event inbox через `audit_events.id = event_id`, включая
  security audit при повторе ID с другим hash;
- staged result pattern с детерминированным ключом и атомарной SQL-фиксацией
  result, run status, task review status и audit event;
- filesystem Document Store adapter с relative keys, hash verification, mode `0600`
  и атомарным rename;
- backup integrity verifier связывает все SQL references с immutable files,
  проверяет path boundary, type, permissions, size и SHA-256; synthetic real
  PostgreSQL dump/restore harness сравнивает migration, row/canary и Document
  Store manifests;
- PGlite integration tests на полной [`db/schema-v1.sql`](../../db/schema-v1.sql),
  включая отзыв роли между staging и commit и rollback при конфликте;
- сквозной тест с [Reference Gateway](../../gateway/reference/README.md):
  public task create -> document upload -> agent-run create -> capability redeem ->
  provider lifecycle -> public result read -> `ai_result_save` confirmation ->
  saved memory object -> registry read/search -> task timeline, а также external
  `428` -> public approval -> terminal result; без SQL seed для
  task/run/context/capability/confirmation.

## Проверка

Требуются Node.js 22.18 или новее и pnpm.

```bash
pnpm install --frozen-lockfile
pnpm db:checksums
pnpm check
pnpm lint
pnpm test
pnpm build
```

Тесты не обращаются к внешним сервисам. PGlite не загружает extension
`pgcrypto`, поэтому тестовый loader убирает только его `CREATE EXTENSION`;
остальные таблицы, functions, constraints и triggers берутся из основного SQL-файла.

## Локальный запуск

Сначала нужно применить versioned migrations к пустой PostgreSQL 15+:

```bash
export DATABASE_URL=postgresql://localhost/dirizhor
export DIRECTOR_MIGRATION_DATABASE_URL="$DATABASE_URL"
pnpm db:migrate
pnpm db:status
```

Для существующей schema v1 используется отдельная проверяемая adoption-процедура
из [Database README](../../db/README.md). Прямой запуск `schema-v1.sql` больше не
является runtime deployment flow, потому что не создаёт migration history.
В production `DIRECTOR_MIGRATION_DATABASE_URL(_FILE)` принадлежит отдельной
DDL-роли и не передаётся процессу Director; совпадение с runtime `DATABASE_URL`
допустимо только локально.
Production image содержит скомпилированные команды без `tsx`:
`node dist/db-migrate-cli.js migrate` и `node dist/db-migrate-cli.js status`.
Public upload сам создаёт immutable bytes под
`DOCUMENT_STORE_ROOT`; заранее заполненные строки `document_versions` должны
ссылаться на существующие relative keys в том же хранилище.

```bash
export DIRECTOR_ALLOW_INSECURE_DEV=true
export DIRECTOR_HOST=127.0.0.1
export DIRECTOR_PORT=8080
export DATABASE_URL=postgresql://localhost/dirizhor
export DOCUMENT_STORE_ROOT="$PWD/.director-state/documents"
export DIRECTOR_GATEWAY_TOKEN=local-gateway-to-director-token
export GATEWAY_BASE_URL=http://127.0.0.1:8443
export GATEWAY_DIRECTOR_TOKEN=local-director-to-gateway-token
export DIRECTOR_CAPABILITY_KEY_BASE64="$(openssl rand -base64 32)"
export DIRECTOR_AGENT_ROUTES_JSON='[
  {
    "agent_type": "architect",
    "provider": "fixture",
    "model": null,
    "deployment_class": "internal",
    "provider_data_profile_version": null
  }
]'
# Static public auth is available only with DIRECTOR_ALLOW_INSECURE_DEV=true.
export DIRECTOR_PUBLIC_USER_TOKEN=local-user-token
export DIRECTOR_PUBLIC_USER_ID=00000000-0000-4000-8000-000000000001
# export DIRECTOR_MAX_DOCUMENT_UPLOAD_BYTES=26214400
# export DIRECTOR_CONFIRMATION_TTL_MS=900000
pnpm dev
```

Незащищённый HTTP-режим допустим только для локальной разработки.
В этом режиме вместо `DIRECTOR_AGENT_ROUTES_JSON` можно временно задать legacy
fallback `DIRECTOR_AGENT_PROVIDER`, `DIRECTOR_AGENT_MODEL`,
`DIRECTOR_AGENT_DEPLOYMENT_CLASS` и `DIRECTOR_PROVIDER_DATA_PROFILE_VERSION`.
Fallback принимает любой `agent_type` и поэтому запрещён в защищённом режиме.

## Защищённый запуск

Без `DIRECTOR_ALLOW_INSECURE_DEV=true` обязательны:

- `DIRECTOR_TLS_CERT_PATH` — сертификат Director;
- `DIRECTOR_TLS_KEY_PATH` — private key Director;
- `DIRECTOR_TLS_CA_PATH` — CA для проверки клиентского сертификата;
- `DIRECTOR_ALLOWED_PEER_CNS` — непустой список разрешённых CN, по умолчанию
  `agent-gateway`;
- `DIRECTOR_WORKLOAD_SIGNING_KEY_ID` и
  `DIRECTOR_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64(_FILE)`;
- `GATEWAY_WORKLOAD_VERIFY_KEYS_JSON(_FILE)` — public Ed25519 keyset Gateway;
- `DIRECTOR_AGENT_ROUTES_JSON` — непустой массив точных маршрутов для разрешённых
  `agent_type`; одинаковые `agent_type` и fallback отклоняются при старте.

Outbound Director -> Gateway всегда использует mTLS. По умолчанию применяются
service certificate/key/CA выше. Для отдельных client credentials задаются
`DIRECTOR_GATEWAY_CLIENT_CERT_PATH`, `DIRECTOR_GATEWAY_CLIENT_KEY_PATH` и
`DIRECTOR_GATEWAY_CA_PATH`. Требования к SAN, EKU и ротации описаны в
[Service mTLS profile v1](../../docs/dirizhor/service-mtls-v1.md).

При работе за reverse proxy нужно явно перечислить только его IP/CIDR в
`DIRECTOR_TRUSTED_PROXY_CIDRS`. Без этой настройки forwarded client IP
игнорируется. Wildcard и hostname запрещены. Готовый edge-профиль описан в
[reference deployment](../../deploy/reference/README.md).

Public authentication по умолчанию работает в режиме
`DIRECTOR_PUBLIC_AUTH_MODE=session`. Bearer является высокоэнтропийным opaque
session token; Director хранит и ищет только `sha256:<hex>`, проверяет срок,
отзыв сессии и active user, затем атомарно обновляет `last_seen_at`. Static public
auth в защищённом режиме отклоняется при старте.

Corporate OIDC login включается только в protected HTTPS mode. Минимальная
конфигурация:

```bash
export DIRECTOR_OIDC_ISSUER_URL=https://idp.example.com
export DIRECTOR_OIDC_CLIENT_ID=dirizhor
export DIRECTOR_OIDC_CLIENT_SECRET='read-from-secret-manager'
export DIRECTOR_OIDC_REDIRECT_URI=https://director.example.com/api/v1/auth/oidc/callback
export DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI=https://director.example.com/
export DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG=RS256
# Optional, requires an advertised end_session_endpoint:
# export DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI=https://director.example.com/signed-out
```

В production вместо прямого значения рекомендуется
`DIRECTOR_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc-client-secret`.

IdP должен зарегистрировать `DIRECTOR_OIDC_REDIRECT_URI` как точный callback.
Опциональны `DIRECTOR_OIDC_PROVIDER_CODE` (по умолчанию `corporate`),
`DIRECTOR_OIDC_SCOPES` (обязательно содержит `openid`),
`DIRECTOR_OIDC_TOKEN_ENDPOINT_AUTH_METHOD`,
`DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG`,
`DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI`,
`DIRECTOR_OIDC_TRANSACTION_TTL_MS` (1-15 минут) и
`DIRECTOR_OIDC_DISCOVERY_TIMEOUT_MS`.

Перед production rollout discovery-профиль проверяется из той же среды:

```bash
pnpm oidc:preflight
```

До первого входа административный provisioning создаёт active `app_users` и
`user_identities(provider_code, provider_issuer, provider_subject)`, где
`provider_issuer` равен configured issuer, а `provider_subject` — точному `sub`
проверенного ID Token. Reference runtime намеренно не создаёт
пользователя и не связывает identity по email. Подробные инварианты описаны в
[OIDC/SSO boundary v1](../../docs/dirizhor/oidc-sso-v1.md), а provisioning,
canary, logout и revoke-all команды — в
[OIDC operational runbook](../../docs/dirizhor/oidc-operations-runbook.md).

Local password login выключен по умолчанию. Для его явного включения и изменения
12-часового TTL, ограниченного максимумом 30 дней:

```bash
export DIRECTOR_LOCAL_PASSWORD_LOGIN_ENABLED=true
export DIRECTOR_USER_SESSION_TTL_MS=43200000
```

Local identity заранее создаётся административным provisioning-процессом в
`user_identities`. Reference-утилита читает пароль только из stdin и выводит
подходящий versioned `secret_hash`:

```bash
read -s DIRECTOR_PASSWORD
printf '%s' "$DIRECTOR_PASSWORD" | pnpm password:hash
unset DIRECTOR_PASSWORD
```

`DIRECTOR_DATABASE_CA_PATH` включает проверку TLS-сертификата PostgreSQL.
HTTPS listener запрашивает клиентский сертификат, но обязательный verified mTLS
проверяется только authenticator внутренних Gateway-маршрутов. Публичные endpoints
используют TLS и user bearer без клиентского сертификата.

Runtime credentials принимают ровно один источник: `NAME` или `NAME_FILE`.
Mounted files поддерживаются для `DATABASE_URL`,
`DIRECTOR_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64`, `GATEWAY_WORKLOAD_VERIFY_KEYS_JSON`,
`DIRECTOR_CAPABILITY_KEY_BASE64`,
`DIRECTOR_OIDC_CLIENT_SECRET` и development-only `DIRECTOR_PUBLIC_USER_TOKEN`.
Одновременное задание, пустые/multiline values и NUL отклоняются при старте.

## Backup/restore checks

На двух выделенных пустых PostgreSQL databases доступен destructive synthetic
smoke `pnpm db:test-backup-restore`. Для уже восстановленной из production
копии команда `pnpm db:document-store-evidence` выполняет read-only проверку
migration history и всех SQL-ссылок на Document Store. Обязательные safety env,
порядок snapshot и граница между logical smoke и PITR описаны в
[Backup and restore v1](../../docs/dirizhor/backup-restore-v1.md).

Отдельный destructive `pnpm db:test-startup-guards` на ещё одной пустой
database доказывает, что production startup отклоняет dirty, diverged
и pending migration history. Safety environment и evidence boundary описаны
в [Database README](../../db/README.md#real-startup-refusal-guards).

## Ограничения reference runtime

- signing private key загружается при старте; автоматическая выдача ключа через
  внешнюю workload-identity platform и hot reload пока не реализованы;
- local session issuance, отзыв текущей session и один corporate OIDC provider
  реализованы, но refresh token, password reset/change, отзыв всех сессий,
  SAML, multi-provider login, JIT/linking API и IdP logout ещё отсутствуют;
- local login требует внешнего distributed rate limit; reference runtime сам не
  защищает несколько экземпляров от распределённого password guessing;
- invalid bearer и invalid/replayed OIDC transaction не создают постоянный
  `authentication.failed` audit, чтобы unauthenticated traffic не мог раздувать
  audit; для них нужны rate-limited ingress/runtime telemetry и внешний rate
  limit;
- filesystem adapter не заменяет versioned object storage и не защищает от
  подмены файла привилегированным локальным процессом;
- orphan cleanup для staged documents/results и production observability ещё нет;
- PGlite не проверяет конкурентные блокировки на нескольких connections;
  отдельный [real PostgreSQL harness](../../db/README.md#real-postgresql-contention)
  реализован, но должен пройти на целевом PostgreSQL build и topology;
- synthetic backup/restore и read-only evidence verifier реализованы, но
  provider-native base backup/WAL/PITR должен пройти отдельный target restore
  drill с утверждёнными RPO/RTO;
- per-agent маршруты загружаются при старте; динамического routing registry,
  hot reload, provider health/failover и административного API пока нет;
- confirmation workflow реализован для `agent_context_share`,
  `bulk_context_share` и `ai_result_save`; confirmations для decisions и
  sensitivity lowering ещё не реализованы;
- expiry обрабатывается лениво при approve/reject; фонового sweeper нет;
- MockAgent и ephemeral-CA smoke доказывают dispatcher и двусторонний TLS
  handshake, но конкретные production CA/SAN/EKU ещё требуют deployment test;
- registry search пока лексический и использует project-scoped SQL scan; FTS,
  stemming, vector ranking и отдельный поисковый индекс отложены;
- не реализованы остальные public Director endpoints, полноценный
  Auth/RBAC decision engine, Task Queue и UI.
