# Agent Gateway Protocol v1

Черновой внутренний протокол между Director API и Agent Gateway для
первого MVP «Дирижёра». Машиночитаемый HTTP-контракт зафиксирован в
[`gateway/openapi-v1.yaml`](../../gateway/openapi-v1.yaml).

Статус — архитектурный черновик v1. OpenAPI нормативен для transport и DTO;
этот документ нормативен для lifecycle, security и retry semantics.

## 1. Цель

Gateway изолирует Director API от API конкретных AI-провайдеров. Он должен:

- принять уже авторизованный и замороженный `agent_run`;
- получить ровно тот context bundle, на который выдана capability;
- вызвать один заранее выбранный provider и model;
- нормализовать финальный ответ или ошибку;
- идемпотентно вернуть событие Director API.

Gateway не выбирает документы, не расширяет scope, не меняет provider и не
сохраняет ответ в корпоративную память.

## 2. Решения MVP

1. Transport — внутренний HTTPS request/response с mTLS и короткоживущим
   service token.
2. Публичные clients не видят internal endpoint.
3. До `202` Gateway одноразово получает и проверяет context bundle, сохраняет
   его в защищенный временный spool и удаляет raw capability из памяти.
   Provider вызывается асинхронно после `202`.
4. Context не помещается в Task Queue. Gateway redeem-ит его по одноразовой
   capability.
5. Director передает точные `provider`, `model`, deployment class и версию
   data profile. Неявный fallback запрещен.
6. Gateway отправляет `started` и получает `204` до provider call.
7. Каждый run имеет один логический provider attempt. Повтор после
   неопределенного provider outcome требует новый `agent_run`.
8. Streaming, tool calls, shell, browser, repository writes и agent-to-agent calls не входят
   в v1.
9. Gateway может использовать зашифрованный временный execution spool, но
   удаляет execute envelope, context и result после terminal acknowledgment
   или TTL.
10. Произвольные callback URL запрещены. Director endpoint заданы конфигурацией.

## 3. Trust boundaries

| Участник | Доверено | Запрещено |
| --- | --- | --- |
| Director API | Auth/RBAC, выбор provider, фиксация context, persistence | Подменять provider adapter во время run |
| Agent Gateway | Валидация protocol, adapter call, normalization | Искать память, менять context, решать RBAC |
| Provider adapter | Перевод normalized request в provider API | Получать service/capability tokens |
| External provider | Обработка явно переданного payload | Доступ к Director, Document Store и внутренней сети |

Каждый межсервисный вызов требует mTLS, service token и `X-Request-Id`.
Каждый сервис проверяет workload identity ожидаемого caller; сетевого адреса
недостаточно.

Provider выбирается только по серверному registry адаптеров. External
adapter разрешает egress только к exact public provider origin и запрещает
private/internal destinations. Internal adapter имеет отдельные exact
corporate origin, model allowlist, egress CIDR, Bearer и client mTLS identity. Оба
класса запрещают redirects и URL из execute payload. Adapter selection отклоняет
любое несовпадение provider, deployment class и data profile semantics.

## 4. Полный flow

```mermaid
sequenceDiagram
    participant D as Director API
    participant G as Agent Gateway
    participant P as AI Provider
    participant S as Document Store

    D->>D: Auth/RBAC, confirmation, freeze context
    D->>D: context_set_hash + capability
    D->>G: POST execute + capability header
    G->>D: POST context-bundle:redeem
    D->>S: Read exact document versions
    S-->>D: Immutable bytes + hashes
    D-->>G: Ordered ContextBundle; capability used
    G->>G: Verify positions, hashes, sensitivity
    G->>G: Persist encrypted temporary spool
    G-->>D: 202 accepted
    G->>D: event agent_run.started
    D-->>G: 204; run is running
    G->>P: Provider request
    P-->>G: Final result or error
    G->>D: One terminal event
    D->>D: Persist result/status/audit atomically
    D-->>G: 204
```

`awaiting_user_confirmation` никогда не передается Gateway. `execute` разрешен только
для run со статусом `queued` и непросроченной capability.

## 5. Фиксация execute request

Director атомарно фиксирует до dispatch:

- `agent_run` и его неизменяемые request fields;
- ordered `agent_run_context` с position, version и sensitivity snapshot;
- `context_set_hash`;
- `origin_request_id`, `request_fingerprint`, `dispatched_at` и `deadline_at`;
- provider, model, deployment class и data profile version;
- capability для `agent-gateway` с единственным action `context_bundle.read`.

`Idempotency-Key` равен `agent_run_id`. Gateway хранит до terminal TTL:

- `agent_run_id`;
- `request_fingerprint`;
- текущую фазу;
- IDs отправленных events;
- provider request ID, если он получен.

Перед `202` Gateway stage-ит зашифрованные execute envelope и context по
детерминированному ключу. Затем одна транзакция execution store фиксирует
receipt, spool URI/hashes и outbox record. Публикация в Task Queue идет из
outbox после commit; queue job содержит только `agent_run_id`, а дубль безопасен.
Raw capability в spool, execution store и outbox не входит. Orphan spool без
execution record удаляется по TTL.

Повтор с тем же fingerprint не создает второй provider call. Другой fingerprint для
того же run считается попыткой подмены и возвращает `409 idempotency_conflict`.

## 6. Capability и context bundle

Сырой capability token передается только в `X-Agent-Capability`. Он не попадает в:

- request body и durable queue;
- application/access logs;
- traces и metrics labels;
- audit metadata;
- exception messages.

Director выдает bundle только если одновременно верны:

1. token hash существует;
2. capability выдана active service principal `agent-gateway`;
3. capability не used, не revoked и не expired;
4. action равен `context_bundle.read`;
5. `agent_run_id`, project и `context_set_hash` совпадают;
6. capability resources точно равны замороженному context;
7. run остается `queued`, а deadline и project AI-policy действуют;
8. текущая sensitivity источника не выше frozen snapshot;
9. каждая версия сохранила content hash и размер.

Повышение sensitivity, запрет provider политикой, security incident или cancel
отзывают еще не использованную capability. Понижение sensitivity не ослабляет
уже замороженный snapshot.

Director сначала читает immutable versions и проверяет bytes, затем в короткой
SQL-транзакции блокирует capability (`SELECT ... FOR UPDATE`), повторяет
проверки run/policy/resources и ставит `used_at`. Bundle отправляется только
после commit. Поэтому два concurrent redeem не могут оба завершиться успешно;
долгий вызов Document Store не удерживает блокировку БД.

В v1 bundle передает неизмененные байты версии: UTF-8 для текста и base64
для binary. OCR, extraction, chunking и другие трансформации в v1 не входят. Адаптер
может загрузить байты provider как file, но не меняет их до фиксации hash.

Если ответ bundle потерян после consume до фиксации accepted receipt,
использованная capability остается неизменной с `used_at`. Director может
выдать новую capability на тот же immutable context, но только до accepted
receipt и provider dispatch. Еще не использованная capability перед заменой
отзывается.

## 7. Канонические хеши

Все хеши имеют вид `sha256:<64 lowercase hex>`. JSON канонизируется по
RFC 8785 (JCS), затем SHA-256 считается по UTF-8 bytes.

### `context_set_hash`

Канонический manifest:

```json
{
  "version": 1,
  "agent_run_id": "00000000-0000-0000-0000-000000000000",
  "project_id": "00000000-0000-0000-0000-000000000000",
  "items": [
    {
      "position": 1,
      "memory_object_id": "00000000-0000-0000-0000-000000000000",
      "document_version_id": "00000000-0000-0000-0000-000000000000",
      "file_name": "architecture.md",
      "media_type": "text/markdown",
      "size_bytes": 1024,
      "content_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "sensitivity_level": "internal",
      "access_reason": "Основной архитектурный контекст"
    }
  ]
}
```

`items` сортируются по `position`. Порядок является частью входа AI и не может
восстанавливаться по случайному SQL order.

### `request_fingerprint`

Хеш версионированного envelope содержит run, task, project, provider, model,
`agent_type`, purpose, instructions, deployment class, data profile version,
`origin_request_id`, `context_set_hash`, `dispatched_at` и `deadline_at`.
Capability token в fingerprint не входит, поэтому его можно безопасно
перевыдать до provider dispatch.

Точный канонический объект v1 состоит из path-поля `agent_run_id` и всех полей
execute body, кроме самого `request_fingerprint`. Поэтому наличие optional-поля
и его значение различаются: отсутствующее поле, `null` и пустая строка дают
разные fingerprints. HTTP ingress не должен применять coercion к этому envelope.
Gateway сам канонизирует path `agent_run_id` и execute body и сравнивает
полученный хеш с `request_fingerprint`; доверять готовому полю без пересчета
нельзя.

### `event_hash`

Хеш канонического event без поля `event_hash`. Он позволяет Director отличить
безопасный retry от подмены уже использованного `event_id`. Director
пересчитывает его до проверки idempotency и применения side effects.

### Content hashes

`ContextItem.content_hash` и `size_bytes` относятся к исходным байтам версии до
base64. `GatewayResult.content_hash` и `size_bytes` считаются по точным UTF-8
байтам поля `content`. Director пересчитывает их до записи в Document Store.

## 8. Provider adapter

Адаптер получает только:

- provider/model и версию профиля обработки данных;
- purpose и instructions;
- ordered context items;
- deadline и размерные лимиты;
- correlation IDs, но не service/capability tokens.

Адаптер возвращает:

- только final answer;
- normalized `content_type`, `finish_reason` и usage;
- provider request ID, если провайдер его выдает;
- либо одну ошибку из каталога Gateway.

Hidden chain-of-thought, raw provider traces, request/response headers и provider body не
возвращаются Director и не попадают в Audit Log.

## 9. Event order и atomicity

Событие `agent_run.started` переводит SQL-статус `queued` в `running`.
Допустимы следующие последовательности событий и статусов:

```text
queued -> started -> completed
queued -> started -> failed
queued -> failed
queued -> cancelled
queued -> started -> cancelled
```

Прямой `queued -> failed` используется только для ошибки admission или context,
возникшей до принятого `started`. Для provider и normalization failure запуск
уже должен быть в `running`.

Gateway отправляет только один terminal event. Для `failed` и `cancelled`
Director применяет status и audit event одной SQL-транзакцией. Для `completed`
нельзя изображать общую транзакцию PostgreSQL и Document Store, поэтому
используется staged pattern:

1. Director пересчитывает event/content hashes и предварительно проверяет run,
   fingerprint и idempotency.
2. Content записывается в Document Store идемпотентно по детерминированному
   временному ключу `agent-results/{agent_run_id}/{content_hash}`.
3. В одной SQL-транзакции Director блокирует run, повторяет проверки, вставляет
   `audit_event` с `id = event_id` и `event_hash` в metadata, создает
   `agent_run_result` с storage URI и inherited sensitivity и меняет status.
4. `204` отправляется только после SQL commit. Staging object без связанной
   строки БД считается orphan и удаляется фоновым TTL cleanup.

Повторный `event_id` с тем же `event_hash` не повторяет side effects. Тот же ID
с другим hash создает отдельный security audit event с новым ID и возвращает
`409`.

## 10. Retry policy

| Фаза | Автоповтор | Правило |
| --- | --- | --- |
| `execute` без receipt | да | Тот же run, fingerprint и idempotency key; accepted run возвращает сохраненную receipt |
| Context redeem до consume | да | Та же capability |
| Context redeem после uncertain delivery | только до accepted receipt | Новая capability, тот же fingerprint |
| `started`/terminal event без `204` | да | Те же event ID и hash |
| Provider rate limit до acceptance | да | Только если provider доказывает, что request не принят |
| Timeout или recovery с unknown provider outcome | нет | `provider_outcome_unknown`; для повтора новый run |
| Смена provider/model | нет | Новый run и новая Auth/RBAC-проверка |

Retry использует exponential backoff с jitter и bounded attempts. Точные лимиты —
deployment config, а не часть бизнес-контракта.

## 11. Cancellation

`cancel` идемпотентен и best effort:

1. До provider call Gateway не вызывает provider и сразу шлет `cancelled`.
2. Во время provider call Gateway использует provider cancellation, если она есть.
3. Если provider не поддерживает cancel, Gateway игнорирует поздний ответ и
   шлет `cancelled`.
4. Director переводит run в `cancelled` только по terminal event.

Первый принятый `reason_code` остается причиной отмены. Повторный cancel с
другой причиной не меняет terminal semantics и возвращает текущую receipt.

Достижение `deadline_at` до terminal result эквивалентно cancel с
`reason_code = deadline_exceeded`. Доставка уже созданного terminal event
продолжается и после execution deadline до event-delivery TTL.

Поздний completed/failed event после accepted cancelled event отвергается как
out-of-order и не создает result.

## 12. Result и sensitivity

Gateway result:

- содержит только final content;
- имеет `content_hash` и byte size;
- в v1 имеет sensitivity, точно равный максимальному уровню context bundle;
- сохраняется Director сначала как временный `agent_run_result`;
- становится `memory_object` только после отдельного user confirmation.

Director проверяет content hash, size, inherited sensitivity и terminal status до
persistence. Gateway не получает `memory_object.create` или `ai_result.save`.

## 13. Error taxonomy

Внутренняя transport-ошибка имеет `code`, безопасное `message`, `retryable`,
`details` и `request_id`. Terminal Gateway failure дополнительно фиксирует phase:

- `admission` — protocol, fingerprint, unsupported adapter;
- `context` — capability, bundle, hash и лимиты;
- `provider` — rate limit, timeout, unavailable, rejected;
- `normalization` — недопустимый или слишком большой provider output;
- `delivery` — доставка event Director.

`message` и `details` никогда не содержат prompt, context, result, capability, API key или
raw provider response.

`provider_outcome_unknown` означает, что Gateway восстановил durable-фазу
`provider_calling`, но не может доказать, был ли provider request принят. Такой
вызов не повторяется, failure имеет `retryable = false`, а новая попытка требует
нового agent run.

## 14. Audit и observability

Минимальные audit actions:

- `agent_run.dispatched`;
- `agent_context.redeemed`;
- `agent_run.started`;
- `agent_run.completed`;
- `agent_run.failed`;
- `agent_run.cancelled`;
- `agent_gateway.event_conflict`;
- `agent_capability.reissued`.

Безопасные metrics:

- accepted/running/terminal counts;
- queue/admission/provider/delivery latency;
- result/context byte sizes;
- provider status class и normalized failure code;
- token usage, если provider его возвращает;
- retries и event conflicts.

IDs проекта и документов не используются как неограниченные metric labels.
Логи содержат IDs, phases, durations и sizes, но не content.

## 15. Не входит в v1

- UI и публичная аутентификация;
- выбор контекста или provider;
- token streaming в UI;
- tool execution и function calling;
- shell, browser, Git и repository access;
- provider fallback и гонка нескольких models;
- multi-agent orchestration;
- OCR, parsing, chunking и retrieval;
- долгосрочное хранение prompt/context/result в Gateway;
- billing и квоты провайдера.

## 16. Соответствие другим слоям

- [Director API v1](director-api-v1.md) создает и показывает agent run пользователю.
- [Auth/RBAC v1](auth-rbac-v1.md) определяет capability, sensitivity и provider policy.
- [PostgreSQL schema v1](postgresql-schema-v1.md) фиксирует context, capability,
  result и status transitions.
- [Архитектурные запреты](architecture-guardrails.md) не позволяют Gateway обойти
  Director или самому выбрать документ.

## 17. Критерии готовности

1. Дубль `execute` не создает второй provider call.
2. Другой fingerprint для run отклоняется.
3. Capability не выдает ни одной лишней версии и не используется дважды.
4. Bundle order, content hashes и max sensitivity проверяются до provider call.
5. Provider не вызывается до accepted `started` event.
6. Ровно один terminal event меняет состояние run.
7. Дубль event не повторяет persistence и audit side effects.
8. После cancel поздний provider result не сохраняется.
9. Context, result, capability и provider body отсутствуют в логах и Audit Log.
10. Замена adapter не меняет Director API, SQL модель и корпоративную память.
11. Recovery из `provider_calling` не создает второй provider call.
12. Каждый protected вызов Director/Gateway использует HTTPS, проверенный
    client certificate, точную service identity и bearer.
