# Director API v1

Сценарное описание центрального API «Дирижёра» для первого MVP. API является
единственной точкой входа для UI и внешних клиентов. UI, AI-агенты и
интеграционные адаптеры не должны обращаться к корпоративной памяти напрямую.

Нормативный контракт путей, DTO и кодов ответа зафиксирован в
[`api/openapi-v1.yaml`](../../api/openapi-v1.yaml). Этот документ объясняет сценарии
и архитектурную мотивацию.

## Принципы API

1. Каждый запрос проходит через Auth/RBAC.
2. Каждая чувствительная операция создает `audit_event`.
3. AI-агент получает только явно выбранный и разрешенный контекст.
4. Результат AI сохраняется отдельно от утвержденных решений.
5. Все долгие операции представлены как `task` или `agent_run`.
6. Ошибки возвращаются в едином формате.
7. API не содержит жесткой зависимости от конкретного AI-провайдера.

## Базовые соглашения

Версия API:

```text
/api/v1
```

Формат данных:

```text
application/json
```

Идентификаторы:

```text
UUID
```

Время:

```text
ISO 8601 UTC
```

Обязательные служебные заголовки:

```text
Authorization: Bearer <token>
X-Request-Id: <uuid>
```

Browser UI может вместо header использовать Secure HttpOnly
`__Host-dirizhor_session` cookie. Для cookie-authenticated mutations обязателен
точный HTTPS same-origin `Origin`; `X-Request-Id` остаётся обязательным.

`POST /auth/sessions` не требует готовой session: он принимает local
credentials и возвращает bearer. OIDC start/callback также публичны и
генерируют `X-Request-Id`, если обычная browser navigation его не передала.

`X-Request-Id` используется для связи API-запроса, фоновых операций и
`audit_event`.

## Единый формат ошибки

```json
{
  "error": {
    "code": "access_denied",
    "message": "Access denied.",
    "details": {},
    "request_id": "00000000-0000-0000-0000-000000000000"
  }
}
```

Базовые коды ошибок:

- `validation_error`;
- `unauthorized`;
- `access_denied`;
- `not_found`;
- `conflict`;
- `requires_confirmation`;
- `task_not_ready`;
- `agent_route_unavailable`;
- `session_not_available`;
- `csrf_check_failed`;
- `oidc_transaction_invalid`;
- `oidc_authentication_failed`;
- `oidc_provider_unavailable`;
- `identity_not_provisioned`;
- `agent_run_failed`;
- `payload_too_large`;
- `rate_limited`;
- `internal_error`.

## Общие DTO

### Pagination

```json
{
  "limit": 50,
  "cursor": "opaque-cursor"
}
```

### PageResponse

```json
{
  "items": [],
  "next_cursor": "opaque-cursor"
}
```

### RelationshipRef

```json
{
  "target_type": "memory_object",
  "target_id": "00000000-0000-0000-0000-000000000000",
  "relation_type": "references",
  "description": "Источник для вывода"
}
```

## Authentication

### Начать корпоративный вход

```text
GET /api/v1/auth/oidc/start
```

Endpoint создаёт короткоживущую server-side login transaction с уникальными
state, nonce и PKCE S256, устанавливает Secure HttpOnly
`__Host-dirizhor_oidc` cookie и отвечает `302` на authorization endpoint IdP.
Callback URL фиксирован runtime-конфигурацией; клиентский `return_to` не
принимается.

### Завершить корпоративный вход

```text
GET /api/v1/auth/oidc/callback?code=...&state=...
```

Director атомарно потребляет browser-bound transaction, проверяет ответ IdP и
сопоставляет точный `(issuer, sub)` и ожидаемый provider code с заранее provisioned
`user_identities`. Email для linking не используется. Успех создаёт внутреннюю
hash-only Director session, устанавливает `__Host-dirizhor_session` и отвечает
`303` на fixed same-origin UI URL. IdP tokens и Director bearer в redirect не
попадают.

Отказ возвращает UI только безопасный `auth_error` code. Unknown subject не
создаёт пользователя. Полный security contract зафиксирован в
[OIDC/SSO boundary v1](oidc-sso-v1.md).

### Создать локальную сессию

```text
POST /api/v1/auth/sessions
```

Endpoint регистрируется только при
`DIRECTOR_LOCAL_PASSWORD_LOGIN_ENABLED=true`. Он принимает `login` и `password`,
проверяет local identity с versioned scrypt и возвращает 256-bit opaque bearer
ровно один раз. В PostgreSQL сохраняется только SHA-256 hash bearer.

Неверный пароль, неизвестный login и inactive user возвращают одинаковый
`401 unauthorized`. Ответ `201` содержит `Cache-Control: no-store` и
`Pragma: no-cache`. Успех и отказ создают соответственно
`authentication.succeeded` или `authentication.failed`.

### Отозвать текущую сессию

```text
DELETE /api/v1/auth/sessions/current
```

Endpoint требует текущий session bearer. Отзыв и `session.revoked` audit
выполняются одной SQL-транзакцией; следующий запрос с этим bearer получает
`401` без ожидания истечения TTL.

## Projects

### Создать проект

```text
POST /api/v1/projects
```

Запрос:

```json
{
  "title": "Дирижёр",
  "description": "Корпоративная AI-платформа"
}
```

Ответ:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "title": "Дирижёр",
  "description": "Корпоративная AI-платформа",
  "status": "active",
  "owner_user_id": "00000000-0000-0000-0000-000000000000",
  "created_at": "2026-08-09T00:00:00Z",
  "updated_at": "2026-08-09T00:00:00Z"
}
```

Audit:

- `project.created`.

### Получить список проектов

```text
GET /api/v1/projects?limit=50&cursor=<cursor>
```

Возвращает только проекты, доступные пользователю.

### Получить проект

```text
GET /api/v1/projects/{project_id}
```

## Topics

### Создать тему

```text
POST /api/v1/projects/{project_id}/topics
```

Запрос:

```json
{
  "title": "Корпоративная память",
  "summary": "Модель памяти и реестра",
  "parent_topic_id": null
}
```

Audit:

- `topic.created`.

### Получить темы проекта

```text
GET /api/v1/projects/{project_id}/topics
```

## Memory Objects

### Создать объект памяти без файла

Используется для текстовых заметок, протоколов и результатов исследований.
`decision` и `ai_result` создаются специализированными endpoint, чтобы
карточка памяти и типизированная запись возникали атомарно. Endpoint для
`open_question` не входит в API v1.

```text
POST /api/v1/memory-objects
```

Запрос:

```json
{
  "project_id": "00000000-0000-0000-0000-000000000000",
  "topic_id": "00000000-0000-0000-0000-000000000000",
  "type": "note",
  "title": "Принцип сменяемости AI-моделей",
  "summary": "AI-провайдер не должен быть критической зависимостью",
  "keywords": ["AI", "модульность", "архитектура"],
  "sensitivity_level": "internal"
}
```

Ответ:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "type": "note",
  "title": "Принцип сменяемости AI-моделей",
  "project_id": "00000000-0000-0000-0000-000000000000",
  "topic_id": "00000000-0000-0000-0000-000000000000",
  "current_version_id": null,
  "author_user_id": "00000000-0000-0000-0000-000000000000",
  "summary": "AI-провайдер не должен быть критической зависимостью",
  "keywords": ["AI", "модульность", "архитектура"],
  "status": "active",
  "sensitivity_level": "internal",
  "created_at": "2026-08-09T00:00:00Z",
  "updated_at": "2026-08-09T00:00:00Z"
}
```

Audit:

- `memory_object.created`.

### Загрузить документ

```text
POST /api/v1/memory-objects:upload
```

MVP-вариант может принимать `multipart/form-data`. В дальнейшем желательно
разделить получение upload URL и подтверждение загрузки.

Поля формы:

- `project_id`;
- `topic_id`;
- `type`;
- `title`;
- `summary`;
- `keywords`;
- `sensitivity_level`;
- `file`.

Результат:

- создается `memory_object`;
- создается первая `document_version`;
- файл сохраняется в Document Store;
- фиксируются audit-события.

Audit:

- `memory_object.created`;
- `document_version.created`.

### Получить карточку объекта памяти

```text
GET /api/v1/memory-objects/{memory_object_id}
```

Карточка требует `memory_object.read`. Текущая версия включается в ответ только
при наличии отдельного `document_version.read`.

Audit:

- `memory_object.read` со ссылкой на `allow` decision для каждого чтения.

### Поиск по реестру памяти

```text
GET /api/v1/memory-objects/search?project_id=<id>&q=<text>&type=document&limit=50
```

Поиск работает по карточкам реестра: названию, краткому содержанию, ключевым
словам, теме, проекту и связям. Полный текст документов на этом этапе агенту не
передается.

Ответ:

```json
{
  "items": [
    {
      "id": "00000000-0000-0000-0000-000000000000",
      "type": "document",
      "title": "Контекст проекта Дирижёр",
      "summary": "Базовая архитектура",
      "keywords": ["Дирижёр", "память", "AI"],
      "project_id": "00000000-0000-0000-0000-000000000000",
      "topic_id": "00000000-0000-0000-0000-000000000000",
      "sensitivity_level": "internal",
      "status": "active",
      "updated_at": "2026-08-09T00:00:00Z"
    }
  ],
  "next_cursor": null
}
```

### Создать новую версию документа

```text
POST /api/v1/memory-objects/{memory_object_id}/versions
```

MVP-вариант может принимать `multipart/form-data`.

Поля формы:

- `change_summary`;
- `file`.

Audit:

- `document_version.created`;
- `memory_object.updated`.

## Tasks

### Создать задачу

```text
POST /api/v1/tasks
```

Запрос:

```json
{
  "project_id": "00000000-0000-0000-0000-000000000000",
  "title": "Оценить архитектуру памяти",
  "user_request": "Изучи документы и предложи следующую спецификацию"
}
```

Ответ:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "project_id": "00000000-0000-0000-0000-000000000000",
  "created_by_user_id": "00000000-0000-0000-0000-000000000000",
  "title": "Оценить архитектуру памяти",
  "user_request": "Изучи документы и предложи следующую спецификацию",
  "status": "created",
  "created_at": "2026-08-09T00:00:00Z",
  "updated_at": "2026-08-09T00:00:00Z"
}
```

Audit:

- `task.created`.

### Подобрать контекст для задачи

```text
POST /api/v1/tasks/{task_id}/context:search
```

Запрос:

```json
{
  "query": "архитектура корпоративной памяти",
  "types": ["document", "decision", "ai_result"],
  "limit": 20
}
```

`project_id` берется из задачи по `task_id` и не принимается отдельным полем
клиента.

Ответ:

```json
{
  "task_id": "00000000-0000-0000-0000-000000000000",
  "candidates": [
    {
      "memory_object_id": "00000000-0000-0000-0000-000000000000",
      "title": "Модель корпоративной памяти",
      "summary": "Реестр, документы, связи",
      "reason": "Совпадение по теме и ключевым словам",
      "sensitivity_level": "internal"
    }
  ]
}
```

Важно: этот endpoint не передает полный текст документов агенту.

### Получить задачу

```text
GET /api/v1/tasks/{task_id}
```

### Получить историю задачи

```text
GET /api/v1/tasks/{task_id}/timeline
```

Возвращает связанные audit-события, agent runs, сохраненные результаты и
решения, доступные пользователю.

## Agent Runs

### Запустить агента на выбранном контексте

```text
POST /api/v1/tasks/{task_id}/agent-runs
```

Запрос:

```json
{
  "agent_type": "chatgpt",
  "purpose": "architecture_review",
  "instructions": "Оцени архитектуру и предложи следующий слой спецификации",
  "context": [
    {
      "memory_object_id": "00000000-0000-0000-0000-000000000000",
      "document_version_id": "00000000-0000-0000-0000-000000000000",
      "access_reason": "Основной документ архитектуры"
    }
  ]
}
```

Поведение:

1. Director API проверяет права пользователя.
2. По `agent_type` Director выбирает точный серверный маршрут
   `provider/model/deployment_class/provider_data_profile_version`. Клиент не
   может передать или переопределить provider; неизвестный `agent_type` получает
   `agent_route_unavailable`.
3. Director API проверяет допустимость передачи каждого объекта AI выбранному
   provider.
4. Auth/RBAC сам определяет, требуется ли confirmation. Клиент не может
   отключить это требование параметром запроса.
5. При необходимости Director API создает `agent_run` со статусом
   `awaiting_user_confirmation`, замораживает набор версий и возвращает
   `requires_confirmation` с серверным `confirmation_id`.
6. Если confirmation не требуется или уже подтвержден, Director создает
   ordered `agent_run_context`, вычисляет `context_set_hash` и фиксирует
   dispatch envelope с `request_fingerprint` и deadline.
7. Auth/RBAC выдает Agent Gateway короткоживущую capability на точный набор
   версий с единственным action `context_bundle.read`.
8. Director вызывает внутренний `execute` Agent Gateway.
9. Gateway одноразово redeem-ит capability; Director получает из Document
   Store только зафиксированные версии и возвращает ordered context bundle.
10. Принятое событие `agent_run.started` переводит запуск из `queued` в
   `running`, после чего Gateway вызывает выбранный provider.

Идемпотентный retry использует маршрут из уже созданного `agent_run`, даже если
startup-конфигурация после первого dispatch была изменена. Это сохраняет
provider boundary и исходный request fingerprint.

Пример ответа, когда требуется confirmation:

```json
{
  "error": {
    "code": "requires_confirmation",
    "message": "Операция требует подтверждения пользователя",
    "details": {
      "confirmation_id": "00000000-0000-0000-0000-000000000000",
      "target_type": "agent_run",
      "target_id": "00000000-0000-0000-0000-000000000000",
      "payload_hash": "sha256:...",
      "expires_at": "2026-08-09T00:15:00Z"
    },
    "request_id": "00000000-0000-0000-0000-000000000000"
  }
}
```

Ответ:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "task_id": "00000000-0000-0000-0000-000000000000",
  "project_id": "00000000-0000-0000-0000-000000000000",
  "agent_type": "chatgpt",
  "provider": "openai",
  "model": null,
  "purpose": "architecture_review",
  "status": "queued",
  "requested_by_user_id": "00000000-0000-0000-0000-000000000000",
  "provider_data_profile_version": "openai-enterprise-v1",
  "deployment_class": "external",
  "context_set_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "origin_request_id": "00000000-0000-0000-0000-000000000001",
  "request_fingerprint": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "dispatched_at": "2026-08-09T00:00:01Z",
  "deadline_at": "2026-08-09T00:10:01Z",
  "created_at": "2026-08-09T00:00:00Z"
}
```

Audit:

- `agent_run.dispatched`;
- `memory_object.read`;
- `agent_context.attached`;
- `agent_context.redeemed`.

### Получить запуск агента

```text
GET /api/v1/agent-runs/{agent_run_id}
```

Возвращает технические метаданные без prompt, исходного контекста и текста
AI-результата.

### Получить результат запуска

```text
GET /api/v1/agent-runs/{agent_run_id}/result
```

Если запуск еще не завершен, возвращается `task_not_ready`.
Для чтения текста требуются права на все версии исходного контекста, включая
дополнительные permissions для `confidential` и `restricted`.

### Сохранить результат AI в память

```text
POST /api/v1/agent-runs/{agent_run_id}/result:save
```

Запрос:

```json
{
  "title": "Оценка архитектуры памяти",
  "summary": "AI-результат по архитектурному черновику",
  "topic_id": "00000000-0000-0000-0000-000000000000",
  "keywords": ["архитектура", "ревью", "AI"],
  "relationships": [
    {
      "target_type": "memory_object",
      "target_id": "00000000-0000-0000-0000-000000000000",
      "relation_type": "derived_from",
      "description": "AI-результат основан на этом документе"
    }
  ]
}
```

Результат:

- создается `memory_object` типа `ai_result`;
- создается версия с текстом результата;
- создаются связи с источниками;
- фиксируется audit-событие.

Audit:

- `ai_result.saved`;
- `memory_object.created`;
- `document_version.created`.

## Decisions

### Создать решение

```text
POST /api/v1/decisions
```

Запрос:

```json
{
  "project_id": "00000000-0000-0000-0000-000000000000",
  "topic_id": "00000000-0000-0000-0000-000000000000",
  "title": "Использовать Дирижёра как единую точку доступа",
  "decision_text": "AI-агенты не получают прямой доступ к корпоративной памяти.",
  "rationale": "Это сохраняет контроль доступа, журналирование и независимость памяти.",
  "status": "approved",
  "relationships": [
    {
      "target_type": "memory_object",
      "target_id": "00000000-0000-0000-0000-000000000000",
      "relation_type": "derived_from",
      "description": "Основание решения"
    }
  ]
}
```

Правило:

- `approved`-решение может создать только пользователь с соответствующим правом;
- AI-агент не может создать `approved`-решение от своего имени.

Audit:

- `decision.created`;
- `decision.approved`, если статус сразу `approved`.

### Получить решение

```text
GET /api/v1/decisions/{decision_id}
```

### Заменить решение новым

```text
POST /api/v1/decisions/{decision_id}:supersede
```

Запрос:

```json
{
  "title": "Уточненное решение",
  "decision_text": "Новый текст решения",
  "rationale": "Причина замены",
  "relationships": []
}
```

Результат:

- старое решение получает статус `superseded`;
- новое решение создается со связью `supersedes`;
- оба действия журналируются.

## Audit

### Получить журнал объекта

```text
GET /api/v1/audit-events?target_type=memory_object&target_id=<id>
```

Возвращает только события, которые пользователь имеет право видеть.
`target_type` и `target_id` передаются только вместе.

### Получить журнал задачи

```text
GET /api/v1/audit-events?task_id=<id>
```

## Confirmations

Некоторые операции должны требовать явного подтверждения пользователя:

- передача чувствительного документа AI;
- массовая передача контекста;
- сохранение результата AI;
- утверждение решения;
- замена утвержденного решения.

Необходимость confirmation определяет Auth/RBAC, а не UI. Сначала защищенная
операция проходит обычную проверку permission и scope. Если требуется
подтверждение, Director API замораживает существенные параметры операции,
вычисляет `payload_hash` и возвращает ошибку `requires_confirmation` с
`confirmation_id`. Confirmation не может предоставить отсутствующее право.
Замороженные параметры хранятся во внутреннем `confirmations.frozen_payload`, не
возвращаются клиенту и не попадают в audit metadata.

### Получить подтверждение

Очередь подтверждений проекта для UI:

```text
GET /api/v1/confirmations?project_id={project_id}&status=pending&limit=50&cursor={cursor}
```

`status` по умолчанию равен `pending`. Ответ содержит `items` и непрозрачный
`next_cursor`; cursor привязан к пользователю, проекту и статусу. Пагинация идет
по `(created_at DESC, id DESC)`. Каждая страница требует `project.read` и
`confirmation.read` и фиксируется отдельными связанными `allow` decision и
`access.allowed`. Внутренний `frozen_payload` в ответ не включается.

```text
GET /api/v1/confirmations/{confirmation_id}
```

Confirmation создается Director API как часть защищенной операции. UI не создает
его из произвольных полей. Endpoint возвращает только запись, доступную текущему
пользователю.

Ответ:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "operation": "agent_context_share",
  "target_type": "agent_run",
  "target_id": "00000000-0000-0000-0000-000000000000",
  "project_id": "00000000-0000-0000-0000-000000000000",
  "requested_by_user_id": "00000000-0000-0000-0000-000000000000",
  "authorization_decision_id": "00000000-0000-0000-0000-000000000000",
  "request_id": "00000000-0000-0000-0000-000000000000",
  "status": "pending",
  "payload_hash": "sha256:...",
  "summary": "Передать 3 внутренних документа внешнему AI",
  "created_at": "2026-08-09T00:00:00Z",
  "expires_at": "2026-08-09T00:15:00Z"
}
```

### Подтвердить операцию

```text
POST /api/v1/confirmations/{confirmation_id}:approve
```

Перед approval Director API повторно проверяет права подтверждающего и
совпадение текущего `payload_hash`. Успешный approval атомарно продолжает
защищенную операцию: например, переводит тот же `agent_run` из
`awaiting_user_confirmation` в `queued`. После запуска целевой операции
confirmation получает статус `consumed`; повторять исходный запрос не нужно.

### Отклонить операцию

```text
POST /api/v1/confirmations/{confirmation_id}:reject
```

Отклонение отменяет связанную ожидающую операцию. Для `agent_run` статус
переходит из `awaiting_user_confirmation` в `cancelled`.

## Статусы задач

`task.status`:

- `created`;
- `planning`;
- `awaiting_context`;
- `awaiting_user_confirmation`;
- `running_agent`;
- `reviewing`;
- `completed`;
- `failed`;
- `cancelled`.

Разрешенные переходы MVP:

```text
created -> planning
created -> awaiting_context
planning -> awaiting_context
planning -> failed
planning -> cancelled
awaiting_context -> awaiting_user_confirmation
awaiting_context -> running_agent
awaiting_context -> failed
awaiting_user_confirmation -> running_agent
awaiting_user_confirmation -> failed
running_agent -> reviewing
reviewing -> completed
created -> cancelled
awaiting_context -> cancelled
awaiting_user_confirmation -> cancelled
running_agent -> cancelled
running_agent -> failed
reviewing -> cancelled
reviewing -> failed
```

## Статусы agent_run

`agent_run.status`:

- `queued`;
- `running`;
- `completed`;
- `failed`;
- `cancelled`;
- `awaiting_user_confirmation`.

Разрешенные переходы MVP:

```text
queued -> running
queued -> failed
awaiting_user_confirmation -> queued
awaiting_user_confirmation -> cancelled
running -> completed
running -> failed
running -> cancelled
```

## Минимальные права MVP

Права называются действиями, а не ролями. Роли могут быть собраны из этих прав.
Полный каталог, области действия и базовая матрица ролей определены в
[Auth/RBAC v1](auth-rbac-v1.md). Список ниже фиксирует только права, напрямую
упомянутые в текущих endpoint-сценариях Director API.

- `project.read`;
- `project.create`;
- `topic.read`;
- `topic.create`;
- `memory_object.search`;
- `memory_object.read`;
- `memory_object.read_confidential`;
- `memory_object.read_restricted`;
- `memory_object.create`;
- `memory_object.update`;
- `document_version.read`;
- `document_version.create`;
- `task.create`;
- `task.read`;
- `agent_run.create`;
- `agent_run.read`;
- `agent_context.share`;
- `agent_context.share_confidential`;
- `agent_provider.use_external`;
- `ai_result.save`;
- `decision.read`;
- `decision.create`;
- `decision.approve`;
- `decision.supersede`;
- `confirmation.read`;
- `confirmation.approve`;
- `confirmation.reject`;
- `audit_event.read`;

## Минимальный список audit-событий MVP

- `project.created`;
- `topic.created`;
- `task.created`;
- `memory_object.created`;
- `memory_object.read`;
- `memory_object.updated`;
- `document_version.created`;
- `agent_run.dispatched`;
- `agent_run.started`;
- `agent_run.completed`;
- `agent_run.failed`;
- `agent_context.attached`;
- `agent_context.redeemed`;
- `ai_result.saved`;
- `decision.created`;
- `decision.approved`;
- `decision.superseded`;
- `access.allowed`;
- `access.denied`;
- `confirmation.created`;
- `confirmation.approved`;
- `confirmation.rejected`;
- `confirmation.consumed`.

## Статус reference-реализации

Исполнимый [OpenAPI 3.1 v1](openapi-v1.md), внутренний
[Agent Gateway Protocol v1](agent-gateway-v1.md), reference Gateway и
[reference Director](../../director/reference/README.md) созданы.
Reference runtime реализует public upload, Memory Registry read/search, task
create/read/context search/timeline, agent-run create/read, temporary result
read, result save и confirmation get/approve/reject. Dispatch фиксирует ordered
context и одноразовую capability; external и bulk policy могут остановить его
на frozen confirmation.
`ai_result_save` всегда требует отдельного confirmation, после которого одна
SQL-транзакция создаёт `memory_object`, первую version, relationships, result
link, task completion и audit events. Сквозной тест проходит весь путь через
Reference Gateway без ручного SQL seed операционных сущностей.

Reference runtime также выбирает точный startup-configured маршрут для каждого
`agent_type`. Public bearer проверяется как opaque PostgreSQL session: в БД
хранится только SHA-256 hash, а expired/revoked session или inactive user
немедленно получают одинаковый `401`.

Local password session issuance и отзыв текущей session реализованы с scrypt,
hash-only storage и атомарным audit. Permission и project-policy deny для всех
реализованных public business endpoints создают immutable
`authorization_decision` и связанный `access.denied`. Concealed permission deny
сохраняет публичный `404`, а project scope для audit определяется сервером.

Успешные immediate/replay public business flows создают immutable `allow`
decision в той же SQL-транзакции. Direct write-события ссылаются на него
напрямую; read/search/replay используют metadata-only `access.allowed`, а чтение
memory object — связанный `memory_object.read`. Search audit хранит hash
нормализованного запроса, но не сам запрос. Confirmation lifecycle и события
защищённой операции продолжают ссылаться на исходный `require_confirmation`, а
текущий approve/reject получает отдельный `allow`.

Reference confirmation UI реализован отдельным Vite-клиентом и использует
OIDC-first вход с HttpOnly Director session cookie. Refresh, multi-provider/SAML,
JIT provisioning/linking API и IdP logout остаются отдельной production-границей.

Отдельная спецификация [Auth/RBAC v1](auth-rbac-v1.md) уже создана.
Исполнимая [PostgreSQL schema v1](postgresql-schema-v1.md) также создана.
