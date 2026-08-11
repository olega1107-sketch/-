# PostgreSQL schema v1

Этот документ сопровождает исполнимую схему
[`db/schema-v1.sql`](../../db/schema-v1.sql) для первого MVP «Дирижёра».
Схема переводит концептуальную модель корпоративной памяти и Auth/RBAC в
конкретные таблицы, внешние ключи, индексы и триггеры PostgreSQL.

## 1. Техническая база

- PostgreSQL 15 или новее;
- отдельная схема БД `dirizhor`;
- UUID через `pgcrypto.gen_random_uuid()`;
- время в `timestamptz`;
- содержимое файлов и ответов AI хранится в Document Store, а в PostgreSQL —
  URI, хеши, метаданные и связи;
- SQL рассчитан на однократное применение к пустой базе.

## 2. Группы таблиц

### Идентичность и RBAC

- `app_users`;
- `user_identities`;
- `user_sessions`;
- `oidc_login_transactions`;
- `service_principals`;
- `permissions`;
- `roles`;
- `role_permissions`;
- `role_assignments`;
- `project_ai_policies`.

### Корпоративная память

- `projects`;
- `topics`;
- `memory_objects`;
- `document_versions`;
- `decisions`;
- `open_questions`;
- `relationships`.

### Задачи и AI

- `tasks`;
- `agent_runs`;
- `agent_run_contexts`;
- `agent_run_results`;
- `agent_capabilities`;
- `agent_capability_resources`.

### Контроль и история

- `authorization_decisions`;
- `confirmations`;
- `audit_events`.

## 3. Уточнения исходной модели

SQL-проектирование выявило несколько недостающих технических сущностей.

### `user_identities` и `user_sessions`

Пользовательская карточка сама по себе не позволяет проверить способ входа,
отозвать сессию или связать несколько способов аутентификации. Эти таблицы
разделяют бизнес-пользователя, учетную идентичность и активную сессию. Сырые
пароли и session tokens в БД не хранятся; `user_sessions.session_token_hash`
защищён SQL-проверкой формата `sha256:<64 hex>`. Partial unique index разрешает
не более одной local identity на пользователя, не ограничивая внешние identity.
Внешняя identity хранит точный HTTPS `provider_issuer`; partial unique index на
`(provider_issuer, provider_subject)` фиксирует нормативную OIDC-пару
`(issuer, sub)`. Reference local password хранится как versioned scrypt hash с
отдельной солью.

### `oidc_login_transactions`

OIDC callback требует восстановить transaction-specific `nonce` и PKCE
`code_verifier`, но браузеру нельзя доверять их хранение. Таблица связывает
одноразовую попытку с hash случайного HttpOnly browser token и hash `state`,
задаёт TTL и atomic consume. После consume `nonce` и verifier зануляются;
повтор callback не может выпустить вторую session. Access/refresh/ID tokens IdP
в таблице не сохраняются.

### `authorization_decisions`

Каждый результат Auth/RBAC получает отдельный неизменяемый идентификатор. На него
ссылаются confirmations и audit events. Это позволяет доказать, почему операция
была разрешена, запрещена или остановлена для подтверждения. SQL требует хотя
бы один `reason_code` для каждого decision. Allow и связанный success/access
audit создаются в транзакции разрешённой операции; deny и связанный
`access.denied` — отдельной транзакцией после rollback запрещённой операции.

### Замороженный payload confirmation

`confirmations.frozen_payload` хранит канонические параметры отложенной операции.
Без них approval не мог бы атомарно продолжить `ai_result.save` и другие
операции без повторной отправки payload клиентом. Поле не выдается в API,
не копируется в audit metadata и защищается теми же мерами доступа, что и
остальная бизнес-база.

### `agent_run_results`

Ответ AI существует до того, как пользователь решит сохранить его в
корпоративную память. Таблица хранит URI, hash, `size_bytes`, media type,
sensitivity и срок жизни временного результата, а позже связывает его с
`memory_object` типа `ai_result`. Сам ответ остается в Document Store.

### Типизированные объекты памяти

`decisions` и `open_questions` имеют обязательный `memory_object_id`. Реестр
остается общей точкой поиска, а отдельные таблицы содержат специализированные
поля и жизненный цикл.

### Повторение `project_id`

В задачах, agent runs, контексте и capabilities `project_id` местами можно было
бы вычислить через другие таблицы. Он сохранен намеренно: составные внешние ключи
запрещают случайно связать документы и процессы разных проектов.

### Воспроизводимость AI-запуска

В `agent_runs` добавлены `instructions`, `deployment_class`, версия профиля
обработки данных провайдера, `context_set_hash`, `origin_request_id`,
`request_fingerprint`, `dispatched_at` и `deadline_at`. Без них невозможно
проверить, какие условия и какой точный dispatch породили результат.
Unique index на `origin_request_id` не даёт двум конкурентным retry создать
два run для одного исходного `X-Request-Id`.
`agent_run_contexts.position` фиксирует порядок входа, а
`agent_run_contexts.sensitivity_level` — классификацию каждого источника на
момент запуска. `agent_run_results.sensitivity_level` хранит максимальный
уровень этого набора.

## 4. Что гарантирует PostgreSQL

Схема запрещает или автоматически контролирует:

- ссылки между объектами разных проектов;
- смену типа и проекта существующего объекта памяти;
- пропуски и гонки в нумерации версий одного документа;
- изменение или удаление версии документа;
- перевод `current_version_id` назад;
- изменение набора `agent_run_context` после его фиксации;
- повторение или изменение позиции context item внутри одного run;
- переход или создание run в `queued`, `running` или `completed` без полного
  dispatch envelope;
- неверный sensitivity snapshot контекста или понижение уровня AI-результата;
- выдачу capability на версию вне замороженного контекста;
- выдачу capability не сервису `agent-gateway`, с другим action, без
  dispatch-ready run или за пределы deadline;
- повторное использование или изменение capability;
- изменение audit events и authorization decisions;
- изменение замороженного confirmation payload;
- недопустимые переходы task, agent run, decision и confirmation;
- изменение утвержденного решения, кроме перехода в `superseded`;
- создание проекта без автоматической роли `project_owner`;
- создание проекта без закрытой по умолчанию AI-policy;
- назначение роли в scope, не соответствующем типу роли;
- внешнюю AI-policy с максимальным уровнем `restricted`;
- физическое удаление основных объектов корпоративной памяти и процессов.

## 5. Что остается обязанностью Director API

База данных не заменяет Auth/RBAC и оркестратор. Director API обязан:

- аутентифицировать principal и проверять актуальную сессию;
- вычислять permissions по ролям, scope и сроку назначения;
- не позволять platform admin назначать себе проектную роль обычным путем;
- фильтровать поиск до подсчета количества и пагинации;
- проверять уровень чувствительности каждого объекта;
- повторно проверять права на замороженный контекст перед выдачей AI-результата;
- применять `project_ai_policy` и профиль обработки данных провайдера;
- вычислять `payload_hash` confirmation и `context_set_hash` agent run;
- формировать context positions без пропусков и проверять точное равенство
  capability resources замороженному набору;
- вычислять и атомарно фиксировать Gateway `request_fingerprint`, dispatch time
  и deadline;
- проверять право подтверждающего на целевую операцию;
- создавать audit event для чтений и чувствительных действий;
- не помещать prompt, документ, ответ AI или секрет в audit metadata;
- проводить понижение чувствительности только после confirmation;
- выполнять все PostgreSQL-части составной бизнес-операции одной транзакцией;
- писать файлы Document Store идемпотентно по детерминированному staging key и
  очищать orphan objects по TTL, не заявляя несуществующую cross-store
  транзакцию.

PostgreSQL Row-Level Security в v1 не включен. Приложение не должно выдавать
пользовательским клиентам учетные данные БД: доступ к таблицам идет только через
Director API и доверенные внутренние модули. RLS можно добавить вторым защитным
слоем после стабилизации API-контракта.

## 6. Транзакционные сценарии

Следующие операции должны выполняться атомарно:

1. Создание проекта, default AI-policy и назначения владельца.
2. Создание `memory_object`, сохранение файла и первой `document_version`.
3. Создание типизированного `decision` или `open_question` вместе с карточкой
   памяти.
4. Фиксация ordered agent run context, хешей и dispatch window, затем выдача
   capability.
5. Approval confirmation, запуск защищенной операции и перевод confirmation в
   `consumed`.
6. Сохранение AI-результата, создание версии, связей `derived_from` и обновление
   `agent_run_results.saved_memory_object_id`.
7. Замена решения: создание нового approved decision, перевод старого в
   `superseded` и создание связи.

Список описывает атомарность изменений PostgreSQL. Запись файла или AI-ответа в
Document Store выполняется до SQL commit как идемпотентная staged-операция.
Успешная запись без последующего commit не видна через Director API и удаляется
как orphan; двухфазный commit между хранилищами в v1 не вводится.

## 7. Применение

```bash
cd director/reference
pnpm db:checksums
pnpm db:migrate
pnpm db:status
```

Runner применяет `schema-v1.sql` как immutable baseline только к новой базе,
фиксирует checksum и сериализует запуск advisory lock. Существующая schema v1
проходит отдельный verified adoption. Каждое последующее изменение оформляется
фазами `expand -> backfill -> validate -> contract`; contract требует явного
флага и отдельного deployment window. Процедура описана в
[production migration runbook](../../db/production-migration-runbook.md).

## 8. Не входит в schema v1

- хранение файлов и полных AI-ответов;
- хранилище сырых паролей, API keys и приватных ключей;
- PostgreSQL RLS;
- полнотекстовый и векторный поиск;
- партиционирование Audit Log;
- автоматическая очистка временных AI-результатов;
- мультитенантность организаций;
- хранение IdP access/refresh tokens, group sync и provider-specific catalog;

## 9. Статус reference-реализации

[OpenAPI 3.1 v1](openapi-v1.md) и
[Agent Gateway Protocol v1](agent-gateway-v1.md) созданы и сверены с
SQL-схемой. Reference Gateway и
[reference Director](../../director/reference/README.md) проверяют public
document upload и internal agent-run lifecycle на этой схеме. PGlite-тесты
подтверждают promotion первой версии, атомарный audit, rollback при конфликте и
повторную RBAC-проверку после staging. OIDC integration tests дополнительно
проверяют hash-bound login transaction, уничтожение ephemeral secrets после
consume, replay protection, pre-provisioned identity и hash-only session.

Отдельный real PostgreSQL contention harness реализован: он использует два
соединения и проверяет ожидание конкурентного revoke через `pg_stat_activity`.
PGlite по-прежнему не является доказательством этих блокировок, а harness ещё
нужно выполнить на целевом PostgreSQL build/topology перед pilot.
