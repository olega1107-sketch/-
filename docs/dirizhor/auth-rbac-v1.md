# Auth/RBAC v1

Черновая спецификация аутентификации, авторизации и подтверждений для первого
MVP «Дирижёра». Документ определяет, кто и при каких условиях может работать с
проектами, корпоративной памятью, решениями и AI-агентами.

Спецификация является нормативной для Director API, Memory Registry, Document
Store и Agent Gateway. Reference runtime использует PostgreSQL session boundary
и стандартную OIDC client library; нормативны инварианты, а не конкретный
vendor IdP.

## 1. Цель и границы MVP

Auth/RBAC должен обеспечить:

- идентификацию пользователя и внутренних сервисов;
- выдачу прав через роли, назначенные в определенной области;
- запрет доступа по умолчанию;
- отдельные правила для чувствительных объектов;
- контролируемую передачу контекста AI;
- одноразовые подтверждения чувствительных операций;
- восстановимую историю решений доступа.

В первом MVP предполагается одна организация и один corporate OIDC provider.
Мультитенантность, SAML, автоматическая синхронизация каталога и сложные ACL
отдельных абзацев документа не входят в этот этап.

## 2. Основные термины

- **Principal** — субъект, от имени которого выполняется действие: пользователь,
  внутренний сервис или ограниченный запуск агента.
- **Permission** — право выполнить одно действие, например
  `memory_object.read`.
- **Role** — именованный набор permissions.
- **Role assignment** — назначение роли principal в конкретной области.
- **Scope** — область действия назначения: вся система или конкретный проект.
- **Policy** — дополнительное условие, которое может сузить ролевое право.
- **Confirmation** — одноразовое согласие уполномоченного пользователя на уже
  разрешенную, но чувствительную операцию.
- **Capability** — короткоживущий технический допуск к точному набору ресурсов
  для одного `agent_run`.

Аутентификация отвечает на вопрос «кто выполняет действие». Авторизация отвечает
на вопрос «разрешено ли этому субъекту это действие над этим ресурсом сейчас».

## 3. Неподвижные принципы

1. Любое действие запрещено, пока система явно не доказала обратное.
2. Роль назначается в области, а не действует глобально сама по себе.
3. Администратор платформы не получает автоматического доступа к содержимому
   проектов.
4. Связь между объектами памяти не переносит права с одного объекта на другой.
5. Более строгая политика чувствительности имеет приоритет над ролевым правом.
6. Confirmation не создает недостающее permission и не расширяет scope.
7. AI-агент не является пользователем и не получает постоянную роль в проекте.
8. Внешний AI-провайдер не получает учетные данные к корпоративной памяти.
9. Проверка выполняется на сервере при каждом чувствительном действии. UI может
   скрывать недоступные команды, но не является границей безопасности.
10. Все отказы, изменения ролей, подтверждения и передачи данных AI связываются
    с `request_id` и записываются в Audit Log.

## 4. Типы principal

### 4.1. User principal

Человек, вошедший в систему. Пользовательский токен должен однозначно содержать
или позволять определить:

- `user_id`;
- `session_id`;
- время выдачи и истечения;
- способ аутентификации;
- статус сессии.

Полный список ролей не должен считаться достоверным только потому, что он
записан в долгоживущем токене. Director API получает актуальные назначения из
Auth/RBAC, чтобы отзыв роли начинал действовать без ожидания истечения такого
токена.

### 4.2. Service principal

Внутренние модули имеют отдельные технические идентичности:

- `director-api`;
- `memory-registry`;
- `document-store`;
- `agent-gateway`;
- `task-worker`;
- `audit-log`.

Сервисное право разрешает только межмодульный вызов. Оно не заменяет проверку
права пользователя, от имени которого выполняется бизнес-операция.

### 4.3. Agent capability principal

Для каждого `agent_run` Director API выдает Agent Gateway короткоживущую
capability. Она ограничена:

- одним `agent_run_id`;
- единственным action `context_bundle.read` в v1;
- точными `memory_object_id` и `document_version_id`;
- целью запуска;
- временем действия;
- хешем утвержденного набора контекста.

Capability не дает право искать память, выбирать дополнительные документы,
читать другие версии или сохранять результат. Необработанный токен capability
не хранится в журнале или базе данных; хранится только его безопасный отпечаток.

Еще не использованная capability отзывается при cancel, security incident,
запрете provider проектной политикой или повышении sensitivity любого источника
выше frozen snapshot. Понижение sensitivity не расширяет уже выданное право.

В MVP capability используется один раз для серверной сборки всего context
bundle. После успешной сборки она помечается использованной. Повторная попытка
после потери ответа требует новой capability на тот же immutable context;
использованная запись при этом не изменяется. Измененный набор версий требует
новой Auth/RBAC-проверки и, когда применимо, нового confirmation.

## 5. Области действия

MVP поддерживает два scope для назначения ролей:

- `system` — административные операции всей установки;
- `project` — данные и операции одного проекта.

Проектный scope распространяется на принадлежащие проекту темы, объекты памяти,
версии документов, задачи, запуски агентов и решения. Он не распространяется на
связанные объекты другого проекта.

Создатель нового проекта атомарно получает `project_owner`. Проект не должен
существовать в состоянии без владельца, кроме явно зафиксированной аварийной
ситуации.

При проверке конкретного ресурса Director API обязан сначала достоверно
определить его `project_id`. Клиент не может подменить область, передав другой
`project_id` в теле запроса.

Точечные назначения на уровне темы или объекта памяти откладываются до версии
после MVP. Для исключений MVP использует уровни чувствительности и специальные
permissions на чтение.

## 6. Роли MVP

Роли являются стартовыми шаблонами. Пользователь может иметь несколько ролей в
одном проекте; итоговый набор прав объединяется, а ограничивающие policies
применяются после этого.

### `platform_admin`

Управляет пользователями, сервисными principal, системными ролями и настройками.
Не читает содержимое проекта и Audit Log проекта без отдельного проектного
назначения.

Обычное назначение проектных ролей выполняет `project_owner` через
`project.member.manage`. Platform admin не может незаметно назначить себе
проектную роль. Аварийное восстановление осиротевшего проекта должно быть
отдельной break-glass операцией с confirmation и полным audit.

### `project_owner`

Управляет проектом, участниками, содержимым, AI-политикой и решениями. Имеет
доступ к объектам всех уровней чувствительности проекта.

### `project_approver`

Просматривает проектные материалы, утверждает и заменяет решения, подтверждает
передачу конфиденциального контекста AI. Не управляет участниками и системными
настройками.

### `project_editor`

Создает и изменяет темы, объекты памяти, версии и задачи; запускает AI на
разрешенном контексте; создает проекты решений. Не утверждает решения и не
читает объекты уровня `restricted`.

Может подтверждать собственное сохранение AI-результата и собственную массовую
передачу обычного контекста. Не может подтверждать передачу `confidential`,
утверждение решения или операцию другого пользователя.

### `project_viewer`

Ищет и читает доступные материалы проекта. Не изменяет данные и не запускает
AI-агентов.

### `project_auditor`

Читает журнал и технические метаданные проекта. Содержимое документов доступно
только при наличии дополнительной роли `project_viewer` или выше.

## 7. Каталог permissions MVP

Права называются действиями и не содержат названия роли.

### Система и участники

- `identity.manage`;
- `service_principal.manage`;
- `role_assignment.read`;
- `role_assignment.manage`;
- `project.create`;
- `project.read`;
- `project.update`;
- `project.archive`;
- `project.member.manage`;
- `project.ai_policy.manage`.

### Корпоративная память

- `topic.read`;
- `topic.create`;
- `topic.update`;
- `memory_object.search`;
- `memory_object.read`;
- `memory_object.read_confidential`;
- `memory_object.read_restricted`;
- `memory_object.create`;
- `memory_object.update`;
- `memory_object.archive`;
- `document_version.read`;
- `document_version.create`.

`memory_object.read` охватывает уровни `public` и `internal`. Для более строгих
уровней дополнительно требуется соответствующее permission.

Чтение содержимого конкретной версии требует одновременно права на карточку
объекта и `document_version.read`. Поиск фильтруется по правам до подсчета общего
числа и пагинации: недоступный объект не раскрывается названием, summary,
ключевыми словами или самим фактом существования.

### Задачи и AI

- `task.create`;
- `task.read`;
- `task.cancel`;
- `agent_run.create`;
- `agent_run.read`;
- `agent_run.cancel`;
- `agent_context.share`;
- `agent_context.share_confidential`;
- `agent_provider.use_external`;
- `ai_result.save`.

### Решения, подтверждения и аудит

- `decision.read`;
- `decision.create`;
- `decision.approve`;
- `decision.supersede`;
- `confirmation.read`;
- `confirmation.approve`;
- `confirmation.reject`;
- `audit_event.read`.

## 8. Базовая матрица ролей

| Операция | Owner | Approver | Editor | Viewer | Auditor |
| --- | --- | --- | --- | --- | --- |
| Читать проект и обычную память | да | да | да | да | нет |
| Читать `confidential` | да | да | да | нет | нет |
| Читать `restricted` | да | нет | нет | нет | нет |
| Создавать и менять память | да | нет | да | нет | нет |
| Управлять участниками и AI-policy | да | нет | нет | нет | нет |
| Создавать задачи и agent runs | да | нет | да | нет | нет |
| Передавать обычный контекст AI | да | нет | да | нет | нет |
| Подтверждать передачу `confidential` | да | да | нет | нет | нет |
| Сохранять AI-результат | да | нет | да | нет | нет |
| Создавать проект решения | да | да | да | нет | нет |
| Утверждать или заменять решение | да | да | нет | нет | нет |
| Читать журнал проекта | да | да | нет | нет | да |

`platform_admin` намеренно не включен в проектную матрицу. Для работы с данными
проекта ему назначается одна из проектных ролей на общих основаниях.

## 9. Уровни чувствительности

Обязательные значения `memory_object.sensitivity_level`:

| Уровень | Назначение | Чтение | Передача внешнему AI |
| --- | --- | --- | --- |
| `public` | Материал разрешен к публичному раскрытию | `memory_object.read` | разрешается политикой проекта |
| `internal` | Обычная внутренняя информация, значение по умолчанию | `memory_object.read` | разрешается политикой проекта |
| `confidential` | Коммерчески или организационно чувствительная информация | плюс `memory_object.read_confidential` | отдельное право и confirmation для каждого запуска |
| `restricted` | Критичные секреты, учетные данные, особо защищенные данные | плюс `memory_object.read_restricted` | запрещена в MVP |

Уровень наследуется новой версией документа. Понижение чувствительности требует
`project_owner`, явного обоснования и audit-события.

Секреты, пароли, приватные ключи и токены не должны храниться как обычные
объекты памяти даже с уровнем `restricted`; для них требуется отдельное
хранилище секретов.

## 10. Политика передачи данных AI

Для каждого проекта существует `project_ai_policy`. Без явно созданной политики
передача данных внешним AI запрещена.

Минимальные поля политики:

- разрешена ли работа с внешними AI;
- разрешенные `provider_id`;
- класс размещения каждого адаптера: `internal` или `external`;
- версия утвержденного профиля обработки данных провайдера;
- максимальный уровень чувствительности для внешней передачи;
- требуется ли confirmation для `internal`;
- лимит массового контекста;
- дата изменения и пользователь, изменивший политику.

Перед запуском AI Director API проверяет одновременно:

1. право пользователя создать `agent_run`;
2. право пользователя прочитать каждую выбранную версию;
3. право передать контекст AI;
4. проектную AI-policy;
5. уровень чувствительности каждого объекта;
6. допустимость выбранного провайдера и класса размещения;
7. наличие действующего confirmation, если оно требуется.

После успешной проверки Director API фиксирует неизменяемый набор контекста,
создает ordered `agent_run_context` с уникальной `position`, вычисляет
`context_set_hash`, фиксирует `request_fingerprint` и deadline и только затем
выдает Agent Gateway capability.

Agent Gateway не может добавить документ после выдачи capability. Для изменения
набора создаются новый `agent_run`, новая проверка и новое подтверждение.

Каждая запись `agent_run_context` фиксирует sensitivity источника на момент
запуска. Временный AI-результат наследует максимальный уровень этого набора.
`agent_run.read` открывает метаданные запуска, но чтение текста результата
дополнительно требует прав чтения на весь замороженный контекст.

## 11. Confirmation

Confirmation требуется как минимум для:

- передачи `confidential` внешнему AI;
- массовой передачи контекста сверх лимита проекта;
- сохранения AI-результата в корпоративную память;
- утверждения решения;
- замены утвержденного решения;
- понижения уровня чувствительности объекта.

Правила confirmation:

1. Создается только после положительной проверки основного permission.
2. Привязан к пользователю, операции, цели, точному payload и `request_id`.
3. Содержит `payload_hash`; любое изменение операции делает его недействительным.
4. Имеет короткий срок действия и используется только один раз.
5. Approver сам должен иметь `confirmation.approve` и право на целевую операцию.
6. После использования получает статус `consumed` и не может применяться снова.
7. Отклонение, истечение срока или отзыв приводят к запрету операции.
8. Для роли `project_editor` действует дополнительное ограничение: разрешено
   подтверждать только собственную операцию и только если project policy не
   требует другого подтверждающего пользователя.

Статусы:

- `pending`;
- `approved`;
- `rejected`;
- `expired`;
- `consumed`;
- `revoked`.

В однопользовательском MVP `project_owner` может подтвердить собственную
операцию. Audit Log помечает это как `self_approved`. Для промышленного режима
политика проекта может потребовать подтверждение другим пользователем.

## 12. Алгоритм проверки доступа

Auth/RBAC обрабатывает запрос в фиксированном порядке:

1. Проверяет подлинность principal и активность сессии или capability.
2. Загружает ресурс и определяет фактический `project_id` на сервере.
3. Проверяет активность проекта и principal.
4. Собирает актуальные role assignments подходящего scope.
5. Проверяет требуемое permission.
6. Применяет уровень чувствительности и ограничивающие policies.
7. Для AI применяет `project_ai_policy` и проверяет весь набор контекста.
8. Определяет, нужно ли confirmation, и проверяет его payload hash.
9. Возвращает решение и обязательные действия для вызывающего модуля.
10. Записывает необходимое audit-событие.

Возможные решения:

- `allow`;
- `deny`;
- `require_confirmation`.

Confirmation является отдельным результатом, а не разновидностью `allow`.

## 13. Внутренний контракт проверки

Auth/RBAC может быть модулем внутри монолита MVP, но его логический контракт не
должен зависеть от способа развертывания.

Пример запроса:

```json
{
  "subject": {
    "type": "user",
    "id": "00000000-0000-0000-0000-000000000000"
  },
  "action": "agent_context.share_confidential",
  "resource": {
    "type": "agent_run",
    "id": "00000000-0000-0000-0000-000000000000"
  },
  "context": {
    "request_id": "00000000-0000-0000-0000-000000000000",
    "project_id": "00000000-0000-0000-0000-000000000000",
    "provider_id": "provider-adapter-id",
    "deployment_class": "external",
    "context_set_hash": "sha256:...",
    "confirmation_id": null
  }
}
```

Пример ответа:

```json
{
  "decision": "require_confirmation",
  "reason_codes": ["confidential_external_share"],
  "authorization_decision_id": "00000000-0000-0000-0000-000000000000",
  "required_confirmation": {
    "operation": "agent_context_share",
    "payload_hash": "sha256:..."
  },
  "obligations": [
    "audit_access_decision",
    "bind_capability_to_context_set"
  ]
}
```

Базовые reason codes:

- `permissions_satisfied`;
- `authentication_required`;
- `principal_inactive`;
- `permission_missing`;
- `scope_mismatch`;
- `project_inactive`;
- `sensitivity_not_allowed`;
- `external_ai_disabled`;
- `provider_not_allowed`;
- `restricted_external_share_forbidden`;
- `confirmation_required`;
- `confirmation_invalid`;
- `capability_expired`;
- `resource_not_bound_to_run`.

## 14. Сущности данных Auth/RBAC

### `user`

- `id`;
- `login`;
- `display_name`;
- `status`;
- `created_at`;
- `updated_at`;
- `last_authenticated_at`.

Статусы: `invited`, `active`, `suspended`, `disabled`.

### `user_identity`

- `id`;
- `user_id`;
- `provider_code`;
- `provider_subject`;
- `secret_hash` для локальной идентичности;
- `created_at`;
- `updated_at`;
- `last_authenticated_at`.

Сырой пароль не хранится. Таблица отделяет бизнес-пользователя от конкретного
способа входа.

Для OIDC identity `provider_code` задаёт локальное стабильное имя provider,
`provider_issuer` — точный issuer, а `provider_subject` равен проверенному
`sub`. Runtime сопоставляет все три значения; SQL дополнительно запрещает
дубли `(issuer, sub)`. Автоматическое связывание по email запрещено. Неизвестный
subject не создаёт пользователя: identity должна быть заранее provisioned
административным процессом.

Reference local identity использует формат
`$scrypt$v=1$ln=15,r=8,p=1$<salt>$<derived-key>`: случайная соль 16 bytes,
derived key 32 bytes, фиксированный memory cost и constant-time comparison.
Неизвестный login проверяется против корректного dummy hash, чтобы не создавать
явно быстрый путь для user enumeration.

### `user_session`

- `id`;
- `user_id`;
- `session_token_hash`;
- `authentication_method`;
- `created_at`;
- `expires_at`;
- `last_seen_at`;
- `revoked_at`;
- `ip_address`;
- `user_agent`.

Сессия нужна для немедленного отзыва доступа без ожидания истечения токена.
OIDC подтверждает identity только на login boundary; затем все business
endpoints используют эту внутреннюю Director session и актуальные локальные
role assignments.

### `oidc_login_transaction`

- hash случайного browser token;
- hash `state`;
- ephemeral `nonce` и PKCE verifier;
- provider, request ID, timestamps и consume marker.

Транзакция короткоживущая и одноразовая. После consume nonce/verifier
уничтожаются. IdP access/refresh/ID tokens не сохраняются.

### `service_principal`

- `id`;
- `code`;
- `status`;
- `created_at`;
- `rotated_at`.

### `role`

- `id`;
- `code`;
- `name`;
- `scope_type`;
- `system_defined`;
- `created_at`.

### `permission`

- `id`;
- `code`;
- `description`.

### `role_permission`

- `role_id`;
- `permission_id`.

### `role_assignment`

- `id`;
- `principal_type`;
- `principal_id`;
- `role_id`;
- `scope_type`;
- `scope_id`;
- `granted_by_user_id`;
- `created_at`;
- `expires_at`;
- `revoked_at`.

Для `system` значение `scope_id` равно `null`. Для `project` оно обязательно.

### `project_ai_policy`

- `project_id`;
- `external_ai_enabled`;
- `allowed_provider_ids`;
- `provider_data_profile_versions`;
- `max_external_sensitivity_level`;
- `confirm_internal_external_share`;
- `bulk_context_object_limit`;
- `updated_by_user_id`;
- `updated_at`.

### `confirmation`

- `id`;
- `operation`;
- `target_type`;
- `target_id`;
- `project_id`;
- `requested_by_user_id`;
- `decided_by_user_id`;
- `authorization_decision_id`;
- `request_id`;
- `status`;
- `frozen_payload`;
- `payload_hash`;
- `summary`;
- `created_at`;
- `expires_at`;
- `decided_at`;
- `consumed_at`.

`frozen_payload` хранит канонические параметры отложенной операции. Поле
доступно только доверенному Director API, не возвращается клиенту и не
копируется в audit metadata. `payload_hash` вычисляется из его канонического
представления.

### `authorization_decision`

- `id`;
- `principal_type`;
- `principal_id`;
- `action`;
- `resource_type`;
- `resource_id`;
- `project_id`;
- `decision`;
- `reason_codes`;
- `obligations`;
- `request_id`;
- `created_at`.

Запись неизменяема и связывает confirmation и audit events с конкретным
решением Auth/RBAC.

### `agent_capability`

- `id`;
- `agent_run_id`;
- `project_id`;
- `issued_to_service_principal_id`;
- `allowed_actions` — ровно `['context_bundle.read']` в v1;
- `context_set_hash`;
- `token_hash`;
- `issued_at`;
- `expires_at`;
- `used_at`;
- `revoked_at`.

### `agent_capability_resource`

- `agent_capability_id`;
- `project_id`;
- `memory_object_id`;
- `document_version_id`.

## 15. Audit-события

Обязательные события Auth/RBAC:

- `authentication.succeeded`;
- `authentication.failed`;
- `session.revoked`;
- `role_assignment.created`;
- `role_assignment.revoked`;
- `project_ai_policy.updated`;
- `access.allowed`;
- `access.denied`;
- `access.sensitive_allowed`;
- `confirmation.created`;
- `confirmation.approved`;
- `confirmation.rejected`;
- `confirmation.expired`;
- `confirmation.consumed`;
- `agent_capability.issued`;
- `agent_capability.used`;
- `agent_capability.revoked`;
- `agent_context.authorized`.

Audit Event должен содержать `authorization_decision_id`, если событие возникло
из проверки доступа. Причина отказа записывается кодом, но ответ клиенту не
должен раскрывать существование чужого ресурса.

При deny бизнес-транзакция сначала откатывается. После этого отдельная короткая
транзакция атомарно создаёт immutable `authorization_decision(decision=deny)` и
`access.denied`. Если эта audit-транзакция не может завершиться, Director
fail-closed возвращает `500`, а не исходный неаудированный deny. Для concealed
permission deny клиент продолжает получать `404`; внутренний audit содержит
`response_concealed=true`, missing permissions и server-resolved `project_id`.

При immediate allow decision и success audit входят в ту же SQL-транзакцию, что
и разрешённая PostgreSQL-часть операции. Direct write-события получают
`authorization_decision_id` напрямую. Для read/search/replay без отдельного
business-события создаётся metadata-only `access.allowed`; search query хранится
только как hash. Lifecycle и protected-operation события confirmation сохраняют
ссылку на исходный `require_confirmation`, а текущая проверка approve/reject
фиксируется отдельной парой `allow` + `access.allowed`.

Audit metadata не должна содержать полный текст документа, prompt, ответ AI,
пароль, токен или приватный ключ. Для расследования сохраняются идентификаторы,
хеши, размеры, причины и ссылки на защищенные объекты.

Для запроса ресурса вне доступного проекта Director API возвращает `not_found`.
Для известного ресурса, где разрешен просмотр метаданных, но запрещено действие,
возвращается `access_denied`. Для отсутствующей аутентификации используется
`unauthorized`, а для необходимого подтверждения — `requires_confirmation`.

## 16. Критерии приемки MVP

1. Пользователь без роли в проекте не видит проект в списке и не находит его
   объекты через поиск.
2. Поиск и счетчики не раскрывают metadata объектов, недоступных по уровню
   чувствительности.
3. Viewer не может создать или изменить объект памяти.
4. Editor не может утвердить или заменить решение.
5. Platform admin не может читать проектные документы или сам назначить себе
   проектную роль обычным путем.
6. Внешний AI запрещен, пока owner явно не настроил `project_ai_policy`.
7. Передача `confidential` внешнему AI без подходящего permission и confirmation
   невозможна.
8. Передача `restricted` внешнему AI невозможна даже при наличии роли owner.
9. Изменение набора документов после подтверждения аннулирует confirmation.
10. Capability выдается только active service principal `agent-gateway`,
   позволяет собрать только версии из `agent_capability_resource` и перестает
   действовать после использования, истечения срока или отзыва.
11. AI-результат нельзя сохранить без отдельного пользовательского confirmation.
12. Все отказы, изменения ролей, чувствительные передачи и использования
    capability присутствуют в Audit Log и связаны с `request_id`.
13. Отзыв role assignment влияет на следующую проверку без перевыпуска
    долгоживущего пользовательского токена.

## 17. Не входит в MVP

- мультитенантность нескольких организаций;
- SAML, несколько OIDC providers и автоматическая синхронизация каталогов;
- обязательное правило двух разных подтверждающих пользователей;
- назначения ролей на отдельные темы и объекты;
- права на уровне абзацев или полей документа;
- делегирование прав между AI-агентами;
- доступ внешнего AI к объектам `restricted`;
- пользовательский редактор собственных ролей и policy-языка.

## 18. Статус reference-реализации

Исполнимые [PostgreSQL schema v1](postgresql-schema-v1.md),
[OpenAPI 3.1 v1](openapi-v1.md) и внутренний
[Agent Gateway Protocol v1](agent-gateway-v1.md), reference Gateway и
[reference Director](../../director/reference/README.md) созданы. Public upload
проверяет active user, active project, актуальное project-scoped назначение и
permissions `project.read`, `memory_object.create`, `document_version.create`.
Права повторно вычисляются в commit-транзакции под row locks; тест отзыва роли
между staging и commit подтверждает отказ без SQL side effects.

Public task/agent-run dispatch также проверяет базовые и условные permissions
для `confidential`/`restricted`, фиксирует точные document versions и применяет
актуальный `project_ai_policy`. Internal immediate и разрешённый external
immediate flow атомарно создают run, capability/resources и audit.

Для external `internal`/`confidential` context по policy и для набора сверх
`bulk_context_object_limit` создаётся frozen pending confirmation. Public
get/approve/reject повторно проверяют requester/approver RBAC, текущую policy,
sensitivity и canonical payload hash. Approval атомарно выпускает capability и
потребляет confirmation; reject, expiry или stale payload отменяют waiting
run/task. Идемпотентный retry повторно проверяет текущую роль и использует тот же
замороженный envelope и capability.

Public task/run/result reads получают project scope только из серверной записи.
Чтение текста временного результата требует права на весь frozen context и
учитывает текущую sensitivity источников. `ai_result_save` всегда создаёт
confirmation с frozen metadata, result signature, relationships и эффективной
sensitivity. Approval повторно проверяет requester/approver и атомарно создаёт
`ai_result`, версию, связи, result link, task completion и audit events.

Public session verifier реализован поверх `user_sessions`: opaque bearer
хешируется SHA-256, валидная неистёкшая и неотозванная сессия active user
выбирается одним atomic `UPDATE ... FROM`, который обновляет `last_seen_at`.
Сырой token в БД не хранится; expired, revoked, inactive и неизвестная сессия
возвращают одинаковый `401`. Static public bearer доступен только в явно
незащищённом development mode.

Явно включаемый local password login создаёт session с максимальным TTL 30 дней,
пишет `authentication.succeeded` или обезличенный `authentication.failed` и не
возвращает различий между bad password, unknown identity и inactive user.
Отзыв текущей session и `session.revoked` выполняются атомарно.

Corporate OIDC Authorization Code + PKCE S256 boundary реализован с уникальными
state/nonce, hash-bound HttpOnly transaction cookie и atomic consume. Проверенный
issuer/sub сопоставляется только с pre-provisioned provider identity; успешный вход
выдаёт внутреннюю Secure HttpOnly Director session. Callback replay, unknown
subject, provider reject и cookie mutation без same-origin Origin покрыты
интеграционными тестами. Подробности: [OIDC/SSO boundary v1](oidc-sso-v1.md).

Permission и project-policy deny всех реализованных public business endpoints
создают `authorization_decision` с reason codes и атомарный `access.denied`.
Реальный not-found не ошибочно классифицируется как deny, а concealed deny не
меняет публичный ответ.

Успешные текущие immediate/replay public business flows систематически создают
`allow` с `permissions_satisfied`; direct write success events,
`memory_object.read` либо metadata-only `access.allowed` ссылаются на него. Все
решения имеют непустой `reason_codes` на SQL-границе. Это ещё не полный
Auth/RBAC decision engine:
refresh, password reset/change, global logout, provisioning/linking API, SAML,
multi-provider и IdP logout не реализованы. Остались invalid bearer audit,
distributed login rate limit, confirmations для decisions и sensitivity
lowering, а также фоновая обработка expiry.
