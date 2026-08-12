# OpenAPI 3.1 v1

Полный [`api/openapi-v1.yaml`](../../api/openapi-v1.yaml) описывает целевую
архитектурную поверхность. Для текущего reference deployment действует более
узкий исполнимый
[`api/openapi-pilot-v1.yaml`](../../api/openapi-pilot-v1.yaml). До завершения
реализации клиенты и pilot acceptance должны опираться на pilot-профиль, а не на
полный контракт.

Исполнимый контракт Director API зафиксирован в
[`api/openapi-v1.yaml`](../../api/openapi-v1.yaml). Этот файл является нормативным
источником для HTTP-путей, методов, DTO, кодов ответа и обязательных
заголовков.
Статус — архитектурный черновик v1; нормативность означает приоритет этого
файла перед prose-описанием, а не производственное утверждение.

## Охват

Версия `0.1.0` описывает 30 операций на 28 путях:

- корпоративный OIDC Authorization Code + PKCE вход, локальную выдачу и отзыв
  текущей пользовательской сессии;
- проекты и темы;
- карточки памяти, загрузку и версии документов;
- задачи, поиск контекста и хронологию;
- запуски AI, получение и сохранение результата;
- решения и их замену;
- audit-события и confirmation workflow.
- project-scoped confirmation inbox с status filter и opaque cursor.

Refresh, provisioning/linking API, управление ролями и внутренние API
Document Store в этот контракт не входят. Взаимодействие с Gateway вынесено в отдельный
[Agent Gateway Protocol v1](agent-gateway-v1.md).

## Гарантии контракта

1. Business operations требуют `X-Request-Id` в формате UUID и принимают
   внутреннюю Director session как opaque Bearer или Secure HttpOnly cookie.
   Browser OIDC start/callback генерируют request ID, если браузер его не
   передал. Local session issuance и OIDC endpoints не требуют готовой session.
2. `project_id` для вложенных ресурсов определяется сервером, а не
   доверяется дублирующему полю клиента.
3. Поиск фильтрует недоступные объекты до пагинации и не возвращает
   метаданные версий.
4. `current_version` требует отдельного `document_version.read`.
5. `confidential` и `restricted` объекты требуют дополнительных
   permissions; передача `restricted` внешнему AI запрещена в MVP.
   `agent_run.read` открывает только метаданные; текст AI-результата требует
   прав чтения на весь исходный контекст.
6. Защищенная операция возвращает `428 requires_confirmation` и
   серверный `confirmation_id`; клиент не может отключить проверку.
   Параметры хранятся в недоступном клиенту `frozen_payload`, поэтому approval
   продолжает ту же операцию без replay исходного запроса.
7. Прямое создание объекта памяти ограничено типами `note`,
   `protocol` и `research_result`. `decision` и `ai_result` создаются
   специализированными атомарными сценариями; endpoint для
   `open_question` отложен за границу v1.
8. Permission/policy deny создаёт внутренний authorization decision и
   `access.denied`. Concealment не меняет контрактный `404` и не раскрывает
   существование чужого ресурса. Успешная immediate/replay business operation
   создаёт `allow` decision и связанный success/access audit в той же
   SQL-транзакции.
9. OIDC callback использует только exact server-configured HTTPS URLs,
   одноразовые state/nonce/PKCE и pre-provisioned `(issuer, sub)` с ожидаемым
   provider code;
   IdP tokens и Director bearer в redirect не выдаются. Cookie-authenticated
   mutations требуют same-origin `Origin`.

## Расширения OpenAPI

| Расширение | Смысл |
| --- | --- |
| `x-permissions` | Базовые permissions операции |
| `x-conditional-permissions` | Дополнительные permissions для конкретного payload или ресурса |
| `x-result-visibility-permissions` | Permissions, управляющие включением объекта в выборку |
| `x-policy-constraints` | Запреты, которые нельзя обойти permission или confirmation |
| `x-audit-events` | События успешного сценария |
| `x-conditional-audit-events` | События, возникающие только при указанном условии |
| `x-confirmation` | Безусловное требование confirmation |
| `x-confirmation-policy` | Условное требование confirmation |

Эти поля документируют policy, но не заменяют серверную проверку
Auth/RBAC.

## Границы источников

- OpenAPI определяет транспортный контракт.
- [Director API v1](director-api-v1.md) объясняет сценарии и мотивацию.
- [Auth/RBAC v1](auth-rbac-v1.md) определяет permissions, scope, sensitivity и
  confirmation policy.
- [PostgreSQL schema v1](postgresql-schema-v1.md) определяет инварианты
  хранения и разрешенные переходы статусов.

При расхождении DTO или HTTP-семантики исправляется описательный
документ. При расхождении политики или инварианта сначала меняется
соответствующий Auth/RBAC или SQL-артефакт, затем OpenAPI.
