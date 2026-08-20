# OIDC/SSO operational runbook

Статус: эксплуатационный черновик v1 для reference Director.

Runbook применяется вместе с [OIDC/SSO boundary v1](oidc-sso-v1.md). Он
описывает подключение одного corporate OIDC provider, проверку metadata,
provisioning identities, canary-вход, logout и экстренный отзыв доступа.

## 1. Ответственность и секреты

До изменений назначаются владелец IdP-конфигурации, оператор Director и
наблюдающий rollback. Client secret передаётся только через secret manager или
mounted file. Он не должен попадать в shell history, task tracker, audit
metadata или вывод команд.

Используются разные credentials:

- runtime `DATABASE_URL(_FILE)` для Director;
- `DIRECTOR_PROVISIONING_DATABASE_URL(_FILE)` для короткой операторской job;
- DDL/migration credential provisioning-командам не нужен.

Provisioning-role получает только необходимые DML-права на `app_users`,
`user_identities`, `user_sessions` и `audit_events`. Этот credential не
монтируется в постоянно работающий Director.

## 2. Регистрация клиента у IdP

Согласовать и зарегистрировать:

- confidential client и точный `client_id`;
- Authorization Code Flow;
- точный callback
  `https://<director>/api/v1/auth/oidc/callback`;
- разрешённые scopes с обязательным `openid`;
- `client_secret_basic` или `client_secret_post`;
- точный асимметричный алгоритм ID Token, `RS256` по умолчанию;
- при RP-initiated logout точный `post_logout_redirect_uri`.

Email, UPN, display name и group claims не используются для linking или RBAC.
Устойчивая внешняя identity определяется только точными `issuer` и `sub`.

### ZITADEL pilot registration sheet

Для pilot используются следующие заранее зарезервированные
несекретные значения:

| ZITADEL setting | Exact value |
| --- | --- |
| Project name | `Dirizhor Pilot` |
| Application name | `Director Pilot` |
| Application type | `Web` |
| Authentication method | `Basic` (`client_secret_basic`) |
| Grant type | `Authorization Code` |
| PKCE | `S256`, required by Director |
| Redirect URI | `https://pilot.baza.fyi/api/v1/auth/oidc/callback` |
| Post logout redirect URI | `https://pilot.baza.fyi/signed-out` |
| Issuer | `https://dirizhor-pilot-r5zsil.eu1.zitadel.cloud` |
| Scopes | `openid profile email` |
| ID Token signing algorithm | `RS256` |

Development mode, wildcard redirect URIs, implicit flow и password grant не
включаются. `client_id` фиксируется после создания application.
Client secret копируется один раз напрямую в утверждённое внешнее
хранилище; его нельзя вставлять в этот файл, чат, shell history или
GitHub variables. Создание project/application и генерация secret
требуют отдельного разрешения. Регистрация URI не разрешает
публикацию DNS или создание public LoadBalancer.

## 3. Runtime configuration

```bash
export DIRECTOR_OIDC_ISSUER_URL=https://idp.example.com/tenant
export DIRECTOR_OIDC_CLIENT_ID=dirizhor
export DIRECTOR_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc-client-secret
export DIRECTOR_OIDC_REDIRECT_URI=https://director.example.com/api/v1/auth/oidc/callback
export DIRECTOR_OIDC_POST_LOGIN_REDIRECT_URI=https://director.example.com/
export DIRECTOR_OIDC_ID_TOKEN_SIGNING_ALG=RS256
```

Для возврата после logout дополнительно задаётся зарегистрированный URL:

```bash
export DIRECTOR_OIDC_POST_LOGOUT_REDIRECT_URI=https://director.example.com/signed-out
```

Если эта переменная задана, startup и preflight требуют HTTPS
`end_session_endpoint`. Без неё отсутствие RP-initiated logout является
предупреждением, а локальный отзыв Director session продолжает работать.

## 4. Discovery preflight

Из `director/reference` выполнить в той же сетевой и secret-среде, где будет
работать Director:

```bash
pnpm oidc:preflight
```

Команда не печатает client secret или provider endpoints. Успешный JSON
подтверждает:

- точное совпадение discovery `issuer`;
- HTTPS authorization, token и JWKS endpoints;
- Authorization Code Flow и PKCE `S256`;
- выбранный token endpoint auth method;
- закреплённый алгоритм подписи ID Token;
- `public` или `pairwise` subject type;
- наличие logout endpoint, если настроен post-logout redirect.

Warnings по scopes/claims требуют сверки с IdP administrator, но сами по себе
не блокируют запуск: discovery может не рекламировать все фактически
поддерживаемые scopes. Любая conformance error блокирует rollout; обход
проверки в production не предусмотрен.

## 5. Provisioning identity

Значение `sub` получают из административного интерфейса/API IdP или другого
утверждённого источника после проверки tenant/issuer. Email нельзя использовать
как замену `sub`. Provisioning request проходит обычное согласование доступа и
получает отдельные `request_id`, `user_id` и `identity_id` UUID.

Команда принимает JSON только через stdin, чтобы `sub` не оказался в process
arguments. Для нового пользователя:

```json
{
  "operation": "create_user",
  "request_id": "71000000-0000-4000-8000-000000000001",
  "user_id": "71000000-0000-4000-8000-000000000002",
  "identity_id": "71000000-0000-4000-8000-000000000003",
  "login": "user@example.com",
  "display_name": "Example User",
  "provider_subject": "exact-id-token-sub"
}
```

Для привязки к существующему active user используется `attach_identity` без
`display_name`. Поле `login` обязано совпасть с выбранным `user_id`; это защита
от ошибки оператора, а не identity key.

```bash
export DIRECTOR_PROVISIONING_DATABASE_URL_FILE=/run/secrets/oidc-provisioning-db-url
export DIRECTOR_PROVISIONING_DATABASE_CA_PATH=/run/secrets/postgresql-ca.crt
pnpm oidc:provision < approved-provisioning-request.json
```

Повтор с теми же UUID и identity возвращает `unchanged`. Конфликт ID, login,
issuer/sub или вторая identity того же provider для пользователя отклоняется.
Audit `identity.provisioned` содержит operation и provider code, но не `sub`.

## 6. Canary и rollout

1. Выполнить preflight из production network segment.
2. Provision отдельного canary user с минимальными Director roles.
3. Запустить `/api/v1/auth/oidc/start` в чистой browser session.
4. Подтвердить callback на точный origin и создание Secure HttpOnly cookie.
5. Проверить доступ canary только к ожидаемым проектам.
6. Повторить callback URL и убедиться, что replay не создаёт вторую session.
7. Проверить local logout и, если включён, переход по `logout_url` IdP.
8. Проверить audit success/failure/revocation без raw code, token, nonce и sub.

Во время rollout наблюдаются provider latency/errors, callback rejection,
`identity_not_provisioned`, session issuance, CSRF rejects и database errors.
Authorization code, query целиком и provider response в telemetry не пишутся.

## 7. Logout

UI вызывает `POST /api/v1/auth/oidc/logout` с `X-Request-Id`, текущей cookie и
точным same-origin `Origin`. Director сначала отзывает локальную session и
очищает cookie, затем возвращает `{ "logout_url": string | null }`. При
непустом URL UI выполняет top-level navigation к IdP.

Director не хранит raw ID Token, поэтому не отправляет `id_token_hint`. IdP
может показать подтверждение и без него может не вернуть browser на RP. Это не
отменяет уже выполненный локальный logout. `DELETE /auth/sessions/current`
остаётся универсальным локальным logout для любой Director session.

Back-channel/front-channel logout и синхронизация IdP session revocation в v1
не реализованы. Поэтому критический offboarding выполняется локальной командой
из следующего раздела, а не ожидает logout event от IdP.

## 8. Экстренный отзыв доступа

Операторский запрос содержит точные `user_id` и текущий `login`:

```json
{
  "request_id": "72000000-0000-4000-8000-000000000001",
  "user_id": "72000000-0000-4000-8000-000000000002",
  "login": "user@example.com"
}
```

```bash
pnpm oidc:revoke-access < approved-revocation-request.json
```

Одна SQL-транзакция переводит `app_users.status` в `disabled`, отзывает все
неотозванные Director sessions и создаёт `user.access_revoked`. Identity row не
удаляется: это сохраняет трассируемость и не допускает случайной повторной
привязки. Повтор после успеха возвращает `unchanged`.

Восстановление доступа не является обратным запуском этой команды. Оно требует
нового согласования, проверки состояния IdP, отдельной административной
операции активации и canary-входа.

## 9. Rollback и evidence

При росте provider failures остановить rollout и сохранить локальный доступ
только по утверждённой break-glass процедуре. Нельзя ослаблять issuer, PKCE,
signature, audience, nonce или state validation. Возврат к предыдущей
конфигурации требует повторного preflight.

Change record содержит release, issuer, client ID, provider code, выбранные
alg/auth method, preflight report, зарегистрированные callback/logout URLs,
canary request IDs и audit event IDs. Client secret, `sub`, authorization code,
ID/access token и database URL в evidence не включаются.
