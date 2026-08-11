# Service mTLS profile v1

Статус: архитектурный черновик v1 и исполнимый reference transport.

Документ определяет двусторонний TLS-профиль внутренних вызовов между Director
и Agent Gateway. Короткоживущий Ed25519 workload token остаётся вторым
независимым фактором service authentication; один token без проверенного клиентского сертификата не
разрешает internal endpoint.

## 1. Матрица доверия

| Вызов | Server certificate | Client certificate | Ingress allowlist |
| --- | --- | --- | --- |
| Director -> Gateway | DNS SAN соответствует host из `GATEWAY_BASE_URL` | CN `director-api` | `GATEWAY_ALLOWED_PEER_CNS` |
| Gateway -> Director | DNS SAN соответствует host из `DIRECTOR_BASE_URL` | CN `agent-gateway` | `DIRECTOR_ALLOWED_PEER_CNS` |

В protected mode оба URL обязаны использовать HTTPS и не могут содержать
credentials, query или fragment. Клиент проверяет server chain и hostname
через явно заданный CA bundle. Сервер проверяет client chain, после чего
authenticator проверяет CN, Ed25519 signature, `kid`, exact issuer/audience и
ограниченный интервал `iat/nbf/exp`.

Director запрашивает client certificate у всех HTTPS-соединений, но требует его
только на internal routes. Это позволяет browser/OIDC traffic приходить через
reverse proxy без пользовательского сертификата. Gateway обслуживает только
internal API и отклоняет TLS-соединение без доверенного client certificate.

## 2. Сертификаты

Рекомендуется выпускать отдельные leaf certificates для server и client roles:

- server certificate содержит `serverAuth` EKU и DNS SAN внутреннего hostname;
- client certificate содержит `clientAuth` EKU и точный CN из ingress allowlist;
- private key доступен только runtime user, рекомендуемый mode `0400` или `0440`;
- CA bundle содержит только доверенные внутренние roots/intermediates;
- wildcard и публичный CA не заменяют service identity allowlist.

Reference runtime по умолчанию повторно использует service certificate для
outbound mTLS, чтобы конфигурация оставалась запускаемой. Такой сертификат обязан
иметь одновременно `serverAuth` и `clientAuth`. Для production предпочтительны
отдельные client credentials через outbound variables ниже.

## 3. Director configuration

Ingress HTTPS и проверка Gateway client identity:

- `DIRECTOR_TLS_CERT_PATH`;
- `DIRECTOR_TLS_KEY_PATH`;
- `DIRECTOR_TLS_CA_PATH`;
- `DIRECTOR_ALLOWED_PEER_CNS`, default `agent-gateway`, пустой список запрещён.

Outbound Director -> Gateway:

- `DIRECTOR_GATEWAY_CLIENT_CERT_PATH`, default `DIRECTOR_TLS_CERT_PATH`;
- `DIRECTOR_GATEWAY_CLIENT_KEY_PATH`, default `DIRECTOR_TLS_KEY_PATH`;
- `DIRECTOR_GATEWAY_CA_PATH`, default `DIRECTOR_TLS_CA_PATH`.

Workload identity:

- `DIRECTOR_WORKLOAD_SIGNING_KEY_ID` и
  `DIRECTOR_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64(_FILE)` выпускают token с
  `iss=director-api`, `aud=agent-gateway`;
- `GATEWAY_WORKLOAD_VERIFY_KEYS_JSON(_FILE)` проверяет входящий
  `iss=agent-gateway`, `aud=director-api`;
- `DIRECTOR_WORKLOAD_TOKEN_TTL_SECONDS`, default `60`, диапазон `10..300`.

## 4. Gateway configuration

Ingress HTTPS и проверка Director client identity:

- `GATEWAY_TLS_CERT_PATH`;
- `GATEWAY_TLS_KEY_PATH`;
- `GATEWAY_TLS_CA_PATH`;
- `GATEWAY_ALLOWED_PEER_CNS`, default `director-api`, пустой список запрещён.

Outbound Gateway -> Director:

- `GATEWAY_DIRECTOR_CLIENT_CERT_PATH`, default `GATEWAY_TLS_CERT_PATH`;
- `GATEWAY_DIRECTOR_CLIENT_KEY_PATH`, default `GATEWAY_TLS_KEY_PATH`;
- `GATEWAY_DIRECTOR_CA_PATH`, default `GATEWAY_TLS_CA_PATH`.

Workload identity:

- `GATEWAY_WORKLOAD_SIGNING_KEY_ID` и
  `GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64(_FILE)` выпускают token с
  `iss=agent-gateway`, `aud=director-api`;
- `DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON(_FILE)` проверяет входящий
  `iss=director-api`, `aud=agent-gateway`;
- `GATEWAY_WORKLOAD_TOKEN_TTL_SECONDS`, default `60`, диапазон `10..300`.

Private key хранится как canonical base64 PKCS8 DER. Verification keyset является
однострочным JSON вида
`{"schema_version":1,"keys":[{"kid":"director-a","public_key_base64":"<SPKI-DER-base64>"}]}`
и содержит от одного до восьми Ed25519 public keys.

## 5. Runtime invariants

- production client без origin-scoped mTLS dispatcher не стартует;
- `rejectUnauthorized` всегда `true` на outbound transport;
- dispatcher прикреплён к конкретному client instance, а не установлен global;
- redirects запрещены, поэтому workload token/capability не уходят на другой origin;
- новый token с уникальным `jti` выпускается перед каждым HTTP-вызовом;
- token с TTL больше пяти минут, неизвестным `kid`, неверным audience, будущим
  `iat/nbf` или истёкшим `exp` отклоняется;
- connection pools закрываются при graceful shutdown;
- PEM, signing private key и workload token не попадают в log/audit metadata.

## 6. Ротация

1. Добавить новый CA в trust bundles вместе со старым и перезапустить receivers.
2. Выпустить новые leaf certificates с теми же service identities.
3. Перезапустить callers с новыми client certificates, закрыв старые pools.
4. Проверить оба направления и internal authentication failures.
5. Перевести server certificates и снова проверить оба направления.
6. После окончания overlap удалить старый CA из bundles и перезапустить services.

При изменении CN сначала разрешаются старое и новое имена через comma-separated
allowlist, затем переключаются callers, и только после проверки удаляется старое
имя.

Signing keys ротируются отдельно для каждого направления:

1. Выпустить новую Ed25519 key pair и добавить новый public key в keyset receiver.
2. Перезапустить receiver и доказать, что он принимает старый и новый `kid`.
3. Переключить caller на новый private key и `SIGNING_KEY_ID`.
4. Выполнить target canary, включая expired и wrong-audience negative cases.
5. Выждать максимальный TTL плюс clock skew, удалить старый public key и
   уничтожить старый private key в secret manager.

## 7. Проверка и остаточный риск

Reference tests запрещают network fallback через `MockAgent`, проверяют выбор
origin-scoped dispatcher, protected startup, expiry, audience binding, signature
tampering и overlap rotation. Target canary предъявляет свежий token и доказывает
отказ для отсутствующего, malformed, истёкшего и wrong-audience token в обоих
направлениях.
Ephemeral-CA smoke дополнительно проходит реальный TLS handshake в обоих
направлениях и подтверждает отказ без client certificate. Он не доказывает
корректность конкретных production PEM, SAN, EKU, DNS и CA chain. Перед pilot
обязателен отдельный test с реально выпущенными сертификатами и обоими services.
