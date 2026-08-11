# Service mTLS profile v1

Статус: архитектурный черновик v1 и исполнимый reference transport.

Документ определяет двусторонний TLS-профиль внутренних вызовов между Director
и Agent Gateway. Bearer остаётся вторым независимым фактором service
authentication; один bearer без проверенного клиентского сертификата не
разрешает internal endpoint.

## 1. Матрица доверия

| Вызов | Server certificate | Client certificate | Ingress allowlist |
| --- | --- | --- | --- |
| Director -> Gateway | DNS SAN соответствует host из `GATEWAY_BASE_URL` | CN `director-api` | `GATEWAY_ALLOWED_PEER_CNS` |
| Gateway -> Director | DNS SAN соответствует host из `DIRECTOR_BASE_URL` | CN `agent-gateway` | `DIRECTOR_ALLOWED_PEER_CNS` |

В protected mode оба URL обязаны использовать HTTPS и не могут содержать
credentials, query или fragment. Клиент проверяет server chain и hostname
через явно заданный CA bundle. Сервер проверяет client chain, после чего
authenticator проверяет CN и bearer constant-time сравнением.

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

## 5. Runtime invariants

- production client без origin-scoped mTLS dispatcher не стартует;
- `rejectUnauthorized` всегда `true` на outbound transport;
- dispatcher прикреплён к конкретному client instance, а не установлен global;
- redirects запрещены, поэтому bearer/capability не уходят на другой origin;
- connection pools закрываются при graceful shutdown;
- PEM, private key и bearer не попадают в log/audit metadata.

## 6. Ротация

1. Добавить новый CA в trust bundles вместе со старым и перезапустить receivers.
2. Выпустить новые leaf certificates с теми же service identities.
3. Перезапустить callers с новыми client certificates, закрыв старые pools.
4. Проверить оба направления и internal authentication failures.
5. Перевести server certificates и снова проверить оба направления.
6. После окончания overlap удалить старый CA из bundles и перезапустить services.

При изменении CN сначала разрешаются старое и новое имена через comma-separated
allowlist, затем переключаются callers, и только после проверки удаляется старое
имя. Static service bearer пока принимает только одно значение; его безостановочная
ротация требует отдельного dual-key/short-lived workload identity механизма.

## 7. Проверка и остаточный риск

Reference tests запрещают network fallback через `MockAgent`, проверяют выбор
origin-scoped dispatcher, protected startup и пустые peer allowlists.
Ephemeral-CA smoke дополнительно проходит реальный TLS handshake в обоих
направлениях и подтверждает отказ без client certificate. Он не доказывает
корректность конкретных production PEM, SAN, EKU, DNS и CA chain. Перед pilot
обязателен отдельный test с реально выпущенными сертификатами и обоими services.
