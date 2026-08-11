# Reference Agent Gateway

Исполнимый эталон внутреннего [Agent Gateway Protocol v1](../openapi-v1.yaml).
Он нужен для проверки границ Director/Gateway/provider и не является готовой
production-службой.

## Что реализовано

- Fastify ingress для `:execute` и `:cancel` с TypeBox runtime-схемами;
- пересчет RFC 8785/JCS fingerprints и SHA-256 content/event hashes;
- полная проверка ordered context bundle до provider call;
- AES-256-GCM file execution store с атомарной записью и mode `0600`;
- durable started/terminal event outbox и безопасная повторная доставка;
- отмена активного provider call через `AbortSignal`;
- recovery без повтора неопределенного provider call;
- фиксированный HTTP client к Director API с origin-scoped outbound mTLS и без
  callback URL из payload;
- fixture provider, external OpenAI Responses и internal corporate HTTP provider
  adapters;
- contract, lifecycle, recovery, encryption и adapter tests;
- `/health/live` и `/health/ready`: readiness проверяет read/write доступ к
  encrypted state directory без утечки exception details.

Сквозной HTTP protocol test с PostgreSQL-backed
[Reference Director](../../director/reference/README.md) находится в
[`director/reference/test/e2e.test.ts`](../../director/reference/test/e2e.test.ts).

OpenAI adapter требует model из Director request, отправляет `instructions` и
ordered `input`, явно ставит `store: false`, не предоставляет tools и отклоняет
неожиданный tool output. Binary context передается как `input_file` с data URI.
OpenAI adapter принимает только `deployment_class=external` с непустым
`provider_data_profile_version`.

Internal adapter принимает только `provider=internal`,
`deployment_class=internal`, `provider_data_profile_version=null` и model из
startup allowlist. Он вызывает только exact `${INTERNAL_PROVIDER_ORIGIN}/v1/generate`,
запрещает redirects, использует dedicated outbound mTLS identity и Bearer,
ограничивает response body и fail-closed сверяет run/model identity.

## Проверка

Требуется Node.js 22.18 или новее и pnpm.

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm lint
pnpm test
pnpm build
```

Тесты не обращаются к OpenAI или другим внешним сервисам.

## Локальный запуск

Незащищенный режим допустим только для локальной разработки:

```bash
export GATEWAY_ALLOW_INSECURE_DEV=true
export GATEWAY_ENABLE_FIXTURE_PROVIDER=true
export GATEWAY_HOST=127.0.0.1
export GATEWAY_PORT=8443
export GATEWAY_STATE_DIR="$PWD/.gateway-state"
export GATEWAY_SPOOL_KEY_BASE64="$(openssl rand -base64 32)"
export DIRECTOR_BASE_URL=http://127.0.0.1:8080
export DIRECTOR_SERVICE_TOKEN=local-gateway-to-director-token
export GATEWAY_DIRECTOR_TOKEN=local-director-to-gateway-token
pnpm dev
```

Для OpenAI adapter нужно задать `OPENAI_API_KEY`; fixture provider можно при
этом не включать. Provider и model по-прежнему выбирает Director, Gateway не
подставляет скрытый default model.

## Защищенный запуск

Без `GATEWAY_ALLOW_INSECURE_DEV=true` обязательны:

- `GATEWAY_TLS_CERT_PATH` — сертификат Gateway;
- `GATEWAY_TLS_KEY_PATH` — private key Gateway;
- `GATEWAY_TLS_CA_PATH` — CA для проверки клиентского сертификата;
- `GATEWAY_ALLOWED_PEER_CNS` — непустой список разрешенных CN, по умолчанию
  `director-api`;
- `GATEWAY_WORKLOAD_SIGNING_KEY_ID` и
  `GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64(_FILE)`;
- `DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON(_FILE)` — public Ed25519 keyset Director.

Outbound Gateway -> Director всегда использует mTLS. По умолчанию применяются
service certificate/key/CA выше. Для отдельных client credentials задаются
`GATEWAY_DIRECTOR_CLIENT_CERT_PATH`, `GATEWAY_DIRECTOR_CLIENT_KEY_PATH` и
`GATEWAY_DIRECTOR_CA_PATH`. Требования к SAN, EKU и ротации описаны в
[Service mTLS profile v1](../../docs/dirizhor/service-mtls-v1.md).

Для internal provider задаются `INTERNAL_PROVIDER_ORIGIN`,
`INTERNAL_PROVIDER_MODELS`, `INTERNAL_PROVIDER_TOKEN` и три dedicated TLS paths:
`INTERNAL_PROVIDER_CLIENT_CERT_PATH`, `INTERNAL_PROVIDER_CLIENT_KEY_PATH`,
`INTERNAL_PROVIDER_CA_PATH`. В protected mode origin обязан быть exact HTTPS DNS
origin, а неполная конфигурация блокирует startup.

Runtime credentials принимают ровно один источник: `NAME` или `NAME_FILE`.
Mounted files поддерживаются для `GATEWAY_SPOOL_KEY_BASE64`,
`GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64`,
`DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON`, `OPENAI_API_KEY` и
`INTERNAL_PROVIDER_TOKEN`.
Одновременное задание, пустые/multiline values и NUL отклоняются при старте.

Node HTTPS server запрашивает клиентский сертификат и отклоняет
неавторизованные соединения. Входной Ed25519 workload token дополнительно
проверяется по signature, `kid`, issuer, audience и сроку действия.

## Ограничения reference runtime

- file store и keyed lock рассчитаны на один процесс и один экземпляр;
- локальный outbox заменяет внешнюю durable queue;
- static inbound/outbound bearer разрешён только при `GATEWAY_ALLOW_INSECURE_DEV=true`;
- нет provider fallback, streaming, tools, retrieval, billing и UI;
- terminal metadata не очищается по TTL автоматически;
- ephemeral-CA smoke проходит в обоих направлениях, но конкретные production
  CA/SAN/EKU ещё требуют deployment test;
- нет production telemetry, KMS rotation и distributed lease.

Для production нужны PostgreSQL-backed execution store/outbox, внешняя выдача и
hot rotation workload signing keys, KMS-managed keys, distributed worker lease,
bounded cleanup и операционная observability. Эти замены проходят через порты
`ExecutionStore`, `DirectorClient`, `ServiceAuthenticator` и `ProviderAdapter`,
не меняя HTTP-протокол.
