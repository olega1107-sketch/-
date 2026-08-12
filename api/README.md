# Director API

Целевой нормативный HTTP-контракт первого MVP находится в
[`openapi-v1.yaml`](openapi-v1.yaml). Исполнимая поверхность текущего reference
deployment выделена в отдельный
[`openapi-pilot-v1.yaml`](openapi-pilot-v1.yaml). Клиенты пилота должны
генерироваться только по pilot-профилю: наличие операции в полном контракте не
означает, что она уже зарегистрирована runtime. Архитектурные границы и правила чтения описаны в
[спецификации Director API](../docs/dirizhor/director-api-v1.md).
Статус артефакта — архитектурный черновик v1.

Pilot-профиль включает рабочий task/agent/result/confirmation flow, registry
read/search, создание `draft`/`proposed` решений и чтение полной доступной
provenance-цепочки. `approved` decision и `supersede` намеренно исключены, пока
для них не реализован отдельный frozen confirmation flow.

## Валидация

```bash
pnpm --package=@redocly/cli@2.46.0 dlx redocly lint \
  --config api/redocly.yaml api/openapi-v1.yaml
pnpm --package=@redocly/cli@2.46.0 dlx redocly lint \
  --config api/redocly.yaml api/openapi-pilot-v1.yaml
```

Правило `info-license` отключено локально, потому что лицензия проекта еще не
определена. Остальной recommended-набор Redocly остается активным.

Генерируемые SDK и серверные заглушки не должны редактироваться
вместо контракта. Изменения API сначала вносятся в OpenAPI, затем
сверяются с Auth/RBAC и PostgreSQL-схемой.
