# Director API

Нормативный HTTP-контракт первого MVP находится в
[`openapi-v1.yaml`](openapi-v1.yaml). Архитектурные границы и правила его
чтения описаны в
[спецификации Director API](../docs/dirizhor/director-api-v1.md).
Статус артефакта — архитектурный черновик v1.

В [`director/reference/`](../director/reference/) реализован первый публичный
vertical slice `POST /api/v1/memory-objects:upload` и внутренний Gateway-facing
slice. Это проверка отдельных контрактов, а не реализация всего публичного API.

## Валидация

```bash
pnpm --package=@redocly/cli@2.46.0 dlx redocly lint \
  --config api/redocly.yaml api/openapi-v1.yaml
```

Правило `info-license` отключено локально, потому что лицензия проекта еще не
определена. Остальной recommended-набор Redocly остается активным.

Генерируемые SDK и серверные заглушки не должны редактироваться
вместо контракта. Изменения API сначала вносятся в OpenAPI, затем
сверяются с Auth/RBAC и PostgreSQL-схемой.
