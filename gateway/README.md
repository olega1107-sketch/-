# Agent Gateway

Машиночитаемый внутренний контракт находится в
[`openapi-v1.yaml`](openapi-v1.yaml). Архитектурные правила, порядок событий и
границы MVP описаны в
[`docs/dirizhor/agent-gateway-v1.md`](../docs/dirizhor/agent-gateway-v1.md).
Статус обоих артефактов — архитектурный черновик v1.

Исполнимый reference Gateway находится в [`reference/`](reference/). Он
проверяет lifecycle контракта, содержит fixture adapter и первый реальный
adapter для OpenAI Responses API. Это проверяемый эталон границ протокола, а не
готовая распределенная production-служба.

Ответная сторона внутреннего протокола реализована в
[`director/reference/`](../director/reference/); там же находится сквозной тест
обоих reference services.

## Валидация

```bash
pnpm --package=@redocly/cli@2.46.0 dlx redocly lint \
  --config api/redocly.yaml gateway/openapi-v1.yaml
```

Публичный Director API не должен экспонировать эти endpoint. Они доступны
только workload identities `director-api` и `agent-gateway` во внутренней сети.
