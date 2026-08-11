# Director

Публичный контракт Director API находится в
[`api/openapi-v1.yaml`](../api/openapi-v1.yaml). Внутренний контракт с Agent
Gateway находится в [`gateway/openapi-v1.yaml`](../gateway/openapi-v1.yaml).
Оба контракта остаются архитектурными черновиками v1.

Исполнимый [`reference/`](reference/) реализует один публичный vertical slice
`POST /api/v1/memory-objects:upload` и внутренний slice, нужный Gateway:
одноразовое получение замороженного контекста и идемпотентный приём lifecycle
events. Остальные публичные endpoint Director API в этом runtime ещё не
реализованы.
