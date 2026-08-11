# Architecture review gate v1

Этот gate фиксирует результат коллективного ревью точного Git baseline. Он не
заменяет обсуждение, а не позволяет выдать незавершённое ревью за одобрение.

## Подготовка

1. Скопировать
   [`architecture-review-template-v1.json`](conformance/architecture-review-template-v1.json)
   в игнорируемый каталог `review-output/`.
2. Указать полный commit, аннотированный tag и `report_sha256` успешного
   `review-package-preflight.mjs`.
3. Назначить decision owner, независимого final reviewer и reviewer для каждой
   из шести дорожек из [руководства](../../REVIEWING.md).
4. Использовать только непрямые идентификаторы людей и evidence, без токенов,
   URL с credentials или содержимого закрытых документов.

Запуск из корня репозитория:

```bash
node deploy/reference/scripts/architecture-review.mjs \
  review-output/architecture-review-v1.json
```

Коды завершения:

- `0`: `PASS`;
- `1`: корректный документ, но gate `BLOCKED`;
- `2`: документ или Git baseline невалиден.

## Дорожки и замечания

Обязательные дорожки: `product_domain`, `application_api`, `security`, `data`,
`platform_sre`, `engineering`. Дорожка `COMPLETE` требует timestamp и opaque
evidence reference вида `ticket:...`, `change:...`, `run:...` или
`artifact:...`.

Каждое замечание содержит тип, severity, точное location, последствие и статус.
Открытое замечание не может иметь resolution evidence. `RESOLVED` и
`ACCEPTED_RISK` требуют решения объявленного decision owner и evidence
reference.

Gate остаётся `BLOCKED`, если:

- хотя бы одна дорожка не завершена;
- открыт хотя бы один `blocking` или `major`;
- отсутствует время завершения;
- final reviewer не поставил `APPROVED`.

Открытые `minor` учитываются в отчёте, но не блокируют baseline. Final reviewer
не может совпадать с decision owner или reviewer любой ролевой дорожки.

## Связь с production evidence

Хэш PASS-отчёта сохраняется в защищённом evidence storage. Он является одним
из источников для `evidence.peer_review`, но не закрывает остальные target
conformance checks и не доказывает production readiness.

Валидатор доказывает полноту и непротиворечивость реестра, а также соответствие
аннотированного tag заявленному commit. Подлинность внешних ticket/change/run
references проверяет final reviewer в системе, которая этими объектами владеет.
