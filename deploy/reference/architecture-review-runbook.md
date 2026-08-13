# Architecture review gate v1

Этот gate фиксирует результат коллективного ревью точного Git baseline. Он не
заменяет обсуждение, а не позволяет выдать незавершённое ревью за одобрение.

## Подготовка

1. Скопировать
   [`architecture-review-template-v1.json`](conformance/architecture-review-template-v1.json)
   в игнорируемый каталог `review-output/`.
2. Указать полный commit, аннотированный tag и `report_sha256` успешного
   `review-package-preflight.mjs`.
3. Скопировать
   [`reviewer-assignments-template-v1.json`](reviewer-assignments-template-v1.json)
   в защищённый или игнорируемый каталог и заменить восемь значений
   `replace-*` на opaque ID: decision owner, независимого final reviewer и
   reviewer для каждой из шести дорожек из [руководства](../../REVIEWING.md).
4. Использовать только непрямые идентификаторы людей и evidence, без токенов,
   URL с credentials или содержимого закрытых документов.

Назначения применяются к исходному, полностью неназначенному review plan и
всегда создают новый файл:

```bash
node scripts/reviewer-assignments.mjs \
  /secure/review/ARCH-2026-001/architecture-review-plan.json \
  /secure/review/ARCH-2026-001/reviewer-assignments.json \
  /secure/review/ARCH-2026-001/architecture-review-assigned.json
```

Генератор требует точный состав полей, назначает все шесть дорожек сразу со
статусом `IN_REVIEW`, проверяет независимость final reviewer и создаёт output с
mode `0600`. Существующий файл не перезаписывается. Один reviewer может вести
несколько дорожек; final reviewer не может совпадать ни с одним из назначенных
owner/reviewer.

После создания review JSON сгенерировать рабочий пакет из exact clean baseline:

```bash
node scripts/reviewer-handoff.mjs \
  /secure/review/ARCH-2026-001/reviewer-packet \
  /secure/review/ARCH-2026-001/architecture-review-assigned.json
```

Генератор проверяет schema review, аннотированный tag, совпадение workspace
`HEAD` с baseline commit, чистый Git snapshot и наличие всех документов в
tracked source set. Новый output directory имеет mode `0700`; manifest и шесть
role briefs — `0600`. Ignored/untracked материалы, credentials и закрытое
evidence содержимое в пакет не переносятся.

`assignments_complete=false` допустим для планирования и означает, что briefs
можно изучать, но дорожки ещё не назначены. После заполнения opaque reviewer ID
пакет генерируется заново в новом каталоге. Даже
`assignments_complete=true` не является одобрением: завершение фиксирует только
основной architecture-review gate.

## Приём результатов

Ответ reviewer в Markdown сохраняется в protected evidence storage и получает
SHA-256. Его выводы нормализуются в копию
[`reviewer-result-template-v1.json`](reviewer-result-template-v1.json): exact
review/commit, reviewer ID, timestamp, hash исходного файла и полный набор всех
назначенных этому reviewer дорожек. Затем результаты применяются к новому review
JSON без перезаписи исходного:

```bash
node scripts/reviewer-results.mjs \
  /secure/review/ARCH-2026-001/architecture-review-assigned.json \
  /secure/review/ARCH-2026-001/architecture-review-progress-01.json \
  /secure/review/ARCH-2026-001/owner-result.json \
  /secure/review/ARCH-2026-001/product-result.json
```

Intake требует все дорожки назначенного reviewer сразу, проверяет exact baseline,
`source_sha256`, reviewer/track ownership и ссылки на открытые findings. Результат
`BLOCKED` оставляет дорожку `IN_REVIEW`; только `COMPLETE` добавляет timestamp и
completion evidence. Дорожку с открытым `blocking` или `major` замечанием
завершить нельзя. Повторное, частичное или чужое назначение отклоняется, output
создаётся с mode `0600` и не перезаписывается.

Запуск из корня репозитория:

```bash
node deploy/reference/scripts/architecture-review.mjs \
  review-output/architecture-review-v1.json
```

Коды завершения:

- `0`: `PASS`;
- `1`: корректный документ, но gate `BLOCKED`;
- `2`: документ или Git baseline невалиден.

На этапе планирования owner/reviewer может быть `null`: документ останется
валидным, но gate покажет `owners_unassigned` или `tracks_unassigned` и вернёт
`BLOCKED`. Для `IN_REVIEW`, `COMPLETE`, закрытого замечания и final decision
соответствующий opaque owner ID обязателен.

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

Versioned вопросы, документы и критерии шести briefs находятся в
[`reviewer-tracks-v1.json`](conformance/reviewer-tracks-v1.json). Изменение
registry требует нового Git baseline; локальная правка готового brief не
изменяет review contract и не считается evidence.
