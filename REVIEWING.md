# Ревью архитектурной модели «Дирижёр»

Этот репозиторий передаётся коллегам для архитектурного ревью. Он
содержит версионируемый черновик спецификаций и исполнимый reference vertical
slice, но не является утверждённым production deployment.

## Что именно рецензируется

Ревью должно ответить на пять вопросов:

1. Соответствует ли модель целям и реальным сценариям «Дирижёра»?
2. Ясны ли ownership, границы модулей и источники истины?
3. Не может ли AI, Gateway, UI или operator обойти Auth/RBAC, confirmation
   и audit?
4. Согласованы ли данные, API, SQL, runtime и deployment contracts?
5. Доказуемы ли startup, degradation, recovery, rollback и stop-ship criteria?

Дизайн UI, cloud provider selection, конкретные production secrets и цены не
утверждаются в этом ревью.

## Маршрут чтения

Первый проход обязателен для всех ролей и занимает 60–90 минут:

1. [Контекст проекта](docs/dirizhor/context.md).
2. [Конституция](docs/dirizhor/constitution.md).
3. [MVP-сценарии](docs/dirizhor/mvp-scenarios.md).
4. [Границы модулей](docs/dirizhor/module-boundaries.md).
5. [Архитектурные запреты](docs/dirizhor/architecture-guardrails.md).

Второй проход зависит от роли:

| Роль | Документы | Главный результат |
| --- | --- | --- |
| Product/domain | [Корпоративная память](docs/dirizhor/corporate-memory.md), [модель данных](docs/dirizhor/data-model-v1.md), [AI-роли](docs/dirizhor/ai-roles.md) | Термины, lifecycle и сценарии верны |
| Application/API | [Director API](docs/dirizhor/director-api-v1.md), [OpenAPI](api/openapi-v1.yaml), [Gateway protocol](docs/dirizhor/agent-gateway-v1.md) | HTTP contracts и state transitions согласованы |
| Security | [Auth/RBAC](docs/dirizhor/auth-rbac-v1.md), [OIDC](docs/dirizhor/oidc-sso-v1.md), [mTLS](docs/dirizhor/service-mtls-v1.md) | Trust boundaries и deny/confirm/audit не обходятся |
| Data | [PostgreSQL schema](docs/dirizhor/postgresql-schema-v1.md), [migrations](db/production-migration-runbook.md), [backup/restore](docs/dirizhor/backup-restore-v1.md) | Persistence, migration и recovery contracts полны |
| Platform/SRE | [Deployment profile](deploy/reference/README.md), [Kubernetes](deploy/reference/kubernetes-target-runbook.md), [conformance](deploy/reference/target-conformance-runbook.md) | Release, rollout, failure и rollback evidence достаточны |
| Engineering | [Reference Director](director/reference/README.md), [Reference Gateway](gateway/reference/README.md), [Reference UI](ui/reference/README.md) | Reference code соответствует спецификациям |

## Как фиксировать замечания

Одно замечание описывает одну проблему и содержит:

- файл и заголовок или точный API/schema element;
- тип: `contradiction`, `missing_decision`, `security_risk`, `operability`,
  `terminology` или `editorial`;
- фактическое последствие;
- предлагаемое решение или вопрос, который нужно решить;
- severity: `blocking`, `major` или `minor`.

`blocking` используется, если противоречие может нарушить authorization,
целостность данных, confidentiality, recovery или однозначность core API.
Предпочтителен issue или inline review в системе контроля версий; исправление
текста без обсуждения не заменяет architecture decision.

## Когда ревью завершено

Модель можно переводить из черновика в approved baseline, когда:

1. Каждая ролевая дорожка имеет назначенного reviewer.
2. Все `blocking` и `major` замечания закрыты или приняты явным decision owner.
3. Нерешённые residual risks и `NOT_RUN` evidence не скрыты за статусом
   «технически готово».
4. API, SQL, diagrams, examples и reference tests приведены к одной версии.
5. Независимый reviewer подтвердил baseline commit и его review package
   preflight.

Формальный результат фиксируется через
[architecture review gate](deploy/reference/architecture-review-runbook.md).
Его `PASS` требует все шесть завершённых дорожек, отсутствие открытых
`blocking`/`major`, явные решения по закрытым замечаниям и отдельного final
reviewer. JSON с именами и замечаниями хранится в игнорируемом
`review-output/`, а не в публикуемом baseline.

## Безопасная выдача доступа

Коллегам выдаётся read-only доступ к exact Git commit или tag. Доступ к
Kubernetes, PostgreSQL, secret manager, CI signing identity и production evidence storage
для изучения модели не нужен.

Перед публикацией из корня чистого Git-снимка выполняется:

```bash
node deploy/reference/scripts/review-package-preflight.mjs
```

Любой `FAIL`, dirty worktree, неотслеживаемые файлы, private key, credential
pattern, runtime state, target evidence или broken local link блокируют выдачу
доступа к этому snapshot.

Если reviewer отдельно получает release evidence, его нельзя считать
проверенным только по наличию JSON. Сначала выполняется проверка внутренних
хешей и закрытых прав:

```bash
node deploy/reference/scripts/release-evidence-verify.mjs \
  /secure/change/CHG-123/release-evidence
```

Для подтверждения исходных и build-файлов вторым аргументом передаётся
сохранённый builder workspace. В отчёте должны быть
`verification_scope=evidence_and_workspace`, `workspace_match=PASS` и четыре
`artifact_match=PASS`. Даже этот результат не доказывает registry digest,
подпись OCI artifact или target readiness: они проверяются отдельными gates.
