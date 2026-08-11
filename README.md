# Архитектура знаний

Репозиторий фиксирует восстановленный и подтвержденный контекст проекта
«Дирижёр» и связанные материалы.

## Текущий статус

Проект находится на стадии архитектурной спецификации и исполнимого reference
vertical slice. Подтвержденная часть архитектуры перенесена в документы ниже.
Все технические спецификации v1, включая SQL и OpenAPI, остаются
архитектурными черновиками до отдельного утверждения.
Коллективное изучение начинается с [руководства для reviewer](REVIEWING.md).

## Основные документы

- [Контекст проекта «Дирижёр»](docs/dirizhor/context.md)
- [Конституция проекта](docs/dirizhor/constitution.md)
- [Модель корпоративной памяти](docs/dirizhor/corporate-memory.md)
- [Границы модулей](docs/dirizhor/module-boundaries.md)
- [Первая модель данных](docs/dirizhor/data-model-v1.md)
- [Director API v1](docs/dirizhor/director-api-v1.md)
- [OpenAPI 3.1 v1](api/openapi-v1.yaml)
- [Agent Gateway Protocol v1](docs/dirizhor/agent-gateway-v1.md)
- [Reference Agent Gateway](gateway/reference/README.md)
- [Reference Director](director/reference/README.md)
- [Reference UI](ui/reference/README.md)
- [Auth/RBAC v1](docs/dirizhor/auth-rbac-v1.md)
- [OIDC/SSO boundary v1](docs/dirizhor/oidc-sso-v1.md)
- [OIDC/SSO operational runbook](docs/dirizhor/oidc-operations-runbook.md)
- [Service mTLS profile v1](docs/dirizhor/service-mtls-v1.md)
- [Reference deployment profile](deploy/reference/README.md)
- [PostgreSQL schema v1](docs/dirizhor/postgresql-schema-v1.md)
- [Production database migration runbook](db/production-migration-runbook.md)
- [Backup and restore v1](docs/dirizhor/backup-restore-v1.md)
- [Target infrastructure conformance runbook](deploy/reference/target-conformance-runbook.md)
- [Container runtime contract v1](deploy/reference/container-runtime-contract.md)
- [Kubernetes target deployment v1](deploy/reference/kubernetes-target-runbook.md)
- [Automated target canary v1](deploy/reference/target-canary-runbook.md)
- [Automated application canary v1](deploy/reference/application-canary-runbook.md)
- [Automated application failure canary v1](deploy/reference/application-failure-canary-runbook.md)
- [MVP-сценарии](docs/dirizhor/mvp-scenarios.md)
- [Архитектурные запреты](docs/dirizhor/architecture-guardrails.md)
- [Роли AI-агентов](docs/dirizhor/ai-roles.md)
- [Правила работы Codex](docs/dirizhor/codex-operating-rules.md)
- [Дорожная карта](docs/dirizhor/roadmap.md)
- [Психологический портрет](docs/profile/psychological-portrait.md)

## Важное ограничение

Полный текст «Психологического портрета» в предоставленном материале отсутствует.
Документ создан как отдельное место для восстановления, без добавления
неподтвержденных психологических выводов.
