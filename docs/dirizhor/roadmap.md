# Дорожная карта

Проект находится на стадии архитектурной спецификации и исполнимого reference
vertical slice. В предыдущих материалах существовал черновик ТЗ примерно на
уровне 5-10%.

## Основные следующие этапы

1. Конституция проекта. Статус: черновик создан.
2. Границы модулей. Статус: черновик создан.
3. Модель корпоративной памяти. Статус: черновик создан.
4. Первая модель данных. Статус: черновик и исполнимая SQL-схема v1 созданы.
5. Реестр данных и документов. Статус: схема и API v1 созданы; public document
   upload, карточка объекта и project-scoped поиск с visibility-фильтрами и
   keyset pagination реализованы.
6. Протокол взаимодействия AI-агентов. Статус: внутренний OpenAPI и lifecycle
   Agent Gateway v1 созданы как архитектурный черновик; reference Gateway,
   fixture adapter, OpenAI Responses adapter, reference Director для internal
   endpoints и public frozen dispatch для trusted-configured internal/external
   provider реализованы.
7. API Дирижёра. Статус: сценарный документ и OpenAPI 3.1 v1 созданы;
   Gateway-facing internal slice, public upload, Memory Registry read/search,
   task create/context/timeline, agent-run dispatch/read, result read/save и
   public confirmation get/approve/reject реализованы. Отдельный
   исполнимый pilot-профиль фиксирует точный поднабор этих операций,
   включая create/read/provenance для draft/proposed решений.
8. Авторизация и права доступа. Статус: черновик v1 создан; upload и dispatch
   применяют project-scoped permissions, условные права для чувствительного
   контекста, project AI policy и повторную проверку перед commit/retry;
   external, bulk context share и сохранение AI-результата проходят
   confirmation workflow; public opaque session verifier проверяет hash, expiry,
   revoke и active user непосредственно в PostgreSQL; явно включаемый local
   password login выдаёт и отзывает текущую session с атомарным audit; corporate
   OIDC Code + PKCE boundary выдаёт HttpOnly Director session только для
   pre-provisioned issuer/sub identity и защищён от callback replay;
   discovery fail-closed проверяет exact issuer, HTTPS endpoints, PKCE S256,
   token auth и закреплённый asymmetric ID Token algorithm; provisioning,
   RP-initiated logout и revoke-all оформлены исполнимыми операторскими flows;
   permission/policy deny создаёт immutable authorization decision и
   `access.denied`, включая concealed `404`; успешные immediate/replay public
   business flows создают `allow` decision и связанную success/access audit-запись.
9. Журналирование. Статус: базовые требования зафиксированы; internal
   agent lifecycle и confirmation transitions пишут audit атомарно с изменением
   состояния; allow и success/access audit коммитятся вместе с разрешённой
   операцией, а deny decision и `access.denied` — атомарно после rollback
   запрещённой business operation.
10. Резервное копирование. Статус: v1-спецификация, synthetic PostgreSQL
    dump/restore harness, проверка согласованности Document Store и read-only
    verifier восстановленной копии реализованы; provider-native base backup/WAL
    и PITR drill остаются проверкой целевой инфраструктуры.
11. MVP. Статус: сценарии описаны; public task create, upload, registry search,
   internal frozen dispatch, external confirmation/dispatch, result read,
   подтверждённое сохранение `ai_result` и task timeline связаны reference
   E2E-тестами без seed операционных сущностей. Создание человеческого
   draft/proposed решения, его чтение и fail-closed reconstruction связей,
   запусков агентов, точных версий источников и audit также реализованы
   в API и responsive UI.
12. Подключение ChatGPT. Статус: первый OpenAI Responses adapter реализован;
    backend policy/confirmation flow и точный per-agent/provider routing готовы;
    local/OIDC session flow, project selector API и responsive cookie-aware
    confirmation UI готовы; остаётся deployment с реальным корпоративным IdP.
13. Подключение Codex. Статус: после deployment hardening identity/policy слоя.
14. Подключение специализированных агентов. Статус: после MVP.

## Новые документы технического слоя

- [Границы модулей](module-boundaries.md)
- [Первая модель данных](data-model-v1.md)
- [Director API v1](director-api-v1.md)
- [OpenAPI 3.1 v1](openapi-v1.md)
- [Pilot OpenAPI 3.1 v1](../../api/openapi-pilot-v1.yaml)
- [Agent Gateway Protocol v1](agent-gateway-v1.md)
- [Reference Agent Gateway](../../gateway/reference/README.md)
- [Reference Director](../../director/reference/README.md)
- [Reference UI](../../ui/reference/README.md)
- [Auth/RBAC v1](auth-rbac-v1.md)
- [OIDC/SSO boundary v1](oidc-sso-v1.md)
- [OIDC/SSO operational runbook](oidc-operations-runbook.md)
- [PostgreSQL schema v1](postgresql-schema-v1.md)
- [Backup and restore v1](backup-restore-v1.md)
- [Target infrastructure conformance runbook](../../deploy/reference/target-conformance-runbook.md)
- [MVP-сценарии](mvp-scenarios.md)
- [Архитектурные запреты](architecture-guardrails.md)

## Текущий ближайший пробел

SQL-схема PostgreSQL, Auth/RBAC, Director OpenAPI 3.1 и Agent Gateway Protocol
v1 созданы на уровне контрактов. Reference E2E проходит public task
create, document upload, frozen agent-run dispatch, capability redeem, provider lifecycle,
staged result и terminal audit через оба HTTP ingress и полную SQL-схему.
Task/run/context/capability в этом сценарии больше не создаются SQL seed-ом.

Policy/confirmation для external provider, большого контекста и сохранения
AI-результата реализован вместе с public read endpoints task/run/result.
Memory Registry read/search, task context search и task timeline также
реализованы с фильтрацией чувствительности до пагинации. Per-agent/provider
routing выбирает точный startup-configured маршрут и сохраняет его при retry;
identity/session verifier немедленно учитывает expiry, revoke и active user.
Local password session issuance/revocation реализован с scrypt, hash-only token
storage и audit. Corporate OIDC Authorization Code + PKCE S256 реализован с
server-side one-time transaction, pre-provisioned issuer/sub identity,
HttpOnly Director session cookie и SSO-first UI. Discovery conformance,
preflight, stdin-only provisioning, local-first RP logout и audited revoke-all
реализованы; реальный IdP canary остаётся инфраструктурной проверкой. `allow`, `deny` и
`require_confirmation` decisions со связанным
success/access audit реализованы для всех текущих public business endpoints.
Pilot API вынесен в отдельный machine-readable OpenAPI-профиль. Public Director
создаёт `draft`/`proposed` решения, возвращает их полное provenance и
проводит `approved`/`rejected`/`superseded` переходы через frozen confirmation
с повторной проверкой requester/approver RBAC, sensitivity и payload hash. Document
body, prompt и AI-response в audit не выдаются.
Reference deployment/reverse-proxy профиль, trusted-proxy boundary, mounted
secret files, dependency readiness, certificate preflight и ephemeral two-way
mTLS smoke реализованы.
Versioned PostgreSQL migration runner, verified adoption существующей schema v1,
startup schema guard, `expand/backfill/validate/contract` runbook и
двухсоединенческий contention harness также реализованы. Backup/restore v1,
synthetic logical restore и связанная проверка PostgreSQL/Document Store также
реализованы. Единый conformance registry, строгий evidence template и
fail-closed validator не позволяют считать `FAIL`, `NOT_RUN` или неполный
отчёт успешным. Multi-stage OCI contracts с digest-only base images, non-root
runtime и read-only filesystem profile оформлены. Fail-closed OCI release
orchestrator реализует multi-platform build/push, registry digest verification,
CycloneDX SBOM, Trivy policy, Cosign image/SBOM signing и защищённый evidence;
его отказные сценарии покрыты synthetic tests. Фактический запуск на approved
builder и registry остаётся внешним release gate со статусом `NOT_RUN`. Следующий
Kubernetes target renderer теперь формирует digest-only prerequisites,
migration Job и workloads с restricted PSS, default-deny NetworkPolicy,
external-secret boundary, RWO PVC и защищённым render evidence. Runtime migrator
скомпилирован в Director production image. Server-side dry-run и фактический
apply остаются target gate со статусом `NOT_RUN`. Fail-closed target canary
runner теперь автоматизирует live DNS/TLS, внешний edge contract, OIDC
discovery/start, обе стороны mTLS+Bearer и точный project scope browser-issued
session без записи секретов в evidence. Следующий продуктовый срез — фактическое
заполнение conformance gate на целевой инфраструктуре: server-side apply,
полный corporate IdP browser/MFA и mutating application canary, contention,
provider PITR и operations evidence.

Origin-scoped исходящий client-mTLS transport между Director и Gateway
реализован в обоих направлениях; ephemeral CA handshake проходит. До
production-профиля ещё нужны проверка реальных CA/SAN/EKU и запуск готового
contention harness на целевом PostgreSQL: локально реальный PostgreSQL server
отсутствует, а PGlite не доказывает поведение нескольких DB connections.
По той же причине локально не доказаны provider-native base backup/WAL/PITR,
реальный restore recovery set и утверждённые организацией RPO/RTO.

Отдельный содержательный пробел — восстановление «Психологического портрета».
В предоставленном материале его полного текста нет, поэтому документ не должен
заполняться неподтвержденными выводами.
