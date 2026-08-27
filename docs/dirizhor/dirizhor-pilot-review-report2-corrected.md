# Technical operational review — Dirizhor Cloud Pilot

Дата: 27 августа 2026 года.

Источник: внешний design/runbook review и фактическая проверка ветки
`codex/architecture-review-v1.16`. Этот документ исправляет operational-часть
`dirizhor-pilot-review-report2.md`. Он не заменяет target conformance evidence.

## Итог

Pilot пока не готов к GA. Блокеры относятся к operational evidence, а не к
необходимости переработать архитектуру.

| Область | Текущий статус | Точная причина |
| --- | --- | --- |
| Formal adoption | `BLOCKED` | Числа подготовлены, проверены validator и подтверждены owner, но нет полного `APPROVED` report с реальными evidence refs и независимым adoption sign-off |
| Backup and restore | `NOT_RUN` | Нет evidence реального isolated PostgreSQL PITR и связанного Document Store recovery set |
| Alerting and dashboards | `NOT_RUN` | В репозитории отсутствует фактическая monitoring configuration; test firing и доставка alert не доказаны |
| Single-replica Director/Gateway и `Recreate` | `ACCEPTED RISK` | Owner принял риск только для pilot; это не отдельный `PASS`/`FAIL` gate |
| Residual risks | 5 пунктов | Это перечень рисков, а не самостоятельный conformance gate |

Нельзя утверждать, что «ни один из шести gates не PASS»: строки исходной
сводки не являются шестью однородными conformance gates. Single-replica и
`Recreate` являются принятым pilot-риском, а residual risks — сводным перечнем.

## Adoption decision

Owner утвердил следующие значения:

- SLO: 99% за 30 дней;
- error budget: 7 часов 12 минут;
- planned outage: 15 минут;
- unplanned outage: 30 минут;
- PostgreSQL RPO: 15 минут;
- Document Store RPO: 60 минут;
- Full Restore RTO: 60 минут;
- Failover RTO: 15 минут;
- backup retention: 30 дней;
- readiness alert: 120 секунд;
- HTTP error threshold: 1% за 5 минут;
- HTTP p95: 1500 мс;
- single-replica Director/Gateway и `Recreate` outage приняты только для pilot.

Эти значения структурно прошли `pilot-adoption-decision.mjs`. Корректный
статус — formal adoption всё ещё `BLOCKED`, а не `PASS`: отсутствуют
подтверждённые поля `approval.status=APPROVED`, `approval.decided_at` и реальные
`approval.evidence_refs`, включающие approval change/ticket, maintenance/risk
references, alert policy и dashboard. Design-review report не подменяет
независимый sign-off полного adoption/target evidence.

## Backup and restore

Статус `NOT_RUN`, не `FAIL`. Synthetic harness и runbook существуют, но они не
доказывают provider PITR. Для `PASS` требуется один полный isolated restore
drill по [плану](../../deploy/reference/pilot-restore-drill-plan.md), включая:

- новую PostgreSQL identity, восстановленную до выбранной PITR point;
- связанный Document Store recovery set;
- migration и Document Store manifest verification;
- readiness, OIDC, RBAC, document-read и task/timeline/audit continuity;
- фактически измеренные PostgreSQL/Document Store RPO и Full Restore RTO.

Restore drill не является единственным live-test gate. Alerting отдельно
требует реального test firing и доказанной доставки ответственному.

## Alerting and dashboards

Полный поиск репозитория не обнаружил `PrometheusRule`, `Prometheus`,
`Alertmanager`, `ServiceMonitor`, `PodMonitor`, Grafana dashboards или иной
фактической alert-rules configuration. Найдены только требования в runbook и
future-stage notes. Поэтому `operations.observability` остаётся `NOT_RUN`.

Минимальный отсутствующий набор зафиксирован в
[monitoring gap](../../deploy/reference/pilot-monitoring-gap.md). Даже после
добавления правил `PASS` требует test event, route/receiver delivery и
подтверждения ответственным; статическая конфигурация сама по себе недостаточна.

## Residual risks

Фактически перечислено 5 рисков:

1. Formal adoption ещё не имеет полного `APPROVED` evidence.
2. Реальный PITR/Document Store restore drill не выполнен.
3. Director и Gateway остаются single point of failure в pilot-профиле.
4. Фактическая monitoring/alerting configuration и test delivery отсутствуют.
5. Долгоживущий адрес `pilot.baza.fyi` требует явного решения перед production GA.

Пункты 3 и 5 являются принятыми или управляемыми рисками и не должны ошибочно
считаться отдельными незакрытыми `PASS`/`FAIL` gates.

## Честный остаток до Pilot Ready/GA

1. Создать и проверить реальные alert rules, dashboards и routing; провести
   test firing с evidence доставки.
2. Провести isolated restore drill и зафиксировать фактические RPO/RTO.
3. После появления alert/dashboard/restore evidence оформить полный adoption
   report и независимый review без фиктивных references.
4. Запустить общий conformance validator. Любой оставшийся `NOT_RUN` продолжает
   блокировать GA.

