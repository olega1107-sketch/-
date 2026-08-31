# Technical operational review — Dirizhor Cloud Pilot

Дата: 27 августа 2026 года.

Источник: внешний design/runbook review и фактическая проверка ветки
`codex/architecture-review-v1.16`. Этот документ исправляет operational-часть
`dirizhor-pilot-review-report2.md`. Он не заменяет target conformance evidence.

## Operational evidence update — 31 August 2026

This addendum supersedes the earlier `NOT_RUN` statements below only for
Backup/Restore and monitoring collection. It does not treat a prepared route,
static rule, or an undelivered alert as delivery evidence.

| Area | Current status | Evidence |
| --- | --- | --- |
| PostgreSQL native PITR | `PASS` | Managed PITR Drill A demonstrated RPO upper bound `25.176 sec` and full verification within the 60 minute target. See `managed-pitr-drill-a-2026-08-30.md`. |
| Document Store recovery | `PASS` | R6 demonstrated RPO `22.055 sec`, RTO `26m55.262s`, and the post-remediation active manifest `6/6`, with zero missing files, hash mismatches and canonical orphans. See `document-store-recovery-r6-2026-08-30.md` and `r5-synthetic-reference-remediation-2026-08-31.md`. |
| Prometheus collection and rules | `PASS` | Private Prometheus, Alertmanager and operator Pods are Running. Director, both Edge targets and Gateway were `UP` on 31 August. The live `dirizhor-pilot` rule contains target-down, readiness 120 seconds, HTTP 5xx 1 percent/5 minutes, p95 1500ms and OIDC callback rules. |
| Alert routing and delivery | `PASS` | Private `AlertmanagerConfig` and relay are applied. A controlled critical test reached Resend over HTTPS and the designated recipient confirmed both `FIRING` and `RESOLVED` email delivery. See `alerting-resend-delivery-2026-08-31.md`. |
| Formal adoption | `BLOCKED` | Owner values are approved, but the complete report still lacks independent sign-off and real evidence references. |

The remaining GA blocker is formal adoption. Additional exporter/rule coverage
remains a documented operational warning, not evidence for a non-existent
delivery failure.

## Итог

Pilot пока не готов к GA. Блокеры относятся к operational evidence, а не к
необходимости переработать архитектуру.

| Область | Текущий статус | Точная причина |
| --- | --- | --- |
| Formal adoption | `BLOCKED` | Числа подготовлены, проверены validator и подтверждены owner, но нет полного `APPROVED` report с реальными evidence refs и независимым adoption sign-off |
| Backup and restore | `PASS` | Managed PostgreSQL PITR Drill A и Document Store Recovery R6 завершены на изолированных recovery resources в пределах утверждённых RPO/RTO; см. operational update выше |
| Alerting and dashboards | `WARN` | Private Prometheus, Alertmanager, ServiceMonitor и application rules применены; targets `UP`, critical routing и controlled `FIRING`/`RESOLVED` delivery доказаны. Дополнительные PostgreSQL, backup/restore, queue и audit exporters/rules ещё не получили live coverage. |
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

Статус `PASS` по двум отдельным изолированным drills. Managed PostgreSQL PITR
Drill A подтвердил native PITR с RPO upper bound `25.176 sec`; R6 подтвердил
Document Store recovery с RPO `22.055 sec`, RTO `26m55.262s`, active manifest
`6/6`, zero missing files, hash mismatches и canonical orphans. Полные
временные шкалы, integrity checks и cleanup зафиксированы в
[`managed-pitr-drill-a-2026-08-30.md`](managed-pitr-drill-a-2026-08-30.md),
[`document-store-recovery-r6-2026-08-30.md`](document-store-recovery-r6-2026-08-30.md)
и [`r5-synthetic-reference-remediation-2026-08-31.md`](r5-synthetic-reference-remediation-2026-08-31.md).

Restore drill не является единственным live-test gate. Alerting test firing и
доставка ответственному теперь подтверждены; сохраняется задача расширить
live coverage дополнительных operational signals.

## Alerting and dashboards

В кластере есть private Prometheus, Alertmanager, operator, `PrometheusRule`
и ServiceMonitor для Director, двух Edge target'ов и Gateway. На 31 августа
все application targets были `UP`; базовые rules покрывают target-down,
readiness 120 seconds, HTTP 5xx 1 percent/5 minutes, p95 1500 ms, OIDC
callback и control-plane failures. Private `AlertmanagerConfig` и relay
применены. Controlled `FIRING` и `RESOLVED` test events были приняты Resend и
подтверждённо доставлены ответственному; evidence приведён в
[`alerting-resend-delivery-2026-08-31.md`](alerting-resend-delivery-2026-08-31.md).
Следовательно, route/delivery имеет `PASS`, а общий раздел остаётся `WARN`
только из-за неразвёрнутых дополнительных exporters/rules.

Непокрытые metric/exporter signals перечислены в
[monitoring gap](../../deploy/reference/pilot-monitoring-gap.md). Даже после
добавления правил `PASS` требует test event, route/receiver delivery и
подтверждения ответственным; статическая конфигурация сама по себе недостаточна.

## Residual risks

Фактически перечислено 5 рисков:

1. Formal adoption ещё не имеет полного `APPROVED` evidence.
2. Resend остаётся внешней HTTPS-зависимостью critical notification route.
3. Director и Gateway остаются single point of failure в pilot-профиле.
4. Дополнительные PostgreSQL, Document Store, queue и audit exporters/rules
   пока подготовлены только как metric contract, а не как live coverage.
5. Долгоживущий адрес `pilot.baza.fyi` требует явного решения перед production GA.

Пункты 3 и 5 являются принятыми или управляемыми рисками и не должны ошибочно
считаться отдельными незакрытыми `PASS`/`FAIL` gates.

## Честный остаток до Pilot Ready/GA

1. Внедрить и проверить дополнительные operational exporters/rules либо
   оформить их как явный pilot scope exclusion.
2. После появления alert/dashboard evidence оформить полный adoption
   report и независимый review без фиктивных references.
3. Запустить общий conformance validator. Любой оставшийся `NOT_RUN` продолжает
   блокировать GA.
