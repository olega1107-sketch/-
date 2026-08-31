# Pilot monitoring and alerting gap

Статус: `PARTIAL`.

В репозитории есть статические `PrometheusRule`, `ServiceMonitor` для
application и monitoring control-plane, Helm values для private
Prometheus/Alertmanager и private Resend webhook relay. Они
покрывают availability, readiness 120 seconds, HTTP 5xx 1 percent/5 minutes,
p95 1500 ms, OIDC callback 5xx и control-plane reload/delivery failures.
Director PostgreSQL/Document Store readiness, authorization-audit write failures
и Gateway queue age/scan failures уже публикуются application runtime и
собираются private Prometheus. Их отдельные alert rules всё ещё требуют
controlled firing и evidence доставки.
Статическая конфигурация не заменяет runtime evidence: каждый target, правило,
routing path и фактическая доставка должны быть проверены отдельно.

## Минимально отсутствующая конфигурация

### Collection

- Kubernetes pod/node metrics;
- managed PostgreSQL metrics integration;
- внешний HTTPS uptime/TLS check для `pilot.baza.fyi`.

### Alert rules

- Edge 4xx anomaly; threshold требует отдельного утверждения;
- OIDC discovery/start/provider failures вне callback 5xx;
- PostgreSQL connection saturation, lock contention и replica lag;
- PostgreSQL WAL/archive lag более 300 секунд;
- Document Store read/write/hash errors и backup age более 1800 секунд;
- Gateway queue depth; rule для oldest pending execution более 5 минут применён,
  но требует controlled firing и evidence доставки;
- audit write failure больше нуля; rule и metric contract применены, но требуют
  controlled firing и evidence доставки;
- unexpected pod restarts, unavailable replicas и node pressure, когда будет
  включён источник Kubernetes metrics;
- certificate expiry и failed renewal для public TLS.

### Dashboard

- availability/error-budget burn за 30 дней;
- request rate, 4xx/5xx и p50/p95/p99 latency;
- OIDC failures;
- Director/Gateway readiness, restarts and queue;
- PostgreSQL connections/locks/lag/WAL archive;
- Document Store errors, backup age и restore-drill age;
- audit write failures и certificate expiry.

### Routing and live evidence

- Private Alertmanager -> webhook relay -> Resend HTTPS delivery for critical
  alerts: `PASS`. A controlled synthetic `FIRING` and its automatic `RESOLVED`
  state were accepted by Resend and confirmed by the designated recipient. See
  `docs/dirizhor/alerting-resend-delivery-2026-08-31.md`.
- severity and grouping policy: `PASS` for the critical route. The relay accepts
  only `severity=critical`; Alertmanager groups by alert name and service.
- Each separate stop-ship signal still requires its own real or controlled
  firing before that signal is claimed as verified.
- SMTP remains disabled; the relay permits only private DNS and HTTPS to
  `api.resend.com`.

`operations.observability` remains `PARTIAL`: routing/delivery is no longer
`NOT_RUN`, but the missing collection and rule coverage above is not claimed as
live evidence.
