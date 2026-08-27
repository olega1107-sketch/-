# Pilot monitoring and alerting gap

Статус: `NOT_RUN`.

Поиск всего репозитория не обнаружил фактические `PrometheusRule`, Prometheus,
Alertmanager, `ServiceMonitor`, `PodMonitor`, Grafana dashboard или другой
alert-rules manifest. Требования существуют только в runbook. Поэтому наличие
monitoring stack, scrape targets, rules, routing и delivery не доказано.

## Минимально отсутствующая конфигурация

### Collection

- metrics collector и storage/retention policy;
- `ServiceMonitor`/эквивалент для Edge, Director и Gateway;
- Kubernetes pod/node metrics;
- managed PostgreSQL metrics integration;
- внешний HTTPS uptime/TLS check для `pilot.baza.fyi`.

### Alert rules

- public/readiness unavailable более 120 секунд;
- Edge 5xx rate более 1% за 5 минут; Edge 4xx anomaly отдельным сигналом;
- Director/Gateway error rate и p95 latency более 1500 мс;
- OIDC discovery/start/callback/provider failures;
- PostgreSQL connection saturation, lock contention и replica lag;
- PostgreSQL WAL/archive lag более 300 секунд;
- Document Store read/write/hash errors и backup age более 1800 секунд;
- Gateway queue age/backlog; точный threshold должен быть утверждён до rule;
- audit write failure больше нуля;
- unexpected pod restarts, unavailable replicas и node pressure;
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

- Alertmanager/эквивалент с назначенным incident/alerts receiver;
- severity и grouping/inhibition policy;
- test firing каждого stop-ship класса;
- timestamps send/delivery/ack и opaque alert reference;
- доказательство доставки ответственному без публикации email, webhook secret
  или receiver credentials.

Статическая конфигурация может закрыть только design review. Для
`operations.observability=PASS` требуется настоящее test firing и подтверждённая
доставка.
