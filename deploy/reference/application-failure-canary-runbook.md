# Automated application failure canary v1

Статус: production-oriented destructive evidence runner для pilot target.
Synthetic tests проверяют state machine, но не создают target evidence.

## 1. Назначение

`scripts/application-failure-canary.mjs` проверяет в реальном Kubernetes target:

1. exact `kubectl` patch version, context, namespace, deployment ID, digest-only
   images и по одной replica Director/Gateway;
2. baseline liveness/readiness и mode `0700` обоих persistent roots;
3. Director `live=200`, `ready=503` при временно удалённом
   PostgreSQL egress и восстановление `ready=200`;
4. тот же контракт при mode `0000` Document Store и Gateway state root;
5. доступность Director при `Gateway replicas=0` и восстановление Gateway;
6. SIGTERM обоих Node PID 1, exit code `0`, exact shutdown marker,
   рост restart count ровно на единицу и восстановление readiness;
7. ссылки на отдельное primary canary и real PostgreSQL startup-guard
   evidence.

Health body должен оставаться ровно `{"status":"ok"}` или
`{"status":"unavailable"}`. Exception, path, hostname и credential в ответе
блокируют gate.

## 2. Предусловия

Запуск разрешён только в утверждённом change window, когда:

- deployment рендерился текущим `kubernetes-render.mjs`, а Director и
  Gateway имеют `Recreate` и по одной replica;
- CNI доказанно применяет NetworkPolicy egress; целевые PostgreSQL
  CIDR/port точно совпадают с rendered policy;
- нет concurrent rollout, autoscaler, policy reconciler, PVC maintenance или
  другого fault injection;
- `target-canary` и `application-canary` прошли на этом deployment;
- оператор имеет namespace-scoped права `get/list` Pods/Deployments,
  `pods/exec`, `pods/log`, `deployments/scale`, `get/update` целевой
  NetworkPolicy и не имеет доступа к Secrets;
- наблюдаются alerts, Pod events и application error rates;
- approved `00-prerequisites.json` и `20-workloads.json` доступны для
  аварийного восстановления.

Runner использует ambient short-lived Kubernetes authentication, но не читает
и не записывает token, kubeconfig или Secret values. Каждая команда
получает explicit `--context` и `--namespace`; `kubectl_path` абсолютный.

## 3. PostgreSQL startup guards

На отдельной пустой PostgreSQL 15+ database, которую разрешено
полностью очистить, выполнить:

```bash
cd director/reference
export DIRECTOR_STARTUP_GUARD_EXPECT_DATABASE=dirizhor_startup_guard_chg_123
export DIRECTOR_STARTUP_GUARD_DATABASE_URL_FILE=/run/secrets/startup-guard/database-url
export DIRECTOR_STARTUP_GUARD_DATABASE_CA_PATH=/run/secrets/startup-guard/ca.crt
pnpm db:test-startup-guards
```

Harness сверяет exact database name, отказывается от `postgres` и
`template*`, требует ноль user objects, накатывает current manifest и
вызывает тот же `assertDatabaseMigrationsCurrent`, что production startup.
Он доказывает отказ при `applying`, checksum drift и pending history, а
затем удаляет схемы `dirizhor` и `dirizhor_migrations`.

Единственная stdout-строка со `status=PASS` и тремя scenarios сохраняется
как protected artifact. URL, database name и SQL error body в неё не попадают.

## 4. Kubernetes canary

Начать с `application-failure-canary-config.example.json` и заменить все
documentation values. `kubectl_client_version` содержит exact patch,
`deployment_id` совпадает с Deployment annotations, а PostgreSQL CIDR берутся
из того же approved target config.

```bash
cd deploy/reference
node scripts/application-failure-canary.mjs \
  /secure/change/CHG-123/application-failure-canary \
  /secure/change/CHG-123/application-failure-canary-config.json
```

Exit codes:

- `0`: все 8 checks и restore verification имеют `PASS`;
- `1`: evidence создан, failed check и зависимые `NOT_RUN` блокируют gate;
- `2`: config/invocation/output некорректны; такой запуск не canary.

Output directory получает mode `0700`, report — `0600`. Новый fault не
начинается, если предыдущий check и его restore не дали `PASS`.
Попытка restore выполняется и при timeout/обрыве ответа мутирующей
команды.

## 5. Emergency restore

`finally` не защищает от SIGKILL evidence host, его потери или полной
недоступности API server. При таком событии немедленно:

1. применить approved `00-prerequisites.json`, чтобы вернуть rendered
   Director NetworkPolicy;
2. вернуть `deployment/dirizhor-gateway` к одной replica;
3. через `kubectl exec` вернуть mode `0700` для
   `/var/lib/dirizhor/documents` и `/var/lib/dirizhor/gateway`;
4. дождаться обоих readiness, проверить alerts/events и повторить
   primary application canary с новым execution ID;
5. открыть incident; не повторять failure canary до независимой
   проверки target state.

## 6. Evidence boundary

Report хранит только statuses, durations, счётчики, булевы признаки
восстановления, deployment ID match и opaque evidence refs. Он не содержит
kubeconfig, token, Secret, Pod UID/name, filesystem path, NetworkPolicy body или logs.

`application.failure_modes=PASS` в report — proposed registry update. Reviewer
сверяет deployment/time window, все restore observations, startup-guard artifact,
primary canary после recovery и alerts. Любой missing artifact, `FAIL`,
`NOT_RUN`, unexpected restart, `SIGKILL`, невосстановленный fault или несовпавший
target identity являются stop-ship.
