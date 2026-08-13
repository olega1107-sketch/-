# Kubernetes target deployment v1

Статус: production-oriented pilot profile. Renderer создаёт проверяемые
Kubernetes JSON manifests, но не доказывает конкретный cluster, CNI, CSI,
LoadBalancer, secret manager или managed PostgreSQL provider.

## 1. Граница профиля

В cluster размещаются Edge, Director, Agent Gateway, PVC, migration Job и
одноразовый read-only runtime privilege Job.
PostgreSQL не разворачивается как StatefulSet: используется утверждённый
managed PostgreSQL 15+ с TLS, backup/PITR и отдельными runtime/DDL credentials.

Director и Gateway в pilot имеют по одной replica и `Recreate` strategy,
поскольку их текущие filesystem stores используют RWO PVC и не являются
распределёнными. Edge имеет минимум две replicas, rolling update, topology
spread и PodDisruptionBudget. Масштабирование stateful services выше одной
replica запрещено до shared Document Store и распределённого Gateway store.
До rollout decision owner обязан утвердить этот риск, допустимое окно простоя,
SLO/RPO/RTO, владельцев и alert thresholds через
`pilot-adoption-decision.mjs`. Без `gate_status=PASS` проверка
`operations.adoption_decisions` остаётся `NOT_RUN` и блокирует rollout.

## 2. Render

`kubernetes-target-config.example.json` использует `.invalid`, documentation
CIDRs и placeholder policy values. Его нельзя применять к cluster. На каждый
rollout создаётся утверждённая копия с digest references из успешного
`oci-release-evidence.json`:

```bash
cd deploy/reference
node scripts/kubernetes-render.mjs \
  /secure/change/CHG-123/kubernetes \
  /secure/change/CHG-123/kubernetes-target-config.json
```

Output directory имеет mode `0700`, файлы — `0600`. Renderer выдаёт:

1. `00-prerequisites.json` — Namespace, ServiceAccounts, ConfigMaps, PVC,
   Services, NetworkPolicy и Edge PDB;
2. `10-migration-job.json` — одноразовая expand/validate migration;
3. `15-runtime-privilege-job.json` — проверка effective прав runtime-роли;
4. `20-workloads.json` — Edge, Director и Gateway Deployments;
5. `render-evidence.json` — apply order, counts и SHA-256 каждого bundle.

Secret resources и secret values не генерируются. Все bundles сначала проходят
admission и schema validation на target API server:

```bash
kubectl apply --dry-run=server -f 00-prerequisites.json
kubectl apply --dry-run=server -f 10-migration-job.json
kubectl apply --dry-run=server -f 15-runtime-privilege-job.json
kubectl apply --dry-run=server -f 20-workloads.json
```

Client-only dry-run недостаточен: он не доказывает Pod Security Admission,
provider admission policies, StorageClass или Service annotations.

## 3. External secrets

Secrets создаёт только утверждённый external secret controller или оператор.
Required object/key inventory:

| Config key | Required data keys |
| --- | --- |
| `image_pull` | `.dockerconfigjson` |
| `director_workload_identity` | `signing-private-key-base64`, `gateway-verification-keys-json` |
| `gateway_workload_identity` | `signing-private-key-base64`, `director-verification-keys-json` |
| `director_runtime` | `database-url`, `capability-key-base64`, `oidc-client-secret` |
| `director_database` | `database-url` (тот же runtime PostgreSQL credential, без других Director secrets) |
| `director_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `director_gateway_client_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `gateway_runtime` | `spool-key-base64`, `openai-api-key`, `internal-provider-token` |
| `gateway_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `gateway_director_client_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `gateway_probe_client_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `gateway_internal_provider_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `edge_tls` | `tls.crt`, `tls.key` |
| `edge_director_ca` | `ca.crt` |
| `postgres_ca` | `ca.crt` |
| `migration_database` | `database-url` |

Projected files имеют mode `0440`; Pod `fsGroup=10001` является разрешённой
группой чтения. Secrets не передаются через command arguments, ConfigMap или
literal environment values. Signing private key доступен только своему caller,
а receiver получает public verification keyset противоположного сервиса.
Runtime PostgreSQL credential не имеет DDL-прав; `migration_database` существует
только на время migration Job. Поля `postgresql.database_name` и
`postgresql.runtime_role` задают exact identity, которую privilege Job обязан
увидеть через runtime credential; это не секреты.

## 4. PKI identities

Service certificate DNS SAN должен точно совпадать с generated cluster DNS:

- Director server: `dirizhor-director.<namespace>.svc.<cluster_domain>`;
- Gateway server: `dirizhor-gateway.<namespace>.svc.<cluster_domain>`;
- Edge public server: exact `public.host`.

Client identities:

- Director -> Gateway: CN `director-api`, `clientAuth`;
- Gateway -> Director: CN `agent-gateway`, `clientAuth`;
- Gateway local readiness probe: CN `gateway-probe`, `clientAuth`.
- Gateway -> internal provider: CN `agent-gateway-internal-provider`, `clientAuth`.

Server certificates имеют только `serverAuth`; trust chains и private key
permissions проходят `certificate-preflight.mjs`. При включённом
`INTERNAL_PROVIDER_ORIGIN` preflight проверяет пятую identity; её CA bundle
должен проверять provider server и issuer client leaf. Probe identity не даёт
bearer token и может обращаться только к generic health endpoints внутри Pod.

## 5. Apply order

1. Сверить config image digests с OCI release evidence и target cluster minor.
2. Выполнить четыре server-side dry-run.
3. Применить prerequisites; дождаться Bound PVC и provisioned LoadBalancer.
4. Синхронизировать external secrets и проверить только object/key presence.
5. Проверить certificates, PostgreSQL TLS и свежий recovery point.
6. Применить migration Job, дождаться `condition=complete` и сохранить logs.
7. Применить runtime privilege Job, дождаться `condition=complete`, сохранить
   JSON report и проверить `status=PASS`; любой другой исход блокирует rollout.
8. Выполнить отдельный runtime `db:status`; pending/dirty/diverged блокирует rollout.
9. Применить workloads, дождаться rollout и проверить probes/events.
10. Выполнить `target-canary-preflight.mjs`; только после `PASS` запустить
   `target-canary.mjs` для external Host/TLS, OIDC discovery/start,
   mTLS+short-lived-workload-token и exact project scope, затем завершить browser MFA и выполнить
   отдельный `application-canary.mjs`. Его internal route должен соответствовать
   реальному internal adapter/deployment, а не переклассифицированному cloud route.
11. В отдельном change window выполнить PostgreSQL startup-guard harness и
    `application-failure-canary.mjs` по его
    [runbook](application-failure-canary-runbook.md).

```bash
kubectl apply -f 00-prerequisites.json
kubectl apply -f 10-migration-job.json
job_name="$(jq -r '.items[0].metadata.name' 10-migration-job.json)"
kubectl wait --for=condition=complete --timeout=15m "job/$job_name"
kubectl logs "job/$job_name"
kubectl apply -f 15-runtime-privilege-job.json
privilege_job="$(jq -r '.items[0].metadata.name' 15-runtime-privilege-job.json)"
kubectl wait --for=condition=complete --timeout=5m "job/$privilege_job"
kubectl logs "job/$privilege_job"
kubectl apply -f 20-workloads.json
kubectl rollout status deployment/dirizhor-edge --timeout=10m
kubectl rollout status deployment/dirizhor-director --timeout=10m
kubectl rollout status deployment/dirizhor-gateway --timeout=10m
```

Workloads нельзя применять параллельно с migration Job или до privilege report
со статусом `PASS`. Failed Job, unbound PVC, Pod Security rejection, image digest
mismatch, failed readiness или NetworkPolicy connectivity failure являются
stop-ship.

## 6. Network and storage evidence

Namespace начинает с default-deny ingress/egress. Разрешены только DNS, Edge ->
Director, Director <-> Gateway, PostgreSQL CIDR, OIDC CIDR, отдельный internal
provider CIDR и external AI provider CIDR.
CIDR должны происходить из target provider records; documentation ranges и
`0.0.0.0/0` запрещены. Конкретный CNI обязан подтвердить поведение `ipBlock` для
LoadBalancer source IP и доступ kubelet probes.

StorageClass должен обеспечивать encryption at rest, volume expansion,
snapshot/restore и утверждённую reclaim policy. PVC сам по себе не закрывает
backup/PITR gate. Director Document Store и PostgreSQL должны восстанавливаться
как единый recovery set согласно Backup and restore v1.

## 7. Rollback

До contract migration application rollback возвращает предыдущие digest-only
images, сохраняя additive schema. PVC и migration history не удаляются.
Автоматический rollback не выполняет destructive SQL и не удаляет Job evidence.
После contract допустим только forward fix или provider restore по утверждённым
RPO/RTO.
