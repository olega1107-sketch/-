# Kubernetes target deployment v1

Статус: production-oriented pilot profile. Renderer создаёт проверяемые
Kubernetes JSON manifests, но сам по себе не доказывает конкретный cluster,
CSI, LoadBalancer, secret manager или managed PostgreSQL provider. Schema v3
дополнительно требует Cilium `cilium.io/v2` и проверяется на target API server.

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

Schema v1 сохраняется только для совместимости и всегда означает внешний
`LoadBalancer`. Schema v2 добавляет internal-first exposure: значение
`public.exposure=internal` используется до завершения internal canaries, а
`public.exposure=load-balancer` — только после отдельного approval. В internal
mode `load_balancer_source_ranges` сохраняет историческое имя поля, но задаёт
разрешённые source CIDR для Edge NetworkPolicy; это должны быть фактические
target pod/canary CIDR, а не documentation ranges.

Для DOKS rollout используется schema v3. Она сохраняет все правила schema v2 и
добавляет `networking.oidc_egress_fqdns` и
`networking.ai_provider_egress_fqdns`. Renderer создаёт отдельные
`CiliumNetworkPolicy` с exact `matchName` и TCP/443 для Director и Gateway.
Wildcard и `matchPattern` запрещены. Для каждого внешнего направления должен
быть задан хотя бы один CIDR или FQDN; публичные endpoints с изменяемыми IP
используют FQDN, а не зафиксированный снимок DNS-адресов. До render оператор
сверяет exact имена с OIDC discovery и утверждённым AI API origin.

Schema v4 добавляет явный external-only профиль для пилота без внутреннего
inference provider. В нём `internal_provider` и
`secrets.gateway_internal_provider_tls` равны `null`,
`networking.internal_provider_egress_cidrs` является пустым массивом, а
`agent_routes` не содержит `provider=internal`. Renderer не создаёт для
Gateway internal-provider environment, token reference, TLS mount или egress.
Хотя бы один внешний route с непустой `provider_data_profile_version` остаётся
обязательным. Это профиль размещения, а не разрешение передавать внешнему AI
любые данные: project policy, Auth/RBAC, confirmation и frozen authorized
context применяются без изменений. Схемы v1-v3 по-прежнему требуют оба route.
Заполняемый образец находится в
`kubernetes-target-config.external-only.example.json`.

```bash
cd deploy/reference
node scripts/kubernetes-render.mjs \
  /secure/change/CHG-123/kubernetes \
  /secure/change/CHG-123/kubernetes-target-config.json
```

Output directory имеет mode `0700`, файлы — `0600`. Renderer выдаёт:

1. `00-prerequisites.json` — Namespace, ServiceAccounts, ConfigMaps, PVC,
   Services, NetworkPolicy, optional schema-v3 CiliumNetworkPolicy и Edge PDB.
   Schema v2/v3 с `public.exposure=internal`
   создаёт Edge `ClusterIP` без load-balancer annotations; внешний
   `LoadBalancer` разрешён только отдельным утверждённым render с
   `public.exposure=load-balancer`;
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
Schema v3 дополнительно требует, чтобы target API server принял оба
`CiliumNetworkPolicy`; отсутствие CRD или отклонение `toFQDNs` является
stop-ship.

Если target namespace ещё не существует, API server не может проверить
namespaced resources из того же bundle, где объявлен Namespace. До approval на
создание пустого target namespace допускается только structural dry-run:
создать временную копию утверждённого config с `namespace` существующего
validation namespace, отрендерить её в новый каталог и выполнить четыре
server-side dry-run. Такой результат проверяет API schema/admission, но не
namespace-specific policy и не является deployment evidence. Временные
manifests запрещено применять. После отдельного approval и создания пустого
target namespace все четыре dry-run обязательно повторяются без подмены
namespace.

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
| `gateway_runtime` | `spool-key-base64`, `openai-api-key`; `internal-provider-token` только при настроенном `internal_provider` |
| `gateway_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `gateway_director_client_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `gateway_probe_client_tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `gateway_internal_provider_tls` | `tls.crt`, `tls.key`, `ca.crt`; значение `null` для schema-v4 external-only |
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
- Gateway -> internal provider: CN `agent-gateway-internal-provider`, `clientAuth`
  (только если internal provider настроен).

Server certificates имеют только `serverAuth`; trust chains и private key
permissions проходят `certificate-preflight.mjs`. При включённом
`INTERNAL_PROVIDER_ORIGIN` preflight проверяет пятую identity; её CA bundle
должен проверять provider server и issuer client leaf. Probe identity не даёт
bearer token и может обращаться только к generic health endpoints внутри Pod.

## 5. Apply order

1. Сверить config image digests с OCI release evidence и target cluster minor.
2. Если target namespace отсутствует, выполнить structural dry-run в
   существующем validation namespace и сохранить его только как preflight.
3. Получить отдельный approval, создать пустой target namespace и выполнить
   четыре exact server-side dry-run в нём.
4. Для первого internal rollout проверить `public.exposure=internal`, применить
   prerequisites и дождаться Bound PVC. `LoadBalancer` на этом этапе является
   stop-ship; внешний service создаётся только после internal canaries отдельным
   утверждённым schema-v2 render.
5. Синхронизировать external secrets и проверить только object/key presence.
6. Проверить certificates, PostgreSQL TLS и свежий recovery point.
7. Применить migration Job, дождаться `condition=complete` и сохранить logs.
8. Применить runtime privilege Job, дождаться `condition=complete`, сохранить
   JSON report и проверить `status=PASS`; любой другой исход блокирует rollout.
9. Выполнить отдельный runtime `db:status`; pending/dirty/diverged блокирует rollout.
10. Применить workloads, дождаться rollout и проверить probes/events. Internal
   Edge проверяется из разрешённого canary source CIDR по ClusterIP/service DNS.
11. После internal canaries утвердить public host, source ranges и provider
    annotations, повторно отрендерить schema v2 с
    `public.exposure=load-balancer` и выполнить server-side dry-run до изменения
    Service.
12. Выполнить `target-canary-preflight.mjs`; только после `PASS` запустить
   `target-canary.mjs` для external Host/TLS, OIDC discovery/start,
   mTLS+short-lived-workload-token и exact project scope, затем завершить browser MFA и выполнить
   отдельный `application-canary.mjs`. Его internal route должен соответствовать
   реальному internal adapter/deployment, а не переклассифицированному cloud route.
13. В отдельном change window выполнить PostgreSQL startup-guard harness и
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
