# Container runtime contract v1

Статус: production-oriented draft. Контракт создаёт воспроизводимую границу
для Director, Agent Gateway и public Edge/UI, но не доказывает конкретный
registry, orchestrator или cloud environment.

## 1. Образы

Release содержит три независимо публикуемых OCI images:

- Director: `director/reference/Dockerfile`, internal HTTPS port `8444`;
- Agent Gateway: `gateway/reference/Dockerfile`, internal HTTPS port `8443`;
- Edge/UI: `deploy/reference/Dockerfile.edge`, public HTTPS port `8443` внутри
  container; Service/Load Balancer отображает внешний `443` на этот порт.

Dockerfiles не имеют default base image. Release pipeline обязан передать
canonical references `repository@sha256:<64 hex>` для build и runtime stages.
Mutable tags недостаточны. Node build image должен содержать Node.js 22.18+ и
ровно `pnpm 11.16.0`; Node runtime image — Node.js 22.18+. Nginx runtime image
должен содержать Nginx 1.25.1+, POSIX `sh`, `envsubst`, `stat`, `grep`, `cp` и
CA root bundle и поддерживать запуск numeric UID/GID `10001`.

Перед build:

```bash
cd deploy/reference
export DIRIZHOR_NODE_BUILD_IMAGE=registry.example/node-build@sha256:<digest>
export DIRIZHOR_NODE_RUNTIME_IMAGE=registry.example/node-runtime@sha256:<digest>
export DIRIZHOR_NGINX_RUNTIME_IMAGE=registry.example/nginx-runtime@sha256:<digest>
export DIRIZHOR_PNPM_VERSION=11.16.0
node scripts/container-preflight.mjs
```

`ARG` используется только для несекретных base references и версии package
manager. Registry/npm credentials нельзя передавать через `ARG` или `ENV`; если
они требуются, builder использует внешнюю registry authentication или BuildKit
secret mount. Текущий public dependency set не требует build secret.

## 2. Build и публикация

Build context — корень repository. Release выполняется единым orchestrator из
`deploy/reference`; example-конфигурация намеренно указывает `.invalid` registry
и должна быть заменена утверждённой конфигурацией change record:

```bash
cd deploy/reference
node scripts/oci-release.mjs \
  /secure/change/CHG-123/oci-release \
  /secure/change/CHG-123/oci-release-config.json
```

Orchestrator использует `docker buildx build --push` с maximal provenance и
BuildKit SBOM, проверяет `containerimage.digest` из metadata и raw registry
platform index, создаёт независимый CycloneDX SBOM через Syft, запускает Trivy
с предварительным обновлением и проверкой возраста vulnerability database,
запрещёнными suppressions и ненулевым exit code для утверждённых severities/EOL,
затем подписывает image и SBOM attestation через Cosign и немедленно проверяет
обе подписи. Tool versions, platforms и policy ID задаются явно; расхождение
блокирует release.

Deployment manifest ссылается только на полученный digest. Tag, локальный
`dist` hash и hash OCI archive не заменяют registry digest. Image digest,
attestation IDs, scanner policy/version и решение по исключениям входят в
защищённый release evidence.

## 3. Runtime identity

Все три images запускаются как UID/GID `10001:10001`. Orchestrator не
переопределяет их на root и применяет минимум:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

Privileged mode, host PID/IPC/network, hostPath, Docker socket и добавленные
Linux capabilities запрещены. AppArmor/SELinux profile применяется согласно
platform baseline. CPU/memory requests, limits и ephemeral storage limit
утверждаются нагрузочным профилем, а не берутся из reference defaults.

## 4. Writable mounts

Root filesystem остаётся read-only. Writable только отдельные volumes:

- Director: `DOCUMENT_STORE_ROOT`, владелец `10001:10001`, mode `0700`;
- Gateway: `GATEWAY_STATE_DIR`, владелец `10001:10001`, mode `0700`;
- Edge: memory-backed/ephemeral `/tmp` с size limit; application data там нет.

`/run/secrets` монтируется read-only. Private keys имеют mode `0400`, `0440`,
`0600` или `0640`; group-read допустим только если container GID действительно
является разрешённой группой. Projected secret symlink допустим, но target file
не writable для group/others.

Dockerfiles намеренно не объявляют `VOLUME`: storage class, encryption,
snapshot policy, retention и ownership задаёт orchestrator и проверяет
[Backup and restore v1](../../docs/dirizhor/backup-restore-v1.md).

## 5. Edge startup

Edge entrypoint принимает только allowlisted template values, требует
unprivileged listen port `1024+`, проверяет наличие TLS files и permissions
private key. Конфигурация рендерится в `/tmp/dirizhor-nginx`, проходит `nginx -t`
и только затем Nginx запускается foreground-процессом.

`PUBLIC_LISTEN_PORT` задаёт container port (`8443`), а
`DIRECTOR_PUBLIC_PORT` — фактический внешний port (`443`), передаваемый в
`X-Forwarded-Port`. Смешивать их при TLS termination/port mapping запрещено.

Root filesystem не изменяется. Public certificate, key и Director upstream CA
монтируются соответственно как `/run/secrets/public-tls.crt`,
`/run/secrets/public-tls.key` и
`/run/secrets/director-upstream-ca.crt`.

## 6. Probes и shutdown

Director и Gateway получают `SIGTERM`, закрывают listeners/outbound pools и
завершаются в пределах orchestrator grace period. Edge использует `SIGQUIT` для
graceful Nginx shutdown. Kill timeout проверяется на target; `SIGKILL` не
считается graceful result.
Успешный Node shutdown пишет ровно один bounded completion marker; failure-mode
canary сверяет marker, exit code `0` и рост container restart count на единицу.

Liveness/readiness обращаются к Director/Gateway напрямую по protected network.
Edge не публикует эти endpoints. Probe credentials или client keys не
встраиваются в image layers.

## 7. Stop-ship

Release блокируется при mutable/unapproved base image, несовпадении pnpm/Node,
root runtime, writable root filesystem, добавленных capabilities, отсутствии
SBOM/provenance/signature, unresolved vulnerability выше утверждённого порога,
неприкреплённом deployment image или несовпадении фактического digest с
release evidence.

## Нормативные основания

- [Docker build best practices](https://docs.docker.com/build/building/best-practices/);
- [Docker multi-stage builds](https://docs.docker.com/build/building/multi-stage/);
- [Docker build secrets](https://docs.docker.com/build/building/secrets/);
- [Docker Buildx build metadata and attestations](https://docs.docker.com/reference/cli/docker/buildx/build/);
- [Docker Buildx raw image index inspection](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/);
- [Sigstore container signing and attestations](https://docs.sigstore.dev/cosign/signing/signing_with_containers/);
- [Trivy image scan policy options](https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/);
- [Syft SBOM generator](https://github.com/anchore/syft);
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/);
- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).
