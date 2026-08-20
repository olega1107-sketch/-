# Reference deployment profile

Статус: проверяемый production-oriented шаблон, не готовый cloud deployment.

Профиль размещает UI и public Director API за одним HTTPS origin. Agent Gateway
и internal Director routes не публикуются через edge proxy.

```text
Browser / Corporate IdP
          |
          v
   Nginx public HTTPS
      |           |
      |           +-- static UI dist
      v
Director protected HTTPS <---- mTLS ----> Agent Gateway
      |
      +---- TLS ----> PostgreSQL
```

## Файлы

- `nginx/nginx.conf.template` — edge listener, static UI, rate limits и routes;
- `nginx/director-proxy.conf.template` — проверяемый TLS upstream и header policy;
- `nginx/security-headers.conf` — единый набор response security headers;
- `env.example` — только несекретные параметры template rendering;
- `scripts/certificate-preflight.mjs` — fail-closed проверка до пяти service
  certificate profiles;
- `scripts/conformance-evidence.mjs` — fail-closed валидатор target evidence;
- `scripts/pilot-adoption-decision.mjs` и
  `pilot-adoption-decision-template-v1.json` — проверяемое утверждение SLO,
  outage limits, RPO/RTO, owners, alert thresholds и рисков pilot profile;
- `scripts/release-evidence.mjs` — изолированный сбор release evidence для
  Director, Gateway и UI; все frozen offline installs завершаются до первой
  cross-package проверки, фактическая версия pnpm сверяется с package metadata,
  а source scope строится только из чистого набора Git tracked regular files;
- `scripts/container-preflight.mjs` — статическая проверка OCI build/runtime
  contracts и canonical base image references;
- `scripts/oci-release.mjs` и `oci-release-config.example.json` — fail-closed
  multi-platform build/push, registry digest, SBOM, scan, signing и release evidence;
- `scripts/kubernetes-render.mjs`, `kubernetes-target-config.example.json`,
  `kubernetes-target-config.external-only.example.json` и
  `kubernetes-target-runbook.md` — строгий target renderer с schema-v2
  internal-first `ClusterIP` exposure, schema-v3 exact-FQDN egress для Cilium,
  schema-v4 external-only AI profile без неиспользуемых internal-provider
  полномочий, legacy schema-v1 `LoadBalancer`, external secret/PKI inventory и
  последовательностью migration-before-workloads;
- `scripts/target-canary.mjs`, `target-canary-config.example.json` и
  `target-canary-runbook.md` — fail-closed live DNS/TLS, edge, OIDC, two-way
  mTLS+short-lived-workload-token и exact-session-scope evidence runner;
- `scripts/target-canary-preflight.mjs` — offline проверка Node runtime и всех
  target-canary input files по metadata без чтения secret contents и без сети;
- `scripts/application-canary.mjs`, `application-canary-config.example.json` и
  `application-canary-runbook.md` — отдельный least-privilege mutating public
  workflow, confirmation replay и proposed `application.primary_canary` evidence;
- `scripts/application-failure-canary.mjs`, example config и runbook —
  обратимые dependency/storage/Gateway faults, graceful restart и proposed
  `application.failure_modes` evidence;
- `scripts/review-package-preflight.mjs` — fail-closed проверка чистого
  Git-снимка, secret material, runtime/evidence paths и локальных ссылок
  перед architecture review;
- `scripts/reviewer-handoff.mjs` и `conformance/reviewer-tracks-v1.json` —
  exact-baseline manifest и шесть защищённых role briefs для назначения и
  проведения независимого архитектурного ревью;
- `scripts/reviewer-assignments.mjs` и `reviewer-assignments-template-v1.json`
  — проверяемое назначение decision owner, независимого final reviewer и всех
  шести ролевых reviewers без ручной правки основного review JSON;
- `scripts/reviewer-results.mjs` и `reviewer-result-template-v1.json` — строгий
  приём хэшированных ответов, exact-baseline/assignment validation и создание
  нового progress review без ручного изменения статусов;
- `scripts/architecture-review.mjs`, review template и
  `architecture-review-runbook.md` — проверяемый gate шести ролевых дорожек,
  замечаний и независимого финального решения по exact Git baseline;
- `conformance/checks-v3.json` и `conformance/evidence-template-v3.json` —
  текущий versioned registry обязательных проверок и строгий шаблон отчёта со
  встроенной повторной проверкой pilot adoption decision;
- `conformance/checks-v2.json`, `conformance/evidence-template-v2.json` и v1 —
  сохранённые исторические контракты до adoption/workload-identity gates;
- `Dockerfile.edge`, Director/Gateway Dockerfiles и
  `container-runtime-contract.md` — multi-stage non-root images и требования
  orchestrator hardening;
- `target-conformance-runbook.md` — единый `PASS`/`FAIL`/`NOT_RUN` gate для
  целевой инфраструктуры.

Шаблоны рассчитаны на Nginx 1.25.1+ с HTTP/2 module и `envsubst`. Следует
подставлять только перечисленные в
`env.example` имена, чтобы shell environment не менял Nginx variables `$host`,
`$uri` и `$remote_addr`:

```bash
export DIRIZHOR_NGINX_INCLUDE_DIR=/etc/nginx
envsubst '${DIRECTOR_PUBLIC_HOST} ${PUBLIC_LISTEN_PORT} ${DIRECTOR_UPSTREAM_HOST} ${DIRECTOR_UPSTREAM_PORT} ${DIRECTOR_MAX_BODY_SIZE} ${DIRIZHOR_NGINX_INCLUDE_DIR}' \
  < nginx/nginx.conf.template > /etc/nginx/nginx.conf
envsubst '${DIRECTOR_PUBLIC_HOST} ${DIRECTOR_PUBLIC_PORT} ${DIRECTOR_UPSTREAM_TLS_NAME}' \
  < nginx/director-proxy.conf.template > /etc/nginx/director-proxy.conf
nginx -t
```

UI production build монтируется read-only в `/srv/dirizhor-ui`. Public TLS leaf
certificate/key монтируются как `/run/secrets/public-tls.crt` и
`/run/secrets/public-tls.key`. CA, проверяющий Director upstream certificate,
монтируется как `/run/secrets/director-upstream-ca.crt`.

## Trusted proxy boundary

Nginx перезаписывает, а не дополняет, входные `X-Forwarded-*` headers. Director
должен доверять только адресу proxy или изолированной proxy network:

```bash
export DIRECTOR_TRUSTED_PROXY_CIDRS=10.70.0.10/32
```

Wildcard и hostname запрещены. Если доверяется container subnet, доступ к нему
должен иметь только edge proxy: любой другой процесс в доверенной сети сможет
подставить client IP. Без этой переменной Director игнорирует forwarded client
IP и audit фиксирует адрес самого proxy.

## Security properties

- access log использует `$uri`, поэтому OIDC `code`, `state` и provider errors
  из query string не записываются;
- callback location отключает Nginx error log, который иначе может включить
  полный request URI; availability контролируется метриками status/latency;
- несовпадающий public `Host` отклоняется, upstream получает фиксированный Host;
- proxy проверяет CA и DNS SAN Director upstream;
- incoming `Forwarded` и client-certificate headers очищаются;
- auth start/callback/local-login имеют отдельные стартовые rate limits;
- `/health/live` и `/health/ready` не публикуются во внешний origin;
- CSP разрешает только same-origin UI/API resources;
- API request buffering выключен для потоковой document upload.

Rate limits являются исходным профилем, а не универсальными значениями. Перед
pilot их нужно проверить на корпоративном NAT, IdP retry behavior и ожидаемой
нагрузке. Distributed edge deployment должен использовать общий rate-limit
backend либо эквивалентный ingress/WAF механизм.

## Startup probes

Orchestrator обращается к services напрямую по protected network:

- Director `/health/live` и `/health/ready`;
- Gateway `/health/live` и `/health/ready`.

Director readiness проверяет PostgreSQL и read/write доступ к Document Store.
Gateway readiness проверяет read/write доступ к encrypted state directory.
Probe body не содержит exception, hostname, path или credential.

## Database release gate

Director не запускает migrations автоматически и отказывается стартовать при
missing, dirty, diverged или pending migration history. Перед rollout оператор
отдельно выполняет `pnpm db:migrate` с
`DIRECTOR_MIGRATION_DATABASE_URL_FILE`, проверяет `pnpm db:status` и только затем
обновляет Director instances. Destructive `contract` выполняется в другом окне
с `--allow-contract` после вывода всех старых instances.

Migration credential имеет DDL-права и существует только в migration job.
Director runtime credential не может менять migration registry и имеет к нему
только `USAGE/SELECT`, необходимые startup guard. Перед workloads renderer
запускает отдельный read-only privilege Job с тем же runtime credential; его
target JSON report закрывает `postgres.runtime_privileges`.

Полный порядок `expand -> backfill -> validate -> contract`, baseline adoption
для существующей v1 и rollback procedure описаны в
[production migration runbook](../../db/production-migration-runbook.md).

## Mounted secrets

Runtime credentials поддерживают либо `NAME`, либо `NAME_FILE`; одновременное
задание запрещено. Для production рекомендуется `*_FILE` с read-only mount:

- Director: `DATABASE_URL`, `DIRECTOR_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64`,
  `GATEWAY_WORKLOAD_VERIFY_KEYS_JSON`, `DIRECTOR_CAPABILITY_KEY_BASE64`,
  `DIRECTOR_OIDC_CLIENT_SECRET`, `DIRECTOR_PUBLIC_USER_TOKEN`;
- Gateway: `GATEWAY_SPOOL_KEY_BASE64`,
  `GATEWAY_WORKLOAD_SIGNING_PRIVATE_KEY_BASE64`,
  `DIRECTOR_WORKLOAD_VERIFY_KEYS_JSON`, `OPENAI_API_KEY`, `INTERNAL_PROVIDER_TOKEN`.

Например `DIRECTOR_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc-client-secret`.
Loader удаляет ровно один завершающий newline и отклоняет пустые, multiline и
NUL-containing values. Содержимое и filesystem error в startup message не
копируются.

## Не доказано этим профилем

- корректность конкретного DNS, public certificate и корпоративного IdP;
- production CA/SAN/EKU для Director/Gateway;
- backup/restore, PITR и contention harness на конкретном PostgreSQL provider;
- внешний shared rate limiter и telemetry pipeline;
- фактическая OCI build/publish, image signing/scanning и применение
  orchestrator policy на target.

## GitHub Actions без pilot

`.github/workflows/architecture-ci.yml` запускает frozen install, check,
lint, test и build для Director/Gateway/UI, все deployment/conformance
тесты и статический container preflight. Workflow имеет только
`contents: read`, не читает secrets, не публикует images и не создаёт
облачные ресурсы. GitHub Actions закреплены по полным commit SHA.

Синтетические `registry.invalid` digest в preflight проверяют только
структуру Docker-контракта. Этот job не является OCI evidence и не
закрывает `IPR-ENGINEERING-001`.

## Ручная OCI-публикация pilot

`.github/workflows/pilot-oci-release.yml` запускается только вручную и только
через GitHub environment `digitalocean-pilot`. Он строит отдельный pinned
Node/pnpm build image, затем Director/Gateway/Edge, проверяет checksum
инструментов, SBOM, `HIGH`/`CRITICAL` vulnerabilities, Sigstore signatures и
сохраняет OCI evidence artifact. Workflow не разворачивает Kubernetes и не
открывает ingress.

До создания защищённого environment secret и реального успешного запуска
статус OCI release остаётся `NOT_RUN`. DigitalOcean token нельзя добавлять как
repository secret или помещать в git; допустим только отдельный краткоживущий
environment secret `DIGITALOCEAN_ACCESS_TOKEN` с ручным approval.

## Ephemeral mTLS smoke

Локальный smoke выпускает временную CA и отдельные `serverAuth`/`clientAuth`
leaf certificates, проверяет оба направления и обязательный отказ без client
certificate:

```bash
./scripts/mtls-smoke.sh
```

Сертификаты существуют только во временной директории и удаляются через trap.
Этот тест доказывает TLS handshake mechanics, но не заменяет проверку конкретных
production certificates и запущенных Director/Gateway процессов.

Перед target rollout те же environment variables, URL и allowlists проверяются
на реальных mounted secrets:

```bash
node scripts/certificate-preflight.mjs
```

Preflight проверяет соответствие private key, точные permissions, срок действия,
DNS SAN server-сертификатов, CN client-сертификатов, цепочки доверия и
`serverAuth`/`clientAuth`. После него всё равно требуется live handshake в обоих
направлениях. Полный порядок и stop-ship criteria находятся в
[target infrastructure conformance runbook](target-conformance-runbook.md).

Локальная проверка evidence validator:

```bash
node --test test/conformance-evidence.test.mjs
node --test test/release-evidence.test.mjs
node --test test/container-preflight.test.mjs
node --test test/oci-release.test.mjs
node --test test/kubernetes-render.test.mjs
node --test test/target-canary-preflight.test.mjs
node --test test/target-canary.test.mjs
node --test test/application-canary.test.mjs
node --test test/application-failure-canary.test.mjs
node --test test/review-package-preflight.test.mjs
node --test test/reviewer-assignments.test.mjs
node --test test/reviewer-results.test.mjs
node --test test/reviewer-handoff.test.mjs
```

Target evidence считается успешным только если validator завершился с кодом
`0`; `FAIL` и `NOT_RUN` возвращают блокирующий код `1`, а некорректный или
неполный документ — код `2`.

Live subset target checks выполняется из изолированного evidence environment с
реальными target DNS, IdP, service identities и browser-issued canary session:

```bash
node scripts/target-canary-preflight.mjs \
  /secure/change/CHG-123/target-canary-preflight \
  /secure/change/CHG-123/target-canary-config.json

node scripts/target-canary.mjs \
  /secure/change/CHG-123/target-canary \
  /secure/change/CHG-123/target-canary-config.json
```

Preflight должен вернуть `PASS` до certificate preflight и live-runner. Он
собирает все missing/type/mode/size blockers за один проход, не читает
материалы и не создаёт target evidence. Успешный live-runner даёт переносимые
updates только для external edge, обоих live
mTLS направлений и OIDC discovery. Он не объявляет пройденными полный browser
canary или mutating application scenario. Условия, secret boundary и stop-ship
критерии описаны в
[automated target canary v2](target-canary-runbook.md).

После успешного target subset полный mutating workflow выполняется отдельным
процессом, которому не передаются service identities:

```bash
node scripts/application-canary.mjs \
  /secure/change/CHG-123/application-canary \
  /secure/change/CHG-123/application-canary-config.json
```

Он создаёт persistent tagged artifacts только в выделенном canary project и
предлагает `application.primary_canary` update. Перенос `PASS` требует проверки
browser, audit и infrastructure-log evidence по правилам
[automated application canary v1](application-canary-runbook.md).

После primary workflow в approved change window выполняются disposable
PostgreSQL startup guards и target failure injection:

```bash
node scripts/application-failure-canary.mjs \
  /secure/change/CHG-123/application-failure-canary \
  /secure/change/CHG-123/application-failure-canary-config.json
```

Обратимые мутации, emergency restore и evidence boundary заданы в
[automated application failure canary v1](application-failure-canary-runbook.md).

Release collector запускается из `deploy/reference`, требует новый закрытый
output directory вне source workspace и не наследует application secrets:

```bash
node scripts/release-evidence.mjs /secure/change/CHG-123/release-evidence CHG-123
```

Workspace обязан быть корнем чистого Git snapshot. Modified, staged и обычные
untracked paths блокируют collection; ignored build/private paths допускаются,
но не читаются и не входят ни в общий source manifest, ни в source artifact
deployment-профиля. Symlink, submodule и другие non-regular tracked objects
также блокируют collection. Collector повторяет Git/source проверку после всех
профилей и отклоняет смену commit или содержимого во время запуска.

Он фиксирует source-tree до и после запуска, выполняет для трёх компонентов
frozen offline install, static checks, tests и clean build, а затем запускает
полный deployment/conformance suite `test/*.test.mjs`. Для компонентов collector
сохраняет lockfile/package hashes и manifest файлов `dist`; для deployment tooling
он сохраняет отдельный source-tree artifact. Все logs/manifests private. Изменение
workspace во время сбора блокирует evidence. Успех локального запуска не заменяет digest фактически
опубликованного image/artifact и не закрывает остальные target checks.

Независимая проверка collection выполняется без повторного запуска команд:

```bash
node scripts/release-evidence-verify.mjs \
  /secure/change/CHG-123/release-evidence
```

Режим `evidence_integrity` fail-closed проверяет private permissions, точный
набор файлов, schema, команды всех четырёх профилей, canonical collection hash,
log hashes и source/build manifest hashes. Он не утверждает, что рецензент видел
байты, из которых построены manifest. Для полной локальной сверки передаётся
сохранённый builder workspace после collection:

```bash
node scripts/release-evidence-verify.mjs \
  /secure/change/CHG-123/release-evidence \
  /secure/build/CHG-123/workspace
```

Режим `evidence_and_workspace` дополнительно сверяет весь source tree,
`package.json`, lockfiles, каждый файл трёх `dist` и deployment tooling tree.
Отсутствующий или изменённый artifact, лишний evidence-файл и ослабленные права
делают документ невалидным. Эта проверка не заменяет публикацию и проверку OCI
digest/signature.

OCI release запускается только на clean approved builder с настроенной внешней
registry и signing authentication. Конфигурация содержит несекретные policy IDs,
точные версии инструментов, pinned base images и release tags; значения из
`oci-release-config.example.json` являются нерабочим примером:

```bash
node scripts/oci-release.mjs \
  /secure/change/CHG-123/oci-release \
  /secure/change/CHG-123/oci-release-config.json
```

Orchestrator проверяет container contract и версии Docker/Buildx, Syft, Trivy и
Cosign, строит и публикует три multi-platform image с BuildKit provenance/SBOM,
получает registry digest, проверяет raw platform index, создаёт независимый
CycloneDX SBOM, применяет stop-ship vulnerability policy, подписывает image и
SBOM attestation и проверяет обе подписи. Trivy database обновляется до build,
проверяется на допустимый возраст, а baseline запрещает suppressions через
явный пустой ignore-файл. Итоговый
`oci-release-evidence.json`, CLI logs, metadata, SBOM и scanner report имеют mode
`0600`; каталог — `0700`. При частичной публикации создаётся только
`oci-release-failed.json`, а уже опубликованные digest подлежат quarantine.

Успешные synthetic tests доказывают fail-closed orchestration, но не registry,
scanner database, OIDC/KMS identity или фактические image layers. Без реального
запуска этого скрипта OCI release остаётся `NOT_RUN`.
