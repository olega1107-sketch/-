# Automated application canary v1

Статус: production-oriented mutating evidence runner. Synthetic test проверяет
контракт runner, но не создаёт target evidence.

## 1. Назначение и граница

`scripts/application-canary.mjs` выполняет полный основной сценарий через
public HTTPS edge и browser-issued Director session:

1. отклоняет запрос без session и сверяет точный project scope;
2. загружает, читает и находит небольшой `internal` document;
3. создаёт internal task, выполняет task-context search и internal agent run;
4. проверяет terminal result, его marker и SHA-256;
5. получает обязательный `428 requires_confirmation` для сохранения AI result,
   подтверждает операцию и повторяет ровно тот же request с тем же
   `x-request-id` и payload;
6. создаёт отдельный external task, требует подтверждение передачи internal
   context, проверяет отсутствие `frozen_payload` в public confirmation API,
   подтверждает и дожидается completed run;
7. сверяет task states, timelines и поиск исходного и сохранённого artifacts.

Runner создаёт persistent task, run, confirmation, audit, memory object и
document version records. Публичного delete API он намеренно не обходит.
Поэтому запуск разрешён только в отдельном canary project, доступном выделенной
identity, и требует явных `dedicated_project=true` и
`persistent_artifacts_acknowledged=true`.

Успешный отчёт предлагает update только для `application.primary_canary`.
`application.failure_modes` он не закрывает.

## 2. Обязательные предусловия

До запуска:

1. `target-canary.mjs` прошёл на том же rollout, origin и browser session.
2. Canary identity видит ровно один активный canary project; рабочие проекты
   этой identity недоступны.
3. Для запуска выбран новый одноразовый lowercase marker длиной 8-64 символа.
   Повторное использование marker запрещено.
4. Настроены два разных exact agent routes:
   - internal route действительно не выводит content за утверждённую внутреннюю
     processing boundary, возвращает `deployment_class=internal` и `null`
     profile version;
   - external route возвращает `deployment_class=external`, exact approved
     provider/model/profile и требует confirmation для `internal` context.
5. Project AI policy разрешает утверждённый external provider/profile,
   ограничивает sensitivity значением `internal` и включает confirmation для
   internal external share.
6. Browser MFA evidence, audit allow/deny/confirmation review и проверка
   infrastructure logs получили отдельные opaque evidence references.
7. Session token находится в однострочном protected file. Cookie value не
   записывается в config, аргументы процесса, shell history или evidence.

Текущий `kubernetes-target-config.example.json` содержит оба маршрута:
real `internal` HTTP adapter к exact corporate inference origin и external OpenAI
route. Перед target evidence оператор всё равно доказывает, что internal
origin размещён в утверждённой processing boundary; cloud route нельзя
переклассифицировать как `internal`.

## 3. Execution environment

Runner запускается в короткоживущем изолированном Job/host с target DNS. Ему
нужны только public CA и browser session file. Service bearer tokens, mTLS
client keys, database credentials и provider API keys не монтируются.

Filesystem read-only, кроме нового output directory. Egress разрешён только к
public edge. Session и private output удаляются после передачи evidence в
утверждённое хранилище.

Мутации не повторяются автоматически после timeout/reset. При транспортной
неопределённости отчёт получает `FAIL`; оператор ищет частично созданные записи
по marker и только затем запускает новый execution с новым marker.

## 4. Конфигурация

Начать с `application-canary-config.example.json`. Неизвестные, отсутствующие
или неоднозначные поля блокируют запуск.

- `public.origin` — exact HTTPS DNS origin без path/query/fragment.
- `public.ca_path=null` использует системный trust store; private CA задаётся
  абсолютным path и не может быть group/world-writable.
- `session.token_file` имеет mode `0400`, `0440`, `0600` или `0640`.
- `session.expected_project_ids` содержит ровно `application.project_id`.
- `internal_agent` и `external_agent` задают exact значения, ожидаемые в каждом
  созданном/read AgentRun; любой routing drift даёт `FAIL`.
- internal profile обязан быть `null`, external profile — непустой строкой.
- `poll_timeout_ms` ограничен 5-900 секунд; terminal `failed`, `cancelled` или
  неожиданное `awaiting_user_confirmation` немедленно блокирует сценарий.
- три external evidence references уникальны и не могут указывать на сам
  application-canary report.

Config несекретный. Output должен быть новым каталогом вне source workspace;
его parent создаётся заранее с ограниченным доступом.

## 5. Запуск

Из `deploy/reference`:

```bash
node scripts/application-canary.mjs \
  /secure/change/CHG-123/application-canary \
  /secure/change/CHG-123/application-canary-config.json
```

Exit codes:

- `0`: все семь checks имеют `PASS`, создан proposed registry update;
- `1`: evidence создан, минимум один check имеет `FAIL`, зависимые checks имеют
  `NOT_RUN`;
- `2`: invocation/config/output некорректны, запуск нельзя считать canary.

### GitHub protected workflow

Для Pilot доступен ручной workflow `Pilot application canary`. Он не запускается
после push или OCI release автоматически: сценарий создаёт persistent synthetic
artifacts и требует новую browser-issued canary session.

В Environment `digitalocean-pilot` оператор хранит только два защищённых значения:

1. `DIRIZHOR_APPLICATION_CANARY_CONFIG` — JSON по этому примеру, без session
   token; workflow самостоятельно заменяет `execution_id`, marker и локальный
   `session.token_file`.
2. `DIRIZHOR_APPLICATION_CANARY_SESSION_TOKEN` — свежий одноразовый cookie value
   выделенной canary identity. Значение нельзя помещать в Git, issue, shell history,
   workflow inputs или evidence artifact.

Перед каждым запуском задаются новый `execution_id` и новый lowercase marker.
Environment approval остаётся обязательным. После завершения токен удаляется из
Environment либо заменяется новым; runner удаляет локальные protected inputs, а
в GitHub сохраняет только `application-canary-evidence.json` на 30 дней.

Output directory получает mode `0700`,
`application-canary-evidence.json` — `0600`. Сценарий может занять до двух
`poll_timeout_ms` плюс HTTP operations.

## 6. Evidence boundary

Отчёт содержит marker, статусы, durations, route metadata, counts, content и
confirmation payload hashes. Он не содержит session token, cookie value,
document/result content, response bodies, filesystem paths или созданные
resource UUID.

`registry_updates[0]` — предлагаемый, а не самостоятельно утверждённый update.
Runner записывает внешние references, но не читает их содержимое. До переноса
`application.primary_canary=PASS` в общий conformance evidence reviewer обязан:

1. найти записи запуска по execution marker и временному окну;
2. проверить audit allow, deny и обе confirmation transitions;
3. проверить, что infrastructure access/error/application logs не содержат
   cookie, Authorization, document bytes или agent result content;
4. сверить browser evidence с той же canary identity/session;
5. подтвердить существование всех четырёх evidence refs из proposed update;
6. проверить canonical `report_sha256` и неизменность исходного файла.

Audit artifact должен включать allow/confirmation records этого marker и
отдельно выполненный контролируемый authorization deny. Anonymous `401` внутри
runner проверяет authentication boundary, но не выдаётся за authorization-deny
evidence.

Сам `application-canary-evidence.json`, даже со статусом `PASS`, не разрешает
rollout без этих artifacts и независимого `evidence.peer_review=PASS`.

## 7. Stop-ship

Rollout блокируется, если identity видит иной project set, document bytes/hash
не сходятся, context search не находит upload, internal route сообщает external
metadata или наоборот, provider output не содержит marker, result hash неверен,
save проходит без confirmation, replay требует другой request, public API
раскрывает frozen payload, external share проходит без confirmation, run не
достигает `completed`, task/timeline/search не сходятся либо audit/log evidence
не подтверждает заявленную границу.

Исправленный повтор получает новый `execution_id`, marker и output directory.
Исходные `FAIL` и частичные artifacts сохраняются до завершения расследования и
применения утверждённой retention policy canary project.

## 8. Что остаётся отдельно

Этот runner не проверяет OIDC callback replay/logout/revoke-all, отказ
readiness при недоступных PostgreSQL/Document Store/Gateway, graceful shutdown,
restart/migration guards, infrastructure log transport или disaster recovery.
Отказы readiness, graceful shutdown и migration guards автоматизированы
отдельным [application failure canary](application-failure-canary-runbook.md).
Остальные границы остаются отдельными обязательными checks общего target
conformance runbook.
