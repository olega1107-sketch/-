# Migration file contract

Manifest является единственным упорядоченным реестром миграций. Версии идут без
пропусков от `1`, а `id` начинается с той же четырёхзначной версии. Уже
выпущенный SQL, metadata или checksum не редактируются.

## Фазы изменения

Один `change` проходит в таком порядке:

1. `expand` - только обратно совместимые additions, dual-read/dual-write и
   `CHECK`/foreign key через `NOT VALID`, если полный scan опасен.
2. `backfill` - идемпотентный backfill отдельным bounded job; SQL-фаза только
   проверяет, что незаполненных строк больше нет.
3. `validate` - database validation, включая `VALIDATE CONSTRAINT`, метрики и
   canary на новой модели чтения.
4. `contract` - удаление старого column/index/path только после вывода всех
   старых версий приложения.

`backfill` можно пропустить, если данных для переноса нет. `contract` без
предшествующей `validate` runner отклоняет. Обычный `db:migrate` останавливается
перед `contract`; нужен отдельный запуск с `--allow-contract`.

## Transaction mode

- `migration` - runner оборачивает файл в одну транзакцию и задаёт локальные
  `lock_timeout`/`statement_timeout`;
- `self` - разрешён только baseline, который уже содержит `BEGIN/COMMIT`;
- `none` - только для одной идемпотентной команды, запрещённой внутри
  transaction block, например `CREATE INDEX CONCURRENTLY`.

При сбое `none` остаётся строка `status=applying`, и все следующие запуски
останавливаются. DBA обязан проверить catalog state, включая
`pg_index.indisvalid`, устранить или завершить эффект и только после peer review
исправить migration registry. Автоматического удаления dirty state нет.

## Добавление файла

1. Добавить SQL и manifest entry с новым `version`, `id`, `change`, `phase` и
   transaction mode.
2. Выполнить `pnpm db:checksums` из `director/reference`.
3. Перенести выведенный checksum в manifest и повторить проверку.
4. Прогнать fresh install, upgrade копии production backup и application tests.
5. Для `contract` приложить доказательство отсутствия старых application
   instances и проверенную точку восстановления.

Checksum включает id, name, change, phase, transaction mode и точные SQL bytes.
Поэтому изменение не только SQL, но и смысла/фазы выпущенной миграции обнаружится
как history drift.
