# Первая модель данных

Документ описывает минимальную модель данных для проектирования API и MVP. Это
не финальная схема БД, а первая нормализованная форма архитектурного черновика.

## project

Проект или направление работы.

Поля:

- id;
- title;
- description;
- status;
- owner_user_id;
- created_at;
- updated_at;
- archived_at.

Связи:

- имеет много `topic`;
- имеет много `memory_object`;
- имеет много `decision`.

## topic

Тема внутри проекта или сквозная тема между проектами.

Поля:

- id;
- project_id;
- title;
- summary;
- parent_topic_id;
- created_at;
- updated_at.

Связи:

- принадлежит `project`;
- может иметь родительскую `topic`;
- связывается с `memory_object`.

## memory_object

Карточка объекта корпоративной памяти. Это главный индексный объект реестра.

Поля:

- id;
- type;
- title;
- project_id;
- topic_id;
- current_version_id;
- author_user_id;
- summary;
- keywords;
- status;
- sensitivity_level;
- created_at;
- updated_at;
- archived_at.

Примеры `type`:

- document;
- protocol;
- decision;
- research_result;
- open_question;
- ai_result;
- note.

Связи:

- принадлежит `project`;
- может принадлежать `topic`;
- имеет много `document_version`;
- имеет много входящих и исходящих `relationship`;
- может быть источником или результатом `agent_run`.

## document_version

Версия файла или текстового объекта.

Поля:

- id;
- memory_object_id;
- version_number;
- storage_uri;
- file_name;
- file_type;
- content_hash;
- size_bytes;
- created_by_user_id;
- created_at;
- change_summary;

Связи:

- принадлежит `memory_object`;
- может использоваться в `agent_run_context`.

## decision

Формализованное решение пользователя или компании.

Поля:

- id;
- memory_object_id;
- project_id;
- topic_id;
- title;
- decision_text;
- rationale;
- status;
- supersedes_decision_id;
- decided_by_user_id;
- decided_at;
- created_at;
- updated_at.

Статусы:

- draft;
- proposed;
- approved;
- rejected;
- superseded;

Связи:

- обязательно расширяет `memory_object` типа `decision`;
- может заменять другое `decision`;
- должно иметь audit-события изменения статуса.

## open_question

Вопрос, требующий решения или исследования.

Поля:

- id;
- memory_object_id;
- project_id;
- topic_id;
- question_text;
- status;
- owner_user_id;
- created_at;
- updated_at;
- closed_at.

Статусы:

- open;
- in_progress;
- answered;
- closed;

Связи:

- обязательно расширяет `memory_object` типа `open_question`;
- может быть связано с документами, решениями и результатами AI через
  `relationship`.

## agent_run

Запуск AI-агента.

Поля:

- id;
- task_id;
- project_id;
- agent_type;
- provider;
- model;
- purpose;
- instructions;
- input_summary;
- output_summary;
- status;
- requested_by_user_id;
- provider_data_profile_version;
- deployment_class;
- context_set_hash;
- origin_request_id;
- request_fingerprint;
- dispatched_at;
- deadline_at;
- created_at;
- started_at;
- finished_at;
- error_message.

Статусы:

- queued;
- running;
- completed;
- failed;
- cancelled;
- awaiting_user_confirmation.

Связи:

- имеет много `agent_run_context`;
- может создать `memory_object` типа `ai_result`;
- должен иметь связанные `audit_event`.

## agent_run_context

Явная фиксация того, какие объекты памяти были переданы агенту.

Поля:

- id;
- agent_run_id;
- project_id;
- memory_object_id;
- document_version_id;
- position;
- access_reason;
- sensitivity_level;
- created_at.

Назначение:

- доказывает, что агент получил не всю память, а конкретный разрешенный набор;
- фиксирует воспроизводимый порядок элементов в prompt через `position`;
- фиксирует уровень чувствительности источника на момент запуска;
- помогает восстановить, на чем был основан ответ AI.

## agent_run_result

Временный результат AI до решения пользователя сохранить его в корпоративную
память.

Поля:

- id;
- agent_run_id;
- project_id;
- output_storage_uri;
- content_hash;
- size_bytes;
- file_type;
- output_summary;
- sensitivity_level;
- created_at;
- expires_at;
- saved_memory_object_id;
- saved_at.

Назначение:

- не смешивает еще не принятый ответ AI с корпоративной памятью;
- наследует максимальный уровень чувствительности исходного контекста;
- позволяет показать результат пользователю и затем связать его с
  `memory_object` типа `ai_result`;
- хранит в PostgreSQL только метаданные, а полное содержимое — в Document Store.

## audit_event

Журналируемое событие.

Поля:

- id;
- actor_type;
- actor_id;
- action;
- target_type;
- target_id;
- project_id;
- metadata;
- created_at;
- request_id;
- ip_address;
- authorization_decision_id.

Примеры `actor_type`:

- user;
- director;
- agent;
- service;
- system.

Примеры `action`:

- memory_object.created;
- memory_object.read;
- document_version.created;
- agent_run.started;
- agent_run.completed;
- decision.approved;
- access.allowed;
- access.denied;

## relationship

Связь между объектами памяти.

Поля:

- id;
- project_id;
- source_type;
- source_id;
- target_type;
- target_id;
- relation_type;
- description;
- created_by_user_id;
- created_at.

Примеры `relation_type`:

- references;
- depends_on;
- contradicts;
- supersedes;
- explains;
- implements;
- belongs_to;
- derived_from.

## task

Задача пользователя, которую обрабатывает Дирижёр.

Поля:

- id;
- project_id;
- created_by_user_id;
- title;
- user_request;
- status;
- result_memory_object_id;
- created_at;
- updated_at;
- completed_at.

Статусы:

- created;
- planning;
- awaiting_context;
- awaiting_user_confirmation;
- running_agent;
- reviewing;
- completed;
- failed;
- cancelled.

## Сущности доступа

Пользователи, сервисные principal, роли, permissions, назначения ролей,
подтверждения, AI-policy проекта и короткоживущие agent capabilities определены
в отдельной спецификации [Auth/RBAC v1](auth-rbac-v1.md). При подготовке
SQL-схемы эти сущности должны проектироваться вместе с основной моделью, потому
что они ссылаются на `project`, `memory_object`, `document_version` и
`agent_run`.

Исполнимая форма модели и дополнительные технические сущности описаны в
[PostgreSQL schema v1](postgresql-schema-v1.md). SQL-слой добавляет
`user_identity`, `user_session`, `authorization_decision` и
`agent_run_result`, а также составные внешние ключи для запрета связей между
разными проектами.

## Минимальные инварианты

- AI-агент не получает документ без записи в `agent_run_context`.
- Чтение объекта памяти должно порождать `audit_event`, если объект не является
  публичным внутри системы.
- Результат AI, сохраняемый в память, должен иметь тип `ai_result` или быть
  явно преобразован пользователем/секретарем в другой тип.
- Утвержденное решение нельзя менять без создания новой версии или нового
  решения со связью `supersedes`.
