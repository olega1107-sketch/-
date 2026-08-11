-- Director PostgreSQL schema v1.
-- Target: PostgreSQL 15+.
-- Apply once to an empty database with a role allowed to create extensions and
-- schemas. Application data lives in the "dirizhor" schema.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS dirizhor;
SET LOCAL search_path = dirizhor, public;

-- ---------------------------------------------------------------------------
-- Identity and authentication
-- ---------------------------------------------------------------------------

CREATE TABLE app_users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    login text NOT NULL,
    display_name text NOT NULL,
    status text NOT NULL DEFAULT 'invited',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_authenticated_at timestamptz,
    CONSTRAINT app_users_login_not_blank
        CHECK (length(btrim(login)) > 0),
    CONSTRAINT app_users_display_name_not_blank
        CHECK (length(btrim(display_name)) > 0),
    CONSTRAINT app_users_status_valid
        CHECK (status IN ('invited', 'active', 'suspended', 'disabled'))
);

CREATE UNIQUE INDEX app_users_login_unique_idx
    ON app_users (lower(login));

CREATE TABLE user_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    provider_code text NOT NULL,
    provider_issuer text,
    provider_subject text NOT NULL,
    secret_hash text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_authenticated_at timestamptz,
    CONSTRAINT user_identities_provider_not_blank
        CHECK (length(btrim(provider_code)) > 0),
    CONSTRAINT user_identities_subject_not_blank
        CHECK (length(btrim(provider_subject)) > 0),
    CONSTRAINT user_identities_issuer_valid CHECK (
        (provider_code = 'local' AND provider_issuer IS NULL)
        OR
        (provider_code <> 'local'
            AND provider_issuer ~ '^https://[^[:space:]]+$'
            AND length(provider_issuer) <= 2048)
    ),
    CONSTRAINT user_identities_secret_valid CHECK (
        (provider_code = 'local'
            AND secret_hash IS NOT NULL
            AND length(btrim(secret_hash)) > 0)
        OR (provider_code <> 'local' AND secret_hash IS NULL)
    ),
    CONSTRAINT user_identities_provider_subject_unique
        UNIQUE (provider_code, provider_subject)
);

CREATE INDEX user_identities_user_idx ON user_identities (user_id);
CREATE UNIQUE INDEX user_identities_issuer_subject_unique_idx
    ON user_identities (provider_issuer, provider_subject)
    WHERE provider_issuer IS NOT NULL;
CREATE UNIQUE INDEX user_identities_local_user_unique_idx
    ON user_identities (user_id)
    WHERE provider_code = 'local';

CREATE TABLE user_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    session_token_hash text NOT NULL,
    authentication_method text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz,
    revoked_at timestamptz,
    ip_address inet,
    user_agent text,
    CONSTRAINT user_sessions_token_hash_unique UNIQUE (session_token_hash),
    CONSTRAINT user_sessions_token_hash_valid
        CHECK (session_token_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT user_sessions_method_not_blank
        CHECK (length(btrim(authentication_method)) > 0),
    CONSTRAINT user_sessions_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT user_sessions_revocation_valid
        CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CONSTRAINT user_sessions_last_seen_valid
        CHECK (last_seen_at IS NULL OR last_seen_at >= created_at)
);

CREATE INDEX user_sessions_active_user_idx
    ON user_sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE oidc_login_transactions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_code text NOT NULL,
    browser_token_hash text NOT NULL,
    state_hash text NOT NULL,
    nonce text,
    code_verifier text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    request_id uuid NOT NULL,
    ip_address inet,
    CONSTRAINT oidc_login_transactions_provider_not_blank
        CHECK (length(btrim(provider_code)) > 0),
    CONSTRAINT oidc_login_transactions_browser_token_unique
        UNIQUE (browser_token_hash),
    CONSTRAINT oidc_login_transactions_state_unique
        UNIQUE (state_hash),
    CONSTRAINT oidc_login_transactions_browser_token_hash_valid
        CHECK (browser_token_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT oidc_login_transactions_state_hash_valid
        CHECK (state_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT oidc_login_transactions_expiry_valid
        CHECK (expires_at > created_at),
    CONSTRAINT oidc_login_transactions_consumption_valid
        CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CONSTRAINT oidc_login_transactions_secret_lifecycle_valid CHECK (
        (consumed_at IS NULL
            AND nonce IS NOT NULL
            AND length(nonce) BETWEEN 43 AND 512
            AND code_verifier IS NOT NULL
            AND length(code_verifier) BETWEEN 43 AND 128)
        OR
        (consumed_at IS NOT NULL AND nonce IS NULL AND code_verifier IS NULL)
    )
);

CREATE INDEX oidc_login_transactions_expiry_idx
    ON oidc_login_transactions (expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX oidc_login_transactions_consumed_idx
    ON oidc_login_transactions (consumed_at)
    WHERE consumed_at IS NOT NULL;

CREATE TABLE service_principals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at timestamptz,
    CONSTRAINT service_principals_code_unique UNIQUE (code),
    CONSTRAINT service_principals_code_not_blank
        CHECK (length(btrim(code)) > 0),
    CONSTRAINT service_principals_status_valid
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT service_principals_rotation_valid
        CHECK (rotated_at IS NULL OR rotated_at >= created_at)
);

-- ---------------------------------------------------------------------------
-- RBAC catalog
-- ---------------------------------------------------------------------------

CREATE TABLE permissions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code text NOT NULL,
    description text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT permissions_code_unique UNIQUE (code),
    CONSTRAINT permissions_code_valid
        CHECK (code ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT permissions_description_not_blank
        CHECK (length(btrim(description)) > 0)
);

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code text NOT NULL,
    name text NOT NULL,
    scope_type text NOT NULL,
    system_defined boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT roles_code_unique UNIQUE (code),
    CONSTRAINT roles_code_valid CHECK (code ~ '^[a-z][a-z0-9_]*$'),
    CONSTRAINT roles_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT roles_scope_type_valid CHECK (scope_type IN ('system', 'project'))
);

CREATE TABLE role_permissions (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- ---------------------------------------------------------------------------
-- Projects and scoped role assignments
-- ---------------------------------------------------------------------------

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    description text,
    status text NOT NULL DEFAULT 'active',
    owner_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    archived_at timestamptz,
    CONSTRAINT projects_title_not_blank CHECK (length(btrim(title)) > 0),
    CONSTRAINT projects_status_valid CHECK (status IN ('active', 'archived')),
    CONSTRAINT projects_archive_state_valid CHECK (
        (status = 'archived' AND archived_at IS NOT NULL)
        OR (status = 'active' AND archived_at IS NULL)
    )
);

CREATE INDEX projects_owner_idx ON projects (owner_user_id);
CREATE INDEX projects_status_idx ON projects (status, created_at DESC);
CREATE INDEX projects_updated_idx ON projects (updated_at DESC, id DESC);

CREATE TABLE role_assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_type text NOT NULL,
    principal_id uuid NOT NULL,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    scope_type text NOT NULL,
    scope_id uuid REFERENCES projects(id) ON DELETE RESTRICT,
    granted_by_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT role_assignments_principal_type_valid
        CHECK (principal_type IN ('user', 'service')),
    CONSTRAINT role_assignments_scope_type_valid
        CHECK (scope_type IN ('system', 'project')),
    CONSTRAINT role_assignments_scope_shape_valid CHECK (
        (scope_type = 'system' AND scope_id IS NULL)
        OR (scope_type = 'project' AND scope_id IS NOT NULL)
    ),
    CONSTRAINT role_assignments_expiry_valid
        CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT role_assignments_revocation_valid
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE UNIQUE INDEX role_assignments_active_unique_idx
    ON role_assignments (
        principal_type,
        principal_id,
        role_id,
        scope_type,
        COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE revoked_at IS NULL;

CREATE INDEX role_assignments_active_principal_idx
    ON role_assignments (principal_type, principal_id, scope_type, scope_id)
    WHERE revoked_at IS NULL;

CREATE INDEX role_assignments_active_project_idx
    ON role_assignments (scope_id, role_id)
    WHERE scope_type = 'project' AND revoked_at IS NULL;

CREATE TABLE project_ai_policies (
    project_id uuid PRIMARY KEY REFERENCES projects(id) ON DELETE RESTRICT,
    external_ai_enabled boolean NOT NULL DEFAULT false,
    allowed_provider_ids text[] NOT NULL DEFAULT '{}',
    provider_data_profile_versions jsonb NOT NULL DEFAULT '{}'::jsonb,
    max_external_sensitivity_level text NOT NULL DEFAULT 'public',
    confirm_internal_external_share boolean NOT NULL DEFAULT true,
    bulk_context_object_limit integer NOT NULL DEFAULT 10,
    updated_by_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT project_ai_policies_profile_versions_object
        CHECK (jsonb_typeof(provider_data_profile_versions) = 'object'),
    CONSTRAINT project_ai_policies_sensitivity_valid
        CHECK (max_external_sensitivity_level IN ('public', 'internal', 'confidential')),
    CONSTRAINT project_ai_policies_bulk_limit_positive
        CHECK (bulk_context_object_limit > 0),
    CONSTRAINT project_ai_policies_provider_ids_no_nulls
        CHECK (array_position(allowed_provider_ids, NULL) IS NULL),
    CONSTRAINT project_ai_policies_external_provider_required CHECK (
        NOT external_ai_enabled OR cardinality(allowed_provider_ids) > 0
    )
);

-- ---------------------------------------------------------------------------
-- Corporate memory registry
-- ---------------------------------------------------------------------------

CREATE TABLE topics (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    title text NOT NULL,
    summary text,
    parent_topic_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT topics_title_not_blank CHECK (length(btrim(title)) > 0),
    CONSTRAINT topics_not_own_parent CHECK (parent_topic_id IS NULL OR parent_topic_id <> id),
    CONSTRAINT topics_id_project_unique UNIQUE (id, project_id),
    CONSTRAINT topics_parent_same_project_fk
        FOREIGN KEY (parent_topic_id, project_id)
        REFERENCES topics(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX topics_project_parent_idx ON topics (project_id, parent_topic_id);
CREATE INDEX topics_project_title_idx ON topics (project_id, lower(title));

CREATE TABLE memory_objects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    type text NOT NULL,
    title text NOT NULL,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    topic_id uuid,
    current_version_id uuid,
    author_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    summary text,
    keywords text[] NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'active',
    sensitivity_level text NOT NULL DEFAULT 'internal',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    archived_at timestamptz,
    CONSTRAINT memory_objects_type_valid CHECK (
        type IN (
            'document',
            'protocol',
            'decision',
            'research_result',
            'open_question',
            'ai_result',
            'note'
        )
    ),
    CONSTRAINT memory_objects_title_not_blank CHECK (length(btrim(title)) > 0),
    CONSTRAINT memory_objects_status_valid CHECK (status IN ('active', 'archived')),
    CONSTRAINT memory_objects_sensitivity_valid
        CHECK (sensitivity_level IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT memory_objects_archive_state_valid CHECK (
        (status = 'archived' AND archived_at IS NOT NULL)
        OR (status = 'active' AND archived_at IS NULL)
    ),
    CONSTRAINT memory_objects_keywords_no_nulls
        CHECK (array_position(keywords, NULL) IS NULL),
    CONSTRAINT memory_objects_id_project_unique UNIQUE (id, project_id),
    CONSTRAINT memory_objects_topic_same_project_fk
        FOREIGN KEY (topic_id, project_id)
        REFERENCES topics(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX memory_objects_project_status_idx
    ON memory_objects (project_id, status, updated_at DESC);
CREATE INDEX memory_objects_project_topic_idx
    ON memory_objects (project_id, topic_id);
CREATE INDEX memory_objects_project_type_idx
    ON memory_objects (project_id, type, status);
CREATE INDEX memory_objects_project_sensitivity_idx
    ON memory_objects (project_id, sensitivity_level, status);
CREATE INDEX memory_objects_project_title_idx
    ON memory_objects (project_id, lower(title));
CREATE INDEX memory_objects_keywords_gin_idx
    ON memory_objects USING gin (keywords);

CREATE TABLE document_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    memory_object_id uuid NOT NULL REFERENCES memory_objects(id) ON DELETE RESTRICT,
    version_number integer NOT NULL,
    storage_uri text NOT NULL,
    file_name text NOT NULL,
    file_type text NOT NULL,
    content_hash text NOT NULL,
    size_bytes bigint NOT NULL,
    created_by_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    change_summary text,
    CONSTRAINT document_versions_number_positive CHECK (version_number > 0),
    CONSTRAINT document_versions_storage_uri_not_blank
        CHECK (length(btrim(storage_uri)) > 0),
    CONSTRAINT document_versions_file_name_not_blank
        CHECK (length(btrim(file_name)) > 0),
    CONSTRAINT document_versions_file_type_not_blank
        CHECK (length(btrim(file_type)) > 0),
    CONSTRAINT document_versions_hash_valid
        CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT document_versions_size_nonnegative CHECK (size_bytes >= 0),
    CONSTRAINT document_versions_object_number_unique
        UNIQUE (memory_object_id, version_number),
    CONSTRAINT document_versions_id_object_unique
        UNIQUE (id, memory_object_id)
);

CREATE INDEX document_versions_object_created_idx
    ON document_versions (memory_object_id, created_at DESC);
CREATE INDEX document_versions_hash_idx ON document_versions (content_hash);

ALTER TABLE memory_objects
    ADD CONSTRAINT memory_objects_current_version_same_object_fk
    FOREIGN KEY (current_version_id, id)
    REFERENCES document_versions(id, memory_object_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

-- ---------------------------------------------------------------------------
-- Typed knowledge objects
-- ---------------------------------------------------------------------------

CREATE TABLE decisions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    memory_object_id uuid NOT NULL UNIQUE,
    project_id uuid NOT NULL,
    topic_id uuid,
    title text NOT NULL,
    decision_text text NOT NULL,
    rationale text,
    status text NOT NULL DEFAULT 'draft',
    supersedes_decision_id uuid,
    decided_by_user_id uuid REFERENCES app_users(id) ON DELETE RESTRICT,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT decisions_title_not_blank CHECK (length(btrim(title)) > 0),
    CONSTRAINT decisions_text_not_blank CHECK (length(btrim(decision_text)) > 0),
    CONSTRAINT decisions_status_valid
        CHECK (status IN ('draft', 'proposed', 'approved', 'rejected', 'superseded')),
    CONSTRAINT decisions_decider_state_valid CHECK (
        (
            status IN ('approved', 'rejected', 'superseded')
            AND decided_by_user_id IS NOT NULL
            AND decided_at IS NOT NULL
        )
        OR (
            status IN ('draft', 'proposed')
            AND decided_by_user_id IS NULL
            AND decided_at IS NULL
        )
    ),
    CONSTRAINT decisions_not_self_superseding
        CHECK (supersedes_decision_id IS NULL OR supersedes_decision_id <> id),
    CONSTRAINT decisions_id_project_unique UNIQUE (id, project_id),
    CONSTRAINT decisions_memory_object_same_project_fk
        FOREIGN KEY (memory_object_id, project_id)
        REFERENCES memory_objects(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT decisions_topic_same_project_fk
        FOREIGN KEY (topic_id, project_id)
        REFERENCES topics(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT decisions_superseded_same_project_fk
        FOREIGN KEY (supersedes_decision_id, project_id)
        REFERENCES decisions(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX decisions_project_status_idx
    ON decisions (project_id, status, updated_at DESC);
CREATE INDEX decisions_project_topic_idx ON decisions (project_id, topic_id);
CREATE UNIQUE INDEX decisions_one_effective_successor_idx
    ON decisions (supersedes_decision_id)
    WHERE supersedes_decision_id IS NOT NULL AND status IN ('approved', 'superseded');

CREATE TABLE open_questions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    memory_object_id uuid NOT NULL UNIQUE,
    project_id uuid NOT NULL,
    topic_id uuid,
    question_text text NOT NULL,
    status text NOT NULL DEFAULT 'open',
    owner_user_id uuid REFERENCES app_users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at timestamptz,
    CONSTRAINT open_questions_text_not_blank
        CHECK (length(btrim(question_text)) > 0),
    CONSTRAINT open_questions_status_valid
        CHECK (status IN ('open', 'in_progress', 'answered', 'closed')),
    CONSTRAINT open_questions_closed_state_valid CHECK (
        (status = 'closed' AND closed_at IS NOT NULL)
        OR (status <> 'closed' AND closed_at IS NULL)
    ),
    CONSTRAINT open_questions_id_project_unique UNIQUE (id, project_id),
    CONSTRAINT open_questions_memory_object_same_project_fk
        FOREIGN KEY (memory_object_id, project_id)
        REFERENCES memory_objects(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT open_questions_topic_same_project_fk
        FOREIGN KEY (topic_id, project_id)
        REFERENCES topics(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX open_questions_project_status_idx
    ON open_questions (project_id, status, updated_at DESC);
CREATE INDEX open_questions_owner_status_idx
    ON open_questions (owner_user_id, status)
    WHERE owner_user_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Tasks and AI runs
-- ---------------------------------------------------------------------------

CREATE TABLE tasks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    title text NOT NULL,
    user_request text NOT NULL,
    status text NOT NULL DEFAULT 'created',
    result_memory_object_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamptz,
    CONSTRAINT tasks_title_not_blank CHECK (length(btrim(title)) > 0),
    CONSTRAINT tasks_request_not_blank CHECK (length(btrim(user_request)) > 0),
    CONSTRAINT tasks_status_valid CHECK (
        status IN (
            'created',
            'planning',
            'awaiting_context',
            'awaiting_user_confirmation',
            'running_agent',
            'reviewing',
            'completed',
            'failed',
            'cancelled'
        )
    ),
    CONSTRAINT tasks_completion_state_valid CHECK (
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status <> 'completed' AND completed_at IS NULL)
    ),
    CONSTRAINT tasks_id_project_unique UNIQUE (id, project_id),
    CONSTRAINT tasks_result_same_project_fk
        FOREIGN KEY (result_memory_object_id, project_id)
        REFERENCES memory_objects(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX tasks_project_status_idx ON tasks (project_id, status, updated_at DESC);
CREATE INDEX tasks_creator_status_idx ON tasks (created_by_user_id, status);

CREATE TABLE agent_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id uuid NOT NULL,
    project_id uuid NOT NULL,
    agent_type text NOT NULL,
    provider text NOT NULL,
    model text,
    purpose text NOT NULL,
    instructions text NOT NULL,
    input_summary text,
    output_summary text,
    status text NOT NULL DEFAULT 'queued',
    requested_by_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    provider_data_profile_version text,
    deployment_class text NOT NULL,
    context_set_hash text,
    origin_request_id uuid NOT NULL,
    request_fingerprint text,
    dispatched_at timestamptz,
    deadline_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at timestamptz,
    finished_at timestamptz,
    error_message text,
    CONSTRAINT agent_runs_agent_type_not_blank
        CHECK (length(btrim(agent_type)) > 0),
    CONSTRAINT agent_runs_provider_not_blank
        CHECK (length(btrim(provider)) > 0),
    CONSTRAINT agent_runs_purpose_not_blank
        CHECK (length(btrim(purpose)) > 0),
    CONSTRAINT agent_runs_instructions_not_blank
        CHECK (length(btrim(instructions)) > 0),
    CONSTRAINT agent_runs_status_valid CHECK (
        status IN (
            'queued',
            'running',
            'completed',
            'failed',
            'cancelled',
            'awaiting_user_confirmation'
        )
    ),
    CONSTRAINT agent_runs_deployment_class_valid
        CHECK (deployment_class IN ('internal', 'external')),
    CONSTRAINT agent_runs_external_profile_required CHECK (
        deployment_class <> 'external'
        OR (
            provider_data_profile_version IS NOT NULL
            AND length(btrim(provider_data_profile_version)) > 0
        )
    ),
    CONSTRAINT agent_runs_context_hash_valid CHECK (
        context_set_hash IS NULL OR context_set_hash ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT agent_runs_request_fingerprint_valid CHECK (
        request_fingerprint IS NULL
        OR request_fingerprint ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT agent_runs_dispatch_window_valid CHECK (
        (dispatched_at IS NULL AND deadline_at IS NULL)
        OR (
            dispatched_at IS NOT NULL
            AND deadline_at IS NOT NULL
            AND deadline_at > dispatched_at
        )
    ),
    CONSTRAINT agent_runs_dispatch_state_valid CHECK (
        status NOT IN ('queued', 'running', 'completed')
        OR (
            context_set_hash IS NOT NULL
            AND request_fingerprint IS NOT NULL
            AND dispatched_at IS NOT NULL
            AND deadline_at IS NOT NULL
        )
    ),
    CONSTRAINT agent_runs_started_state_valid CHECK (
        status NOT IN ('running', 'completed') OR started_at IS NOT NULL
    ),
    CONSTRAINT agent_runs_started_after_dispatch CHECK (
        started_at IS NULL OR dispatched_at IS NULL OR started_at >= dispatched_at
    ),
    CONSTRAINT agent_runs_finished_state_valid CHECK (
        (status IN ('completed', 'failed', 'cancelled') AND finished_at IS NOT NULL)
        OR (status NOT IN ('completed', 'failed', 'cancelled') AND finished_at IS NULL)
    ),
    CONSTRAINT agent_runs_failure_error_required
        CHECK (
            status <> 'failed'
            OR (error_message IS NOT NULL AND length(btrim(error_message)) > 0)
        ),
    CONSTRAINT agent_runs_id_project_unique UNIQUE (id, project_id),
    CONSTRAINT agent_runs_task_same_project_fk
        FOREIGN KEY (task_id, project_id)
        REFERENCES tasks(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX agent_runs_task_created_idx ON agent_runs (task_id, created_at DESC);
CREATE INDEX agent_runs_project_status_idx
    ON agent_runs (project_id, status, created_at DESC);
CREATE UNIQUE INDEX agent_runs_origin_request_unique_idx
    ON agent_runs (origin_request_id);

CREATE TABLE agent_run_contexts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_run_id uuid NOT NULL,
    project_id uuid NOT NULL,
    memory_object_id uuid NOT NULL,
    document_version_id uuid NOT NULL,
    position integer NOT NULL,
    access_reason text NOT NULL,
    sensitivity_level text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT agent_run_contexts_position_positive CHECK (position > 0),
    CONSTRAINT agent_run_contexts_reason_not_blank
        CHECK (length(btrim(access_reason)) > 0),
    CONSTRAINT agent_run_contexts_sensitivity_valid
        CHECK (sensitivity_level IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT agent_run_contexts_run_version_unique
        UNIQUE (agent_run_id, document_version_id),
    CONSTRAINT agent_run_contexts_run_position_unique
        UNIQUE (agent_run_id, position),
    CONSTRAINT agent_run_contexts_run_same_project_fk
        FOREIGN KEY (agent_run_id, project_id)
        REFERENCES agent_runs(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_contexts_object_same_project_fk
        FOREIGN KEY (memory_object_id, project_id)
        REFERENCES memory_objects(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_contexts_version_same_object_fk
        FOREIGN KEY (document_version_id, memory_object_id)
        REFERENCES document_versions(id, memory_object_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX agent_run_contexts_object_idx
    ON agent_run_contexts (memory_object_id, created_at DESC);
CREATE INDEX agent_run_contexts_run_idx ON agent_run_contexts (agent_run_id);

CREATE TABLE agent_run_results (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_run_id uuid NOT NULL UNIQUE,
    project_id uuid NOT NULL,
    output_storage_uri text NOT NULL,
    content_hash text NOT NULL,
    size_bytes bigint NOT NULL,
    file_type text NOT NULL DEFAULT 'text/markdown',
    output_summary text,
    sensitivity_level text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz,
    saved_memory_object_id uuid,
    saved_at timestamptz,
    CONSTRAINT agent_run_results_storage_uri_not_blank
        CHECK (length(btrim(output_storage_uri)) > 0),
    CONSTRAINT agent_run_results_hash_valid
        CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT agent_run_results_size_nonnegative CHECK (size_bytes >= 0),
    CONSTRAINT agent_run_results_file_type_not_blank
        CHECK (length(btrim(file_type)) > 0),
    CONSTRAINT agent_run_results_sensitivity_valid
        CHECK (sensitivity_level IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT agent_run_results_expiry_valid
        CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT agent_run_results_saved_state_valid CHECK (
        (saved_memory_object_id IS NULL AND saved_at IS NULL)
        OR (saved_memory_object_id IS NOT NULL AND saved_at IS NOT NULL)
    ),
    CONSTRAINT agent_run_results_run_same_project_fk
        FOREIGN KEY (agent_run_id, project_id)
        REFERENCES agent_runs(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_run_results_memory_same_project_fk
        FOREIGN KEY (saved_memory_object_id, project_id)
        REFERENCES memory_objects(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX agent_run_results_unsaved_expiry_idx
    ON agent_run_results (expires_at)
    WHERE saved_memory_object_id IS NULL AND expires_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Authorization decisions, confirmations, and agent capabilities
-- ---------------------------------------------------------------------------

CREATE TABLE authorization_decisions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_type text NOT NULL,
    principal_id uuid NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid,
    project_id uuid REFERENCES projects(id) ON DELETE RESTRICT,
    decision text NOT NULL,
    reason_codes text[] NOT NULL DEFAULT '{}',
    obligations jsonb NOT NULL DEFAULT '[]'::jsonb,
    request_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT authorization_decisions_principal_type_valid
        CHECK (principal_type IN ('user', 'service', 'agent_capability')),
    CONSTRAINT authorization_decisions_action_not_blank
        CHECK (length(btrim(action)) > 0),
    CONSTRAINT authorization_decisions_resource_type_not_blank
        CHECK (length(btrim(resource_type)) > 0),
    CONSTRAINT authorization_decisions_decision_valid
        CHECK (decision IN ('allow', 'deny', 'require_confirmation')),
    CONSTRAINT authorization_decisions_reason_codes_no_nulls
        CHECK (array_position(reason_codes, NULL) IS NULL),
    CONSTRAINT authorization_decisions_reason_required
        CHECK (cardinality(reason_codes) > 0),
    CONSTRAINT authorization_decisions_obligations_array
        CHECK (jsonb_typeof(obligations) = 'array')
);

CREATE INDEX authorization_decisions_request_idx
    ON authorization_decisions (request_id, created_at);
CREATE INDEX authorization_decisions_project_created_idx
    ON authorization_decisions (project_id, created_at DESC)
    WHERE project_id IS NOT NULL;
CREATE INDEX authorization_decisions_principal_created_idx
    ON authorization_decisions (principal_type, principal_id, created_at DESC);

CREATE TABLE confirmations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operation text NOT NULL,
    target_type text NOT NULL,
    target_id uuid NOT NULL,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    requested_by_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    decided_by_user_id uuid REFERENCES app_users(id) ON DELETE RESTRICT,
    authorization_decision_id uuid NOT NULL
        REFERENCES authorization_decisions(id) ON DELETE RESTRICT,
    request_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    frozen_payload jsonb NOT NULL,
    payload_hash text NOT NULL,
    summary text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    decided_at timestamptz,
    consumed_at timestamptz,
    CONSTRAINT confirmations_operation_valid CHECK (
        operation IN (
            'agent_context_share',
            'bulk_context_share',
            'ai_result_save',
            'decision_approve',
            'decision_supersede',
            'sensitivity_lower',
            'break_glass_project_recovery'
        )
    ),
    CONSTRAINT confirmations_target_type_not_blank
        CHECK (length(btrim(target_type)) > 0),
    CONSTRAINT confirmations_status_valid CHECK (
        status IN ('pending', 'approved', 'rejected', 'expired', 'consumed', 'revoked')
    ),
    CONSTRAINT confirmations_frozen_payload_object
        CHECK (jsonb_typeof(frozen_payload) = 'object'),
    CONSTRAINT confirmations_hash_valid
        CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT confirmations_summary_not_blank
        CHECK (length(btrim(summary)) > 0),
    CONSTRAINT confirmations_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT confirmations_decision_state_valid CHECK (
        (status = 'pending' AND decided_by_user_id IS NULL AND decided_at IS NULL AND consumed_at IS NULL)
        OR (status = 'approved' AND decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL AND consumed_at IS NULL)
        OR (status = 'rejected' AND decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL AND consumed_at IS NULL)
        OR (status = 'expired' AND consumed_at IS NULL)
        OR (status = 'revoked' AND consumed_at IS NULL)
        OR (status = 'consumed' AND decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL AND consumed_at IS NOT NULL)
    ),
    CONSTRAINT confirmations_consumed_after_decision
        CHECK (consumed_at IS NULL OR consumed_at >= decided_at)
);

CREATE UNIQUE INDEX confirmations_one_pending_payload_idx
    ON confirmations (operation, target_type, target_id, requested_by_user_id, payload_hash)
    WHERE status = 'pending';
CREATE INDEX confirmations_project_status_idx
    ON confirmations (project_id, status, created_at DESC, id DESC);
CREATE INDEX confirmations_requester_status_idx
    ON confirmations (requested_by_user_id, status, created_at DESC);
CREATE INDEX confirmations_pending_expiry_idx
    ON confirmations (expires_at)
    WHERE status = 'pending';

CREATE TABLE agent_capabilities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_run_id uuid NOT NULL,
    project_id uuid NOT NULL,
    issued_to_service_principal_id uuid NOT NULL
        REFERENCES service_principals(id) ON DELETE RESTRICT,
    allowed_actions text[] NOT NULL,
    context_set_hash text NOT NULL,
    token_hash text NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT agent_capabilities_actions_not_empty
        CHECK (cardinality(allowed_actions) > 0),
    CONSTRAINT agent_capabilities_actions_no_nulls
        CHECK (array_position(allowed_actions, NULL) IS NULL),
    CONSTRAINT agent_capabilities_actions_v1
        CHECK (allowed_actions = ARRAY['context_bundle.read']::text[]),
    CONSTRAINT agent_capabilities_context_hash_valid
        CHECK (context_set_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT agent_capabilities_token_hash_valid
        CHECK (token_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT agent_capabilities_token_hash_unique UNIQUE (token_hash),
    CONSTRAINT agent_capabilities_expiry_valid CHECK (expires_at > issued_at),
    CONSTRAINT agent_capabilities_used_valid
        CHECK (used_at IS NULL OR (used_at >= issued_at AND used_at <= expires_at)),
    CONSTRAINT agent_capabilities_revoked_valid
        CHECK (revoked_at IS NULL OR revoked_at >= issued_at),
    CONSTRAINT agent_capabilities_terminal_state_valid
        CHECK (used_at IS NULL OR revoked_at IS NULL),
    CONSTRAINT agent_capabilities_id_project_unique UNIQUE (id, project_id),
    CONSTRAINT agent_capabilities_run_same_project_fk
        FOREIGN KEY (agent_run_id, project_id)
        REFERENCES agent_runs(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX agent_capabilities_run_issued_idx
    ON agent_capabilities (agent_run_id, issued_at DESC);
CREATE INDEX agent_capabilities_service_expiry_idx
    ON agent_capabilities (issued_to_service_principal_id, expires_at)
    WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE TABLE agent_capability_resources (
    agent_capability_id uuid NOT NULL,
    project_id uuid NOT NULL,
    memory_object_id uuid NOT NULL,
    document_version_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (agent_capability_id, document_version_id),
    CONSTRAINT agent_capability_resources_capability_project_fk
        FOREIGN KEY (agent_capability_id, project_id)
        REFERENCES agent_capabilities(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_capability_resources_object_project_fk
        FOREIGN KEY (memory_object_id, project_id)
        REFERENCES memory_objects(id, project_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT agent_capability_resources_version_object_fk
        FOREIGN KEY (document_version_id, memory_object_id)
        REFERENCES document_versions(id, memory_object_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX agent_capability_resources_object_idx
    ON agent_capability_resources (memory_object_id, document_version_id);

-- ---------------------------------------------------------------------------
-- Cross-object relationships and audit
-- ---------------------------------------------------------------------------

CREATE TABLE relationships (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    source_type text NOT NULL,
    source_id uuid NOT NULL,
    target_type text NOT NULL,
    target_id uuid NOT NULL,
    relation_type text NOT NULL,
    description text,
    created_by_user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT relationships_endpoint_types_valid CHECK (
        source_type IN ('memory_object', 'decision', 'open_question', 'task', 'agent_run')
        AND target_type IN ('memory_object', 'decision', 'open_question', 'task', 'agent_run')
    ),
    CONSTRAINT relationships_type_valid CHECK (
        relation_type IN (
            'references',
            'depends_on',
            'contradicts',
            'supersedes',
            'explains',
            'implements',
            'belongs_to',
            'derived_from'
        )
    ),
    CONSTRAINT relationships_not_self CHECK (
        source_type <> target_type OR source_id <> target_id
    ),
    CONSTRAINT relationships_unique
        UNIQUE (project_id, source_type, source_id, target_type, target_id, relation_type)
);

CREATE INDEX relationships_source_idx
    ON relationships (project_id, source_type, source_id);
CREATE INDEX relationships_target_idx
    ON relationships (project_id, target_type, target_id);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_type text NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    target_type text,
    target_id uuid,
    project_id uuid REFERENCES projects(id) ON DELETE RESTRICT,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    request_id uuid NOT NULL,
    ip_address inet,
    authorization_decision_id uuid
        REFERENCES authorization_decisions(id) ON DELETE RESTRICT,
    CONSTRAINT audit_events_actor_type_valid
        CHECK (actor_type IN ('user', 'director', 'agent', 'service', 'system')),
    CONSTRAINT audit_events_actor_shape_valid CHECK (
        (actor_type = 'system' AND actor_id IS NULL)
        OR (actor_type <> 'system' AND actor_id IS NOT NULL)
    ),
    CONSTRAINT audit_events_action_not_blank CHECK (length(btrim(action)) > 0),
    CONSTRAINT audit_events_target_shape_valid CHECK (
        (target_type IS NULL AND target_id IS NULL)
        OR (
            target_type IS NOT NULL
            AND length(btrim(target_type)) > 0
            AND target_id IS NOT NULL
        )
    ),
    CONSTRAINT audit_events_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX audit_events_project_created_idx
    ON audit_events (project_id, created_at DESC)
    WHERE project_id IS NOT NULL;
CREATE INDEX audit_events_request_idx ON audit_events (request_id, created_at);
CREATE INDEX audit_events_target_idx
    ON audit_events (target_type, target_id, created_at DESC)
    WHERE target_id IS NOT NULL;
CREATE INDEX audit_events_action_created_idx
    ON audit_events (action, created_at DESC);

-- ---------------------------------------------------------------------------
-- RBAC and service-principal seed data
-- ---------------------------------------------------------------------------

INSERT INTO service_principals (code)
VALUES
    ('director-api'),
    ('memory-registry'),
    ('document-store'),
    ('agent-gateway'),
    ('task-worker'),
    ('audit-log');

INSERT INTO permissions (code, description)
VALUES
    ('identity.manage', 'Manage user identities'),
    ('service_principal.manage', 'Manage internal service principals'),
    ('role_assignment.read', 'Read role assignments in the authorized scope'),
    ('role_assignment.manage', 'Manage system role assignments'),
    ('project.create', 'Create a project'),
    ('project.read', 'Read project metadata'),
    ('project.update', 'Update project metadata'),
    ('project.archive', 'Archive a project'),
    ('project.member.manage', 'Manage project members and project roles'),
    ('project.ai_policy.manage', 'Manage project AI egress policy'),
    ('topic.read', 'Read project topics'),
    ('topic.create', 'Create project topics'),
    ('topic.update', 'Update project topics'),
    ('memory_object.search', 'Search the permitted memory registry'),
    ('memory_object.read', 'Read public and internal memory objects'),
    ('memory_object.read_confidential', 'Read confidential memory objects'),
    ('memory_object.read_restricted', 'Read restricted memory objects'),
    ('memory_object.create', 'Create memory objects'),
    ('memory_object.update', 'Update memory object metadata'),
    ('memory_object.archive', 'Archive memory objects'),
    ('document_version.read', 'Read a permitted document version'),
    ('document_version.create', 'Create a document version'),
    ('task.create', 'Create a task'),
    ('task.read', 'Read a task'),
    ('task.cancel', 'Cancel a task'),
    ('agent_run.create', 'Create an AI agent run'),
    ('agent_run.read', 'Read an AI agent run'),
    ('agent_run.cancel', 'Cancel an AI agent run'),
    ('agent_context.share', 'Share permitted ordinary context with an AI agent'),
    ('agent_context.share_confidential', 'Share confidential context with an AI agent'),
    ('agent_provider.use_external', 'Use an approved external AI provider'),
    ('ai_result.save', 'Save an AI result to corporate memory'),
    ('decision.read', 'Read decisions'),
    ('decision.create', 'Create draft or proposed decisions'),
    ('decision.approve', 'Approve decisions'),
    ('decision.supersede', 'Supersede approved decisions'),
    ('confirmation.read', 'Read confirmations'),
    ('confirmation.approve', 'Approve permitted confirmations'),
    ('confirmation.reject', 'Reject permitted confirmations'),
    ('audit_event.read', 'Read audit events in the authorized scope');

INSERT INTO roles (code, name, scope_type, system_defined)
VALUES
    ('platform_admin', 'Platform administrator', 'system', true),
    ('project_owner', 'Project owner', 'project', true),
    ('project_approver', 'Project approver', 'project', true),
    ('project_editor', 'Project editor', 'project', true),
    ('project_viewer', 'Project viewer', 'project', true),
    ('project_auditor', 'Project auditor', 'project', true);

CREATE TEMPORARY TABLE rbac_seed_grants (
    role_code text NOT NULL,
    permission_code text NOT NULL,
    PRIMARY KEY (role_code, permission_code)
) ON COMMIT DROP;

INSERT INTO rbac_seed_grants (role_code, permission_code)
VALUES
    ('platform_admin', 'identity.manage'),
    ('platform_admin', 'service_principal.manage'),
    ('platform_admin', 'role_assignment.read'),
    ('platform_admin', 'role_assignment.manage'),
    ('platform_admin', 'project.create'),

    ('project_owner', 'role_assignment.read'),
    ('project_owner', 'project.read'),
    ('project_owner', 'project.update'),
    ('project_owner', 'project.archive'),
    ('project_owner', 'project.member.manage'),
    ('project_owner', 'project.ai_policy.manage'),
    ('project_owner', 'topic.read'),
    ('project_owner', 'topic.create'),
    ('project_owner', 'topic.update'),
    ('project_owner', 'memory_object.search'),
    ('project_owner', 'memory_object.read'),
    ('project_owner', 'memory_object.read_confidential'),
    ('project_owner', 'memory_object.read_restricted'),
    ('project_owner', 'memory_object.create'),
    ('project_owner', 'memory_object.update'),
    ('project_owner', 'memory_object.archive'),
    ('project_owner', 'document_version.read'),
    ('project_owner', 'document_version.create'),
    ('project_owner', 'task.create'),
    ('project_owner', 'task.read'),
    ('project_owner', 'task.cancel'),
    ('project_owner', 'agent_run.create'),
    ('project_owner', 'agent_run.read'),
    ('project_owner', 'agent_run.cancel'),
    ('project_owner', 'agent_context.share'),
    ('project_owner', 'agent_context.share_confidential'),
    ('project_owner', 'agent_provider.use_external'),
    ('project_owner', 'ai_result.save'),
    ('project_owner', 'decision.read'),
    ('project_owner', 'decision.create'),
    ('project_owner', 'decision.approve'),
    ('project_owner', 'decision.supersede'),
    ('project_owner', 'confirmation.read'),
    ('project_owner', 'confirmation.approve'),
    ('project_owner', 'confirmation.reject'),
    ('project_owner', 'audit_event.read'),

    ('project_approver', 'project.read'),
    ('project_approver', 'topic.read'),
    ('project_approver', 'memory_object.search'),
    ('project_approver', 'memory_object.read'),
    ('project_approver', 'memory_object.read_confidential'),
    ('project_approver', 'document_version.read'),
    ('project_approver', 'task.read'),
    ('project_approver', 'agent_run.read'),
    ('project_approver', 'agent_context.share'),
    ('project_approver', 'agent_context.share_confidential'),
    ('project_approver', 'agent_provider.use_external'),
    ('project_approver', 'decision.read'),
    ('project_approver', 'decision.create'),
    ('project_approver', 'decision.approve'),
    ('project_approver', 'decision.supersede'),
    ('project_approver', 'confirmation.read'),
    ('project_approver', 'confirmation.approve'),
    ('project_approver', 'confirmation.reject'),
    ('project_approver', 'audit_event.read'),

    ('project_editor', 'project.read'),
    ('project_editor', 'topic.read'),
    ('project_editor', 'topic.create'),
    ('project_editor', 'topic.update'),
    ('project_editor', 'memory_object.search'),
    ('project_editor', 'memory_object.read'),
    ('project_editor', 'memory_object.read_confidential'),
    ('project_editor', 'memory_object.create'),
    ('project_editor', 'memory_object.update'),
    ('project_editor', 'memory_object.archive'),
    ('project_editor', 'document_version.read'),
    ('project_editor', 'document_version.create'),
    ('project_editor', 'task.create'),
    ('project_editor', 'task.read'),
    ('project_editor', 'task.cancel'),
    ('project_editor', 'agent_run.create'),
    ('project_editor', 'agent_run.read'),
    ('project_editor', 'agent_run.cancel'),
    ('project_editor', 'agent_context.share'),
    ('project_editor', 'agent_provider.use_external'),
    ('project_editor', 'ai_result.save'),
    ('project_editor', 'decision.read'),
    ('project_editor', 'decision.create'),
    ('project_editor', 'confirmation.read'),
    ('project_editor', 'confirmation.approve'),
    ('project_editor', 'confirmation.reject'),

    ('project_viewer', 'project.read'),
    ('project_viewer', 'topic.read'),
    ('project_viewer', 'memory_object.search'),
    ('project_viewer', 'memory_object.read'),
    ('project_viewer', 'document_version.read'),
    ('project_viewer', 'task.read'),
    ('project_viewer', 'agent_run.read'),
    ('project_viewer', 'decision.read'),

    ('project_auditor', 'role_assignment.read'),
    ('project_auditor', 'project.read'),
    ('project_auditor', 'audit_event.read');

DO $$
DECLARE
    missing_grants text;
BEGIN
    SELECT string_agg(g.role_code || ':' || g.permission_code, ', ' ORDER BY g.role_code, g.permission_code)
    INTO missing_grants
    FROM rbac_seed_grants AS g
    LEFT JOIN roles AS r ON r.code = g.role_code
    LEFT JOIN permissions AS p ON p.code = g.permission_code
    WHERE r.id IS NULL OR p.id IS NULL;

    IF missing_grants IS NOT NULL THEN
        RAISE EXCEPTION 'RBAC seed references missing entries: %', missing_grants;
    END IF;
END;
$$;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM rbac_seed_grants AS g
JOIN roles AS r ON r.code = g.role_code
JOIN permissions AS p ON p.code = g.permission_code;

-- ---------------------------------------------------------------------------
-- Generic trigger helpers
-- ---------------------------------------------------------------------------

CREATE FUNCTION set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE FUNCTION sensitivity_rank(value text)
RETURNS smallint
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE value
        WHEN 'public' THEN 1
        WHEN 'internal' THEN 2
        WHEN 'confidential' THEN 3
        WHEN 'restricted' THEN 4
    END::smallint;
$$;

CREATE FUNCTION reject_row_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = format('%s rows are immutable', TG_TABLE_NAME);
END;
$$;

-- ---------------------------------------------------------------------------
-- Project and role-assignment invariants
-- ---------------------------------------------------------------------------

CREATE FUNCTION validate_role_assignment()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    expected_scope text;
BEGIN
    IF TG_OP = 'INSERT' AND NEW.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new role assignment must start active';
    END IF;

    SELECT scope_type INTO expected_scope
    FROM roles
    WHERE id = NEW.role_id;

    IF expected_scope IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'role does not exist';
    END IF;

    IF NEW.scope_type <> expected_scope THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'role assignment scope does not match role scope';
    END IF;

    IF NEW.principal_type = 'user'
       AND NOT EXISTS (SELECT 1 FROM app_users WHERE id = NEW.principal_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'user principal does not exist';
    END IF;

    IF NEW.principal_type = 'service'
       AND NOT EXISTS (SELECT 1 FROM service_principals WHERE id = NEW.principal_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'service principal does not exist';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.principal_type,
            NEW.principal_id,
            NEW.role_id,
            NEW.scope_type,
            NEW.scope_id,
            NEW.granted_by_user_id,
            NEW.created_at,
            NEW.expires_at
        ) IS DISTINCT FROM ROW(
            OLD.principal_type,
            OLD.principal_id,
            OLD.role_id,
            OLD.scope_type,
            OLD.scope_id,
            OLD.granted_by_user_id,
            OLD.created_at,
            OLD.expires_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'role assignments can only be revoked, not rewritten';
        END IF;

        IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'revoked role assignment is immutable';
        END IF;

        IF OLD.revoked_at IS NULL
           AND NEW.revoked_at IS NOT NULL
           AND NEW.principal_type = 'user'
           AND NEW.scope_type = 'project'
           AND EXISTS (
               SELECT 1
               FROM projects AS p
               JOIN roles AS r ON r.id = NEW.role_id
               WHERE p.id = NEW.scope_id
                 AND p.owner_user_id = NEW.principal_id
                 AND r.code = 'project_owner'
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'primary project owner assignment cannot be revoked';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION bootstrap_project_security()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    owner_role_id uuid;
BEGIN
    SELECT id INTO owner_role_id
    FROM roles
    WHERE code = 'project_owner' AND scope_type = 'project';

    IF owner_role_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'project_owner role must exist before creating projects';
    END IF;

    INSERT INTO project_ai_policies (project_id, updated_by_user_id)
    VALUES (NEW.id, NEW.owner_user_id);

    INSERT INTO role_assignments (
        principal_type,
        principal_id,
        role_id,
        scope_type,
        scope_id,
        granted_by_user_id
    )
    VALUES (
        'user',
        NEW.owner_user_id,
        owner_role_id,
        'project',
        NEW.id,
        NEW.owner_user_id
    );

    RETURN NEW;
END;
$$;

CREATE FUNCTION assign_new_primary_project_owner()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    owner_role_id uuid;
BEGIN
    IF NEW.owner_user_id IS NOT DISTINCT FROM OLD.owner_user_id THEN
        RETURN NEW;
    END IF;

    SELECT id INTO owner_role_id
    FROM roles
    WHERE code = 'project_owner' AND scope_type = 'project';

    IF owner_role_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'project_owner role must exist before transferring ownership';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM role_assignments
        WHERE principal_type = 'user'
          AND principal_id = NEW.owner_user_id
          AND role_id = owner_role_id
          AND scope_type = 'project'
          AND scope_id = NEW.id
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
    ) THEN
        INSERT INTO role_assignments (
            principal_type,
            principal_id,
            role_id,
            scope_type,
            scope_id,
            granted_by_user_id
        )
        VALUES (
            'user',
            NEW.owner_user_id,
            owner_role_id,
            'project',
            NEW.id,
            OLD.owner_user_id
        );
    END IF;

    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Document-version and typed-object invariants
-- ---------------------------------------------------------------------------

CREATE FUNCTION assign_document_version_number()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    expected_version integer;
BEGIN
    PERFORM 1
    FROM memory_objects
    WHERE id = NEW.memory_object_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'memory object does not exist';
    END IF;

    SELECT COALESCE(MAX(version_number), 0) + 1
    INTO expected_version
    FROM document_versions
    WHERE memory_object_id = NEW.memory_object_id;

    IF NEW.version_number IS NULL THEN
        NEW.version_number := expected_version;
    ELSIF NEW.version_number <> expected_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = format('next document version must be %s', expected_version);
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION promote_document_version()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
BEGIN
    UPDATE memory_objects
    SET current_version_id = NEW.id
    WHERE id = NEW.memory_object_id;

    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_current_document_version()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    old_number integer;
    new_number integer;
BEGIN
    IF NEW.current_version_id IS NOT DISTINCT FROM OLD.current_version_id THEN
        RETURN NEW;
    END IF;

    IF NEW.current_version_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'current document version cannot be cleared';
    END IF;

    SELECT version_number INTO new_number
    FROM document_versions
    WHERE id = NEW.current_version_id AND memory_object_id = NEW.id;

    IF new_number IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'current version must belong to the same memory object';
    END IF;

    IF OLD.current_version_id IS NOT NULL THEN
        SELECT version_number INTO old_number
        FROM document_versions
        WHERE id = OLD.current_version_id AND memory_object_id = OLD.id;

        IF new_number <= old_number THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'current document version can only move forward';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_memory_object_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
BEGIN
    IF ROW(
        NEW.id,
        NEW.type,
        NEW.project_id,
        NEW.author_user_id,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.type,
        OLD.project_id,
        OLD.author_user_id,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'memory object identity and type are immutable';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_typed_memory_object()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    expected_type text;
    actual_type text;
    actual_project_id uuid;
BEGIN
    IF TG_OP = 'UPDATE'
       AND ROW(NEW.id, NEW.memory_object_id, NEW.project_id, NEW.created_at)
           IS DISTINCT FROM ROW(OLD.id, OLD.memory_object_id, OLD.project_id, OLD.created_at) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'typed knowledge object identity is immutable';
    END IF;

    expected_type := CASE TG_TABLE_NAME
        WHEN 'decisions' THEN 'decision'
        WHEN 'open_questions' THEN 'open_question'
        ELSE NULL
    END;

    SELECT type, project_id
    INTO actual_type, actual_project_id
    FROM memory_objects
    WHERE id = NEW.memory_object_id;

    IF actual_type IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'memory object does not exist';
    END IF;

    IF actual_type <> expected_type OR actual_project_id <> NEW.project_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = format('%s must extend a %s memory object in the same project', TG_TABLE_NAME, expected_type);
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION enforce_decision_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    prior_status text;
    transition_allowed boolean;
BEGIN
    IF NEW.supersedes_decision_id IS NOT NULL THEN
        SELECT status INTO prior_status
        FROM decisions
        WHERE id = NEW.supersedes_decision_id
          AND project_id = NEW.project_id;

        IF prior_status IS NULL OR prior_status NOT IN ('approved', 'superseded') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'a decision can only supersede an approved decision';
        END IF;
    END IF;

    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;

    IF OLD.status IN ('rejected', 'superseded') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'terminal decision is immutable';
    END IF;

    IF OLD.status = 'approved' THEN
        IF NEW.status <> 'superseded'
           OR ROW(
               NEW.memory_object_id,
               NEW.project_id,
               NEW.topic_id,
               NEW.title,
               NEW.decision_text,
               NEW.rationale,
               NEW.supersedes_decision_id,
               NEW.decided_by_user_id,
               NEW.decided_at,
               NEW.created_at
           ) IS DISTINCT FROM ROW(
               OLD.memory_object_id,
               OLD.project_id,
               OLD.topic_id,
               OLD.title,
               OLD.decision_text,
               OLD.rationale,
               OLD.supersedes_decision_id,
               OLD.decided_by_user_id,
               OLD.decided_at,
               OLD.created_at
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'approved decision can only transition unchanged to superseded';
        END IF;

        RETURN NEW;
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    transition_allowed := CASE OLD.status
        WHEN 'draft' THEN NEW.status IN ('proposed', 'approved', 'rejected')
        WHEN 'proposed' THEN NEW.status IN ('draft', 'approved', 'rejected')
        ELSE false
    END;

    IF NOT transition_allowed THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = format('invalid decision transition: %s -> %s', OLD.status, NEW.status);
    END IF;

    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Task, agent-run, result, confirmation, and capability lifecycles
-- ---------------------------------------------------------------------------

CREATE FUNCTION enforce_task_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    transition_allowed boolean;
BEGIN
    IF ROW(NEW.id, NEW.project_id, NEW.created_by_user_id, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id, OLD.project_id, OLD.created_by_user_id, OLD.created_at) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'task identity is immutable';
    END IF;

    IF OLD.status IN ('completed', 'failed', 'cancelled') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'terminal task is immutable';
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    transition_allowed := CASE OLD.status
        WHEN 'created' THEN NEW.status IN ('planning', 'awaiting_context', 'cancelled')
        WHEN 'planning' THEN NEW.status IN ('awaiting_context', 'failed', 'cancelled')
        WHEN 'awaiting_context' THEN NEW.status IN ('awaiting_user_confirmation', 'running_agent', 'failed', 'cancelled')
        WHEN 'awaiting_user_confirmation' THEN NEW.status IN ('running_agent', 'failed', 'cancelled')
        WHEN 'running_agent' THEN NEW.status IN ('reviewing', 'failed', 'cancelled')
        WHEN 'reviewing' THEN NEW.status IN ('completed', 'failed', 'cancelled')
        ELSE false
    END;

    IF NOT transition_allowed THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = format('invalid task transition: %s -> %s', OLD.status, NEW.status);
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION enforce_agent_run_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    transition_allowed boolean;
BEGIN
    IF ROW(
        NEW.id,
        NEW.task_id,
        NEW.project_id,
        NEW.agent_type,
        NEW.provider,
        NEW.model,
        NEW.purpose,
        NEW.instructions,
        NEW.requested_by_user_id,
        NEW.provider_data_profile_version,
        NEW.deployment_class,
        NEW.origin_request_id,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.task_id,
        OLD.project_id,
        OLD.agent_type,
        OLD.provider,
        OLD.model,
        OLD.purpose,
        OLD.instructions,
        OLD.requested_by_user_id,
        OLD.provider_data_profile_version,
        OLD.deployment_class,
        OLD.origin_request_id,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'agent run request fields are immutable';
    END IF;

    IF OLD.context_set_hash IS NOT NULL
       AND NEW.context_set_hash IS DISTINCT FROM OLD.context_set_hash THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'agent run context hash is immutable once set';
    END IF;

    IF OLD.request_fingerprint IS NOT NULL
       AND NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'agent run request fingerprint is immutable once set';
    END IF;

    IF OLD.dispatched_at IS NOT NULL
       AND ROW(NEW.dispatched_at, NEW.deadline_at)
           IS DISTINCT FROM ROW(OLD.dispatched_at, OLD.deadline_at) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'agent run dispatch window is immutable once set';
    END IF;

    IF OLD.status IN ('completed', 'failed', 'cancelled') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'terminal agent run is immutable';
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    transition_allowed := CASE OLD.status
        WHEN 'queued' THEN NEW.status IN ('running', 'failed', 'cancelled')
        WHEN 'awaiting_user_confirmation' THEN NEW.status IN ('queued', 'cancelled')
        WHEN 'running' THEN NEW.status IN ('completed', 'failed', 'cancelled')
        ELSE false
    END;

    IF NOT transition_allowed THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = format('invalid agent run transition: %s -> %s', OLD.status, NEW.status);
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_agent_run_context_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    run_status text;
    source_sensitivity text;
BEGIN
    SELECT status INTO run_status
    FROM agent_runs
    WHERE id = NEW.agent_run_id AND project_id = NEW.project_id;

    IF run_status IS NULL OR run_status NOT IN ('queued', 'awaiting_user_confirmation') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'agent context can only be attached before an agent run starts';
    END IF;

    SELECT sensitivity_level INTO source_sensitivity
    FROM memory_objects
    WHERE id = NEW.memory_object_id AND project_id = NEW.project_id;

    IF source_sensitivity IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'agent context memory object does not exist in the run project';
    END IF;

    IF NEW.sensitivity_level <> source_sensitivity THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'agent context sensitivity must match the source object';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_agent_run_result()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    result_type text;
    run_status text;
    expected_sensitivity text;
    saved_sensitivity text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT status INTO run_status
        FROM agent_runs
        WHERE id = NEW.agent_run_id AND project_id = NEW.project_id;

        IF run_status IS NULL OR run_status NOT IN ('running', 'completed') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'agent result can only be recorded for a running or completed run';
        END IF;

        SELECT sensitivity_level INTO expected_sensitivity
        FROM agent_run_contexts
        WHERE agent_run_id = NEW.agent_run_id AND project_id = NEW.project_id
        ORDER BY sensitivity_rank(sensitivity_level) DESC
        LIMIT 1;

        IF expected_sensitivity IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'agent result requires a frozen context';
        END IF;

        IF NEW.sensitivity_level <> expected_sensitivity THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'agent result sensitivity must match the highest context sensitivity';
        END IF;
    END IF;

    IF NEW.saved_memory_object_id IS NOT NULL THEN
        SELECT type, sensitivity_level INTO result_type, saved_sensitivity
        FROM memory_objects
        WHERE id = NEW.saved_memory_object_id
          AND project_id = NEW.project_id;

        IF result_type IS NULL OR result_type <> 'ai_result' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'saved agent result must reference an ai_result memory object';
        END IF;

        IF sensitivity_rank(saved_sensitivity) < sensitivity_rank(NEW.sensitivity_level) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'saved AI result cannot lower the result sensitivity';
        END IF;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.agent_run_id,
            NEW.project_id,
            NEW.output_storage_uri,
            NEW.content_hash,
            NEW.size_bytes,
            NEW.file_type,
            NEW.output_summary,
            NEW.sensitivity_level,
            NEW.created_at,
            NEW.expires_at
        ) IS DISTINCT FROM ROW(
            OLD.agent_run_id,
            OLD.project_id,
            OLD.output_storage_uri,
            OLD.content_hash,
            OLD.size_bytes,
            OLD.file_type,
            OLD.output_summary,
            OLD.sensitivity_level,
            OLD.created_at,
            OLD.expires_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'agent result payload is immutable';
        END IF;

        IF OLD.saved_memory_object_id IS NOT NULL
           AND ROW(NEW.saved_memory_object_id, NEW.saved_at)
               IS DISTINCT FROM ROW(OLD.saved_memory_object_id, OLD.saved_at) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'saved agent result link is immutable';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION enforce_confirmation_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    transition_allowed boolean;
    source_decision text;
    source_project_id uuid;
    source_request_id uuid;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'confirmation must start as pending';
        END IF;

        SELECT decision, project_id, request_id
        INTO source_decision, source_project_id, source_request_id
        FROM authorization_decisions
        WHERE id = NEW.authorization_decision_id;

        IF source_decision IS NULL
           OR source_decision <> 'require_confirmation'
           OR source_project_id IS DISTINCT FROM NEW.project_id
           OR source_request_id IS DISTINCT FROM NEW.request_id THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'confirmation must match a require_confirmation authorization decision';
        END IF;

        RETURN NEW;
    END IF;

    IF ROW(
        NEW.operation,
        NEW.target_type,
        NEW.target_id,
        NEW.project_id,
        NEW.requested_by_user_id,
        NEW.authorization_decision_id,
        NEW.request_id,
        NEW.frozen_payload,
        NEW.payload_hash,
        NEW.summary,
        NEW.created_at,
        NEW.expires_at
    ) IS DISTINCT FROM ROW(
        OLD.operation,
        OLD.target_type,
        OLD.target_id,
        OLD.project_id,
        OLD.requested_by_user_id,
        OLD.authorization_decision_id,
        OLD.request_id,
        OLD.frozen_payload,
        OLD.payload_hash,
        OLD.summary,
        OLD.created_at,
        OLD.expires_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'confirmation payload is immutable';
    END IF;

    IF OLD.status IN ('rejected', 'expired', 'consumed', 'revoked') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'terminal confirmation is immutable';
    END IF;

    transition_allowed := CASE OLD.status
        WHEN 'pending' THEN NEW.status IN ('approved', 'rejected', 'expired', 'consumed', 'revoked')
        WHEN 'approved' THEN NEW.status IN ('consumed', 'revoked')
        ELSE false
    END;

    IF NEW.status = OLD.status OR NOT transition_allowed THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = format('invalid confirmation transition: %s -> %s', OLD.status, NEW.status);
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_agent_capability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    run_context_hash text;
    run_request_fingerprint text;
    run_deadline_at timestamptz;
    run_status text;
    service_code text;
    service_status text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.used_at IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'new capability must start unused and active';
        END IF;

        SELECT context_set_hash, request_fingerprint, deadline_at, status
        INTO run_context_hash, run_request_fingerprint, run_deadline_at, run_status
        FROM agent_runs
        WHERE id = NEW.agent_run_id AND project_id = NEW.project_id;

        IF run_context_hash IS NULL OR run_context_hash <> NEW.context_set_hash THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'capability must match the frozen agent-run context hash';
        END IF;

        IF run_status <> 'queued'
           OR run_request_fingerprint IS NULL
           OR run_deadline_at IS NULL
           OR run_deadline_at <= CURRENT_TIMESTAMP THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'capability requires a dispatch-ready queued agent run';
        END IF;

        IF NEW.expires_at > run_deadline_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'capability cannot outlive the agent-run deadline';
        END IF;

        SELECT code, status INTO service_code, service_status
        FROM service_principals
        WHERE id = NEW.issued_to_service_principal_id;

        IF service_code IS NULL
           OR service_code <> 'agent-gateway'
           OR service_status <> 'active' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'capability can only be issued to the active agent-gateway service';
        END IF;

        RETURN NEW;
    END IF;

    IF ROW(
        NEW.agent_run_id,
        NEW.project_id,
        NEW.issued_to_service_principal_id,
        NEW.allowed_actions,
        NEW.context_set_hash,
        NEW.token_hash,
        NEW.issued_at,
        NEW.expires_at
    ) IS DISTINCT FROM ROW(
        OLD.agent_run_id,
        OLD.project_id,
        OLD.issued_to_service_principal_id,
        OLD.allowed_actions,
        OLD.context_set_hash,
        OLD.token_hash,
        OLD.issued_at,
        OLD.expires_at
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'capability grant is immutable';
    END IF;

    IF OLD.used_at IS NOT NULL AND NEW.used_at IS DISTINCT FROM OLD.used_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'used capability is immutable';
    END IF;

    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'revoked capability is immutable';
    END IF;

    IF NEW.used_at IS NOT NULL AND NEW.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'capability cannot be both used and revoked';
    END IF;

    IF NEW.used_at IS NOT NULL AND NEW.used_at > NEW.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'expired capability cannot be used';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_agent_capability_resource()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
DECLARE
    capability_run_id uuid;
    capability_expires_at timestamptz;
    capability_used_at timestamptz;
    capability_revoked_at timestamptz;
BEGIN
    SELECT agent_run_id, expires_at, used_at, revoked_at
    INTO capability_run_id, capability_expires_at, capability_used_at, capability_revoked_at
    FROM agent_capabilities
    WHERE id = NEW.agent_capability_id
      AND project_id = NEW.project_id;

    IF capability_run_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'agent capability does not exist';
    END IF;

    IF capability_used_at IS NOT NULL
       OR capability_revoked_at IS NOT NULL
       OR capability_expires_at <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'resources cannot be attached to inactive capability';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM agent_run_contexts
        WHERE agent_run_id = capability_run_id
          AND project_id = NEW.project_id
          AND memory_object_id = NEW.memory_object_id
          AND document_version_id = NEW.document_version_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'capability resource must belong to the frozen agent-run context';
    END IF;

    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Relationship validation
-- ---------------------------------------------------------------------------

CREATE FUNCTION endpoint_belongs_to_project(
    endpoint_type text,
    endpoint_id uuid,
    expected_project_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = dirizhor, pg_temp
AS $$
BEGIN
    RETURN CASE endpoint_type
        WHEN 'memory_object' THEN EXISTS (
            SELECT 1 FROM memory_objects WHERE id = endpoint_id AND project_id = expected_project_id
        )
        WHEN 'decision' THEN EXISTS (
            SELECT 1 FROM decisions WHERE id = endpoint_id AND project_id = expected_project_id
        )
        WHEN 'open_question' THEN EXISTS (
            SELECT 1 FROM open_questions WHERE id = endpoint_id AND project_id = expected_project_id
        )
        WHEN 'task' THEN EXISTS (
            SELECT 1 FROM tasks WHERE id = endpoint_id AND project_id = expected_project_id
        )
        WHEN 'agent_run' THEN EXISTS (
            SELECT 1 FROM agent_runs WHERE id = endpoint_id AND project_id = expected_project_id
        )
        ELSE false
    END;
END;
$$;

CREATE FUNCTION validate_relationship_endpoints()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = dirizhor, pg_temp
AS $$
BEGIN
    IF NOT endpoint_belongs_to_project(NEW.source_type, NEW.source_id, NEW.project_id)
       OR NOT endpoint_belongs_to_project(NEW.target_type, NEW.target_id, NEW.project_id) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'relationship endpoints must exist in the same project';
    END IF;

    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Triggers
-- ---------------------------------------------------------------------------

CREATE TRIGGER app_users_set_updated_at
BEFORE UPDATE ON app_users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER app_users_reject_delete
BEFORE DELETE ON app_users
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER service_principals_reject_delete
BEFORE DELETE ON service_principals
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER user_identities_set_updated_at
BEFORE UPDATE ON user_identities
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER projects_set_updated_at
BEFORE UPDATE ON projects
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER projects_bootstrap_security
AFTER INSERT ON projects
FOR EACH ROW EXECUTE FUNCTION bootstrap_project_security();

CREATE TRIGGER projects_assign_new_primary_owner
AFTER UPDATE OF owner_user_id ON projects
FOR EACH ROW EXECUTE FUNCTION assign_new_primary_project_owner();

CREATE TRIGGER projects_reject_delete
BEFORE DELETE ON projects
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER role_assignments_validate
BEFORE INSERT OR UPDATE ON role_assignments
FOR EACH ROW EXECUTE FUNCTION validate_role_assignment();

CREATE TRIGGER role_assignments_reject_delete
BEFORE DELETE ON role_assignments
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER project_ai_policies_set_updated_at
BEFORE UPDATE ON project_ai_policies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER project_ai_policies_reject_delete
BEFORE DELETE ON project_ai_policies
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER topics_set_updated_at
BEFORE UPDATE ON topics
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER topics_reject_delete
BEFORE DELETE ON topics
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER memory_objects_protect_current_version
BEFORE UPDATE OF current_version_id ON memory_objects
FOR EACH ROW EXECUTE FUNCTION protect_current_document_version();

CREATE TRIGGER memory_objects_protect_identity
BEFORE UPDATE ON memory_objects
FOR EACH ROW EXECUTE FUNCTION protect_memory_object_identity();

CREATE TRIGGER memory_objects_set_updated_at
BEFORE UPDATE ON memory_objects
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER memory_objects_reject_delete
BEFORE DELETE ON memory_objects
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER document_versions_assign_number
BEFORE INSERT ON document_versions
FOR EACH ROW EXECUTE FUNCTION assign_document_version_number();

CREATE TRIGGER document_versions_promote
AFTER INSERT ON document_versions
FOR EACH ROW EXECUTE FUNCTION promote_document_version();

CREATE TRIGGER document_versions_immutable
BEFORE UPDATE OR DELETE ON document_versions
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER decisions_validate_memory_object
BEFORE INSERT OR UPDATE ON decisions
FOR EACH ROW EXECUTE FUNCTION validate_typed_memory_object();

CREATE TRIGGER decisions_enforce_lifecycle
BEFORE UPDATE OR INSERT ON decisions
FOR EACH ROW EXECUTE FUNCTION enforce_decision_lifecycle();

CREATE TRIGGER decisions_set_updated_at
BEFORE UPDATE ON decisions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER decisions_reject_delete
BEFORE DELETE ON decisions
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER open_questions_validate_memory_object
BEFORE INSERT OR UPDATE ON open_questions
FOR EACH ROW EXECUTE FUNCTION validate_typed_memory_object();

CREATE TRIGGER open_questions_set_updated_at
BEFORE UPDATE ON open_questions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER open_questions_reject_delete
BEFORE DELETE ON open_questions
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER tasks_enforce_lifecycle
BEFORE UPDATE ON tasks
FOR EACH ROW EXECUTE FUNCTION enforce_task_lifecycle();

CREATE TRIGGER tasks_set_updated_at
BEFORE UPDATE ON tasks
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER tasks_reject_delete
BEFORE DELETE ON tasks
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER agent_runs_enforce_lifecycle
BEFORE UPDATE ON agent_runs
FOR EACH ROW EXECUTE FUNCTION enforce_agent_run_lifecycle();

CREATE TRIGGER agent_runs_reject_delete
BEFORE DELETE ON agent_runs
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER agent_run_contexts_validate_insert
BEFORE INSERT ON agent_run_contexts
FOR EACH ROW EXECUTE FUNCTION validate_agent_run_context_insert();

CREATE TRIGGER agent_run_contexts_immutable
BEFORE UPDATE OR DELETE ON agent_run_contexts
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER agent_run_results_protect
BEFORE INSERT OR UPDATE ON agent_run_results
FOR EACH ROW EXECUTE FUNCTION protect_agent_run_result();

CREATE TRIGGER agent_run_results_reject_delete
BEFORE DELETE ON agent_run_results
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER authorization_decisions_immutable
BEFORE UPDATE OR DELETE ON authorization_decisions
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER confirmations_enforce_lifecycle
BEFORE INSERT OR UPDATE ON confirmations
FOR EACH ROW EXECUTE FUNCTION enforce_confirmation_lifecycle();

CREATE TRIGGER confirmations_reject_delete
BEFORE DELETE ON confirmations
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER agent_capabilities_validate
BEFORE INSERT OR UPDATE ON agent_capabilities
FOR EACH ROW EXECUTE FUNCTION validate_agent_capability();

CREATE TRIGGER agent_capabilities_reject_delete
BEFORE DELETE ON agent_capabilities
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER agent_capability_resources_validate
BEFORE INSERT ON agent_capability_resources
FOR EACH ROW EXECUTE FUNCTION validate_agent_capability_resource();

CREATE TRIGGER agent_capability_resources_immutable
BEFORE UPDATE OR DELETE ON agent_capability_resources
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER relationships_validate_endpoints
BEFORE INSERT OR UPDATE ON relationships
FOR EACH ROW EXECUTE FUNCTION validate_relationship_endpoints();

CREATE TRIGGER audit_events_immutable
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

COMMIT;
