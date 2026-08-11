DO $schema_v1_verify$
DECLARE
    missing_objects text[];
BEGIN
    IF current_setting('server_version_num')::integer < 150000 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema v1 requires PostgreSQL 15 or newer';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema v1 verification failed: pgcrypto is missing';
    END IF;

    SELECT array_agg(required.name ORDER BY required.name)
    INTO missing_objects
    FROM (
        VALUES
            ('app_users'),
            ('user_identities'),
            ('user_sessions'),
            ('oidc_login_transactions'),
            ('service_principals'),
            ('permissions'),
            ('roles'),
            ('role_permissions'),
            ('projects'),
            ('role_assignments'),
            ('project_ai_policies'),
            ('topics'),
            ('memory_objects'),
            ('document_versions'),
            ('decisions'),
            ('open_questions'),
            ('tasks'),
            ('agent_runs'),
            ('agent_run_contexts'),
            ('agent_run_results'),
            ('authorization_decisions'),
            ('confirmations'),
            ('agent_capabilities'),
            ('agent_capability_resources'),
            ('relationships'),
            ('audit_events')
    ) AS required(name)
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'dirizhor'
          AND relation.relname = required.name
          AND relation.relkind IN ('r', 'p')
    );
    IF missing_objects IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = format(
                'schema v1 verification failed: missing tables %s',
                array_to_string(missing_objects, ', ')
            );
    END IF;

    SELECT array_agg(required.table_name || '.' || required.column_name
                     ORDER BY required.table_name, required.column_name)
    INTO missing_objects
    FROM (
        VALUES
            ('app_users', 'status'),
            ('user_identities', 'provider_issuer'),
            ('user_identities', 'secret_hash'),
            ('user_sessions', 'session_token_hash'),
            ('user_sessions', 'revoked_at'),
            ('oidc_login_transactions', 'state_hash'),
            ('oidc_login_transactions', 'code_verifier'),
            ('project_ai_policies', 'provider_data_profile_versions'),
            ('memory_objects', 'sensitivity_level'),
            ('agent_runs', 'request_fingerprint'),
            ('agent_runs', 'deadline_at'),
            ('agent_run_results', 'saved_memory_object_id'),
            ('authorization_decisions', 'obligations'),
            ('confirmations', 'frozen_payload'),
            ('agent_capabilities', 'token_hash'),
            ('audit_events', 'authorization_decision_id')
    ) AS required(table_name, column_name)
    WHERE NOT EXISTS (
        SELECT 1
        FROM information_schema.columns AS column_definition
        WHERE column_definition.table_schema = 'dirizhor'
          AND column_definition.table_name = required.table_name
          AND column_definition.column_name = required.column_name
    );
    IF missing_objects IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = format(
                'schema v1 verification failed: missing columns %s',
                array_to_string(missing_objects, ', ')
            );
    END IF;

    SELECT array_agg(required.name ORDER BY required.name)
    INTO missing_objects
    FROM (
        VALUES
            ('set_updated_at'),
            ('sensitivity_rank'),
            ('reject_row_mutation'),
            ('validate_role_assignment'),
            ('bootstrap_project_security'),
            ('assign_new_primary_project_owner'),
            ('assign_document_version_number'),
            ('promote_document_version'),
            ('protect_current_document_version'),
            ('protect_memory_object_identity'),
            ('validate_typed_memory_object'),
            ('enforce_decision_lifecycle'),
            ('enforce_task_lifecycle'),
            ('enforce_agent_run_lifecycle'),
            ('validate_agent_run_context_insert'),
            ('protect_agent_run_result'),
            ('enforce_confirmation_lifecycle'),
            ('validate_agent_capability'),
            ('validate_agent_capability_resource'),
            ('endpoint_belongs_to_project'),
            ('validate_relationship_endpoints')
    ) AS required(name)
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_proc AS procedure
        JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'dirizhor'
          AND procedure.proname = required.name
    );
    IF missing_objects IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = format(
                'schema v1 verification failed: missing functions %s',
                array_to_string(missing_objects, ', ')
            );
    END IF;

    SELECT array_agg(required.name ORDER BY required.name)
    INTO missing_objects
    FROM (
        VALUES
            ('app_users_reject_delete'),
            ('role_assignments_validate'),
            ('memory_objects_protect_identity'),
            ('document_versions_immutable'),
            ('tasks_enforce_lifecycle'),
            ('agent_runs_enforce_lifecycle'),
            ('agent_run_contexts_immutable'),
            ('agent_run_results_protect'),
            ('authorization_decisions_immutable'),
            ('confirmations_enforce_lifecycle'),
            ('agent_capabilities_validate'),
            ('agent_capability_resources_immutable'),
            ('relationships_validate_endpoints'),
            ('audit_events_immutable')
    ) AS required(name)
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_trigger AS trigger_definition
        JOIN pg_class AS relation ON relation.oid = trigger_definition.tgrelid
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'dirizhor'
          AND trigger_definition.tgname = required.name
          AND NOT trigger_definition.tgisinternal
    );
    IF missing_objects IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = format(
                'schema v1 verification failed: missing triggers %s',
                array_to_string(missing_objects, ', ')
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM dirizhor.service_principals
        WHERE code = 'agent-gateway' AND status = 'active'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema v1 verification failed: agent-gateway principal is missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM dirizhor.permissions WHERE code = 'project.read'
    ) OR NOT EXISTS (
        SELECT 1 FROM dirizhor.permissions WHERE code = 'agent_run.create'
    ) OR NOT EXISTS (
        SELECT 1 FROM dirizhor.roles WHERE code = 'project_owner'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema v1 verification failed: RBAC baseline is incomplete';
    END IF;
END;
$schema_v1_verify$;
