# Operational metric contracts

Status: prepared contract; these signals are `NOT_RUN` until the listed metrics
are emitted and scraped. Rules must not be marked `PASS` merely because their
PromQL text exists.

| Signal | Required metric | Proposed alert condition |
| --- | --- | --- |
| PostgreSQL availability | `dirizhor_postgres_up` | value is below 1 for 120 seconds |
| PostgreSQL connections | `dirizhor_postgres_connections{state="used"}`, `dirizhor_postgres_connections_limit` | used/limit exceeds 0.8 for 5 minutes |
| PostgreSQL lock waits | `dirizhor_postgres_lock_waiting` | above 0 for 5 minutes |
| PostgreSQL backup/PITR | `dirizhor_postgres_backup_last_success_timestamp_seconds` | age exceeds 900 seconds |
| Document Store backup | `dirizhor_document_store_backup_last_success_timestamp_seconds` | age exceeds 1800 seconds |
| Restore drill | `dirizhor_restore_drill_last_success_timestamp_seconds` | age exceeds the approved drill cadence |
| Queue/stuck task | `dirizhor_gateway_queue_oldest_seconds` | above approved threshold; threshold is not yet adopted |
| Audit write | `dirizhor_audit_write_failures_total` | increase is above 0 for 5 minutes |
| Director/Gateway process | existing `dirizhor_service_up`, `dirizhor_readiness` | rules already present |

The current application metrics expose HTTP/readiness and process status only.
Implementing the additional exporters changes runtime code and requires a later
controlled OCI release and rollout; it is not claimed as live coverage here.
