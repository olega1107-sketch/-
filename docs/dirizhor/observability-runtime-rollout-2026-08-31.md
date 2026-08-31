# Observability runtime rollout - 31 August 2026

## Scope

This evidence records the controlled rollout of the observability additions in
commits `59dc003` and `9a0da7e`. The scope was limited to:

- `PrometheusRule/dirizhor-pilot` in namespace `monitoring`;
- `Deployment/dirizhor-director` in namespace `dirizhor-pilot`;
- `Deployment/dirizhor-gateway` in namespace `dirizhor-pilot`.

No Edge workload, Service, Secret, NetworkPolicy, DNS, Ingress, LoadBalancer,
or other application workload was changed.

## Release and rollout

- Architecture CI: GitHub Actions run `33429518415`, `success`.
- Pilot OCI release: GitHub Actions run `33432767563`, `success`.
- Director image:
  `registry.digitalocean.com/dirizherpilotregistry/director@sha256:05982f13cd0bb2a62bd414964b365970e91cdad4b81d1b70fa74b7934207bcac`.
- Gateway image:
  `registry.digitalocean.com/dirizherpilotregistry/gateway@sha256:9d312314946d66b239da9ab01e6d2764753e4e5d10fde748a998a184959ebe92`.
- Server-side dry-run passed for both image patches. The complete
  `PrometheusRule` server-side apply reported an existing Helm field-manager
  conflict, so no force ownership was used. A server-side dry-run of a JSON
  patch that appended only the five new rules passed before that exact patch was
  applied.
- Both Deployments completed rollout and reported `1/1 Ready`.

## Runtime collection evidence

The private Prometheus targets for both `director` and `gateway` were `UP`.
Prometheus query results after rollout were:

| Series | Value |
| --- | ---: |
| `dirizhor_postgres_up{service="director"}` | 1 |
| `dirizhor_document_store_up{service="director"}` | 1 |
| `dirizhor_audit_write_failures_total{service="director"}` | 0 |
| `dirizhor_gateway_queue_pending{service="gateway"}` | 0 |
| `dirizhor_gateway_queue_oldest_seconds{service="gateway"}` | 0 |
| `dirizhor_gateway_queue_scan_failures_total{service="gateway"}` | 0 |

The following rules are present in the live `dirizhor-pilot` rule resource:

- `DirizhorPostgresUnavailable`;
- `DirizhorDocumentStoreUnavailable`;
- `DirizhorAuditWriteFailure`;
- `DirizhorGatewayQueueStuck`;
- `DirizhorGatewayQueueScanFailure`.

## Gate status

Runtime metric collection and target discovery for these six series: `PASS`.
Each new alert rule remains `NOT_RUN` for delivery evidence until it has a
controlled firing, Alertmanager route acceptance, provider acceptance, and
recipient confirmation. This document does not claim that a static rule or a
visible series proves alert delivery.
