# Pilot health check

The health check is read-only. It verifies the public HTTPS status and, when
`KUBECTL_BIN` and `KUBECONFIG` are supplied, readiness of the four application
Deployments in `PILOT_NAMESPACE`. It does not read Secrets, pod logs, response
bodies, or image credentials.

```bash
PILOT_NAMESPACE=dirizhor-pilot \
KUBECTL_BIN=.tools/bin/kubectl \
KUBECONFIG=/path/to/kubeconfig \
node deploy/reference/scripts/pilot-health-check.mjs
```

The command prints one safe JSON object. `status=PASS` requires HTTP 2xx/3xx
and all required Deployments to have matching updated, ready, and available
replica counts. Without Kubernetes variables the cluster check is explicitly
reported as `SKIPPED`.
