# Pilot Operations Runbook

## Before Apply

1. Confirm `terraform plan` shows only the intended pilot resources.
2. Confirm region, sizes, node counts, and domain.
3. Confirm Terraform state location and access controls.
4. Confirm the operator has explicit approval to create paid DigitalOcean resources.

## After Apply

Configure local access:

```bash
doctl kubernetes cluster kubeconfig save dirizher-pilot-doks
kubectl get nodes
```

Publish OCI images through the protected manual workflow
`.github/workflows/pilot-oci-release.yml`. Do not copy the DigitalOcean token
into shell history or a repository-level GitHub secret.

Verify the pre-created application namespace and its restricted Pod Security
labels. Creating or replacing it still requires explicit approval:

```bash
kubectl get namespace dirizhor-pilot --show-labels
```

Render schema-v3 digest-only workloads with `public.exposure=internal` only
after the OCI evidence is `PASS`. DOKS must accept the exact-FQDN
`CiliumNetworkPolicy` resources in server-side dry-run. The resulting Edge
Service must be `ClusterIP`; a `LoadBalancer` before internal canaries is
stop-ship. Install ingress and certificates only after internal canaries pass:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx --namespace ingress-nginx --create-namespace
helm upgrade --install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set crds.enabled=true
```

## Evidence Checklist

- Kubernetes nodes are Ready.
- The protected OCI workflow produced a retained `PASS` evidence artifact.
- Registry images have verified digest references, SBOMs, scans, and signatures.
- Application pods run from pinned OCI image digests.
- PostgreSQL is reachable only from DOKS/private network.
- HTTPS certificate is valid for the pilot domain.
- OIDC login works in the pilot domain.
- Monitoring shows app, ingress, node, and database health.
- PostgreSQL restore has been tested and documented.
