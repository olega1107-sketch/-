# Pilot Readiness Stages

The base Terraform layer provisions VPC, DOKS, Managed PostgreSQL, and Container Registry only. The following stages complete the 6/6 pilot evidence path.

## 1. DNS and TLS

- Decide the pilot hostname, for example `pilot.example.com`.
- Manage DNS in DigitalOcean or delegate the subdomain to DigitalOcean nameservers.
- Install an ingress controller, usually `ingress-nginx`.
- Install `cert-manager`.
- Configure a Let's Encrypt ClusterIssuer.
- Validate HTTPS externally and renewals internally.

## 2. Secrets

- Keep secrets out of git and Terraform outputs.
- Store application secrets in a dedicated secret manager.
- Sync secrets into Kubernetes with External Secrets Operator or sealed secrets.
- Rotate database and OIDC client credentials after the first successful deployment.

## 3. OIDC

- Choose the identity provider.
- Register pilot callback URLs.
- Configure application client ID, issuer, audience, and redirect URLs through Kubernetes secrets.
- Add a smoke test that verifies login and token validation.

## 4. Monitoring

- Install metrics collection for Kubernetes workloads.
- Add application health endpoints and alerting.
- Track ingress latency, error rate, pod restarts, node pressure, and PostgreSQL metrics.
- Add an external uptime check for the pilot hostname.

## 5. Backups

- Confirm DigitalOcean Managed PostgreSQL backup/PITR policy.
- Run and document a restore test.
- Back up Kubernetes manifests, Helm values, and Terraform state.
- Define RPO/RTO expectations for pilot.

## 6. OCI Delivery

- Publish `.github/workflows/pilot-oci-release.yml` only after review.
- Protect the GitHub environment `digitalocean-pilot` with manual approval and
  a dedicated short-lived `DIGITALOCEAN_ACCESS_TOKEN` environment secret.
- Run the workflow manually with an approved release ID; do not add automatic
  `push` or `pull_request` triggers.
- Retain the OCI evidence artifact and deploy only its digest references.
- Keep rollback instructions and image provenance for every pilot release.
