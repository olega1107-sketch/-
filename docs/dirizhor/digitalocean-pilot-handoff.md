# DigitalOcean Pilot Handoff

Date: 2026-08-17

The DigitalOcean pilot environment for Dirizhor is represented by the Terraform
configuration under `infra/terraform`. Provider resource IDs and private service
endpoints are intentionally omitted from this public document and remain in the
protected local Terraform state.

## Created Resources

- VPC: `dirizher-pilot-vpc`
  - Region: `fra1`
  - CIDR: `10.42.0.0/16`
- DOKS Kubernetes: `dirizher-pilot-doks`
  - Version: `1.36.3-do.1`
  - Status verified: `running`
  - Node pool: `dirizher-pilot-workers`
  - Size: `s-2vcpu-4gb`
  - Current nodes: 2
  - Autoscale: min 2, max 3
- DigitalOcean Container Registry:
  - Name: `dirizherpilotregistry`
  - Endpoint: `registry.digitalocean.com/dirizherpilotregistry`
  - Region: `fra1`
- Managed PostgreSQL:
  - Name: `dirizher-pilot-postgres`
  - Engine: PostgreSQL 16
  - Region: `fra1`
  - Size: `db-s-1vcpu-1gb`
  - Nodes: 1
  - Status verified: `online`
  - Port: `25060`
  - Database: `dirizher`
  - App user: `dirizher_app`
- PostgreSQL firewall:
  - Allows only the pilot DOKS cluster.

## Verification Completed

- DigitalOcean account access confirmed.
- `terraform init` completed.
- `terraform validate` completed.
- `terraform apply` completed.
- Final `terraform plan` returned `No changes`.
- `kubectl get nodes` showed both worker nodes as `Ready`.
- DigitalOcean registry was reachable.
- Managed PostgreSQL was `online`.
- PostgreSQL firewall rule was present and tied to DOKS.
- Both DOKS worker nodes were `Ready`; only system workloads were present.
- The DigitalOcean project has a USD 130 monthly spend alert at 50%, 75%, 90%,
  and 100%. This alert does not impose a hard spending cap.

## OCI Delivery Status

- `.github/workflows/pilot-oci-release.yml` is prepared for a protected manual
  release from the GitHub environment `digitalocean-pilot`.
- The workflow pins Docker, Buildx, Syft, Trivy, Cosign, Node, pnpm, and both
  runtime base images; verifies downloaded tool checksums; scans `HIGH` and
  `CRITICAL` vulnerabilities; and performs keyless Sigstore signing.
- The workflow has passed repository tests, YAML parsing, and `actionlint`.
- The registry currently contains no application images.
- The OCI workflow has not been pushed or executed and no OCI evidence exists.
- No application namespace or application pods have been deployed.

## Sensitive Local Files

These files must not be committed:

- `infra/terraform/environments/pilot/.env.local`
- `infra/terraform/environments/pilot/terraform.tfvars`
- `infra/terraform/terraform.tfstate`
- `infra/terraform/terraform.tfstate.backup`
- `kubeconfig.pilot`
- `work/kubeconfig`

The local Terraform state contains sensitive database credentials. Keep it out of git. For continued project work, move state to a protected remote backend or import the existing resources into a secure state location before running more Terraform from the main project.

## Current Limitation

The DigitalOcean account droplet limit is 3. The DOKS autoscale maximum was reduced from 4 to 3 to fit that limit.

## Next Stage

Proceed in this order:

1. Review and publish the branch containing the protected OCI workflow.
2. Create the GitHub environment `digitalocean-pilot`, require manual approval,
   and add a dedicated short-lived registry-write token as the environment
   secret `DIGITALOCEAN_ACCESS_TOKEN`.
3. Manually run the OCI workflow and retain its evidence artifact.
4. Select the pilot DNS name and configure OIDC callback URLs.
5. Prepare runtime mTLS, OIDC, database, and signing secrets outside git.
6. Render digest-only Kubernetes manifests and deploy without public ingress.
7. Complete internal canaries, backup/restore verification, monitoring, and
   alerting before enabling ingress.
