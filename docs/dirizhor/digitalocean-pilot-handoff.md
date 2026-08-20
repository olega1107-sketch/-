# DigitalOcean Pilot Handoff

Date: 2026-08-20

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

- Protected manual release `ARCH-V1.16-OCI-05` completed successfully from
  exact commit `6cfd69421ebc8fc0fb07dcf6fd2eae0f1356bfd4` in GitHub Actions run
  `32345638852`.
- Retained artifact `pilot-oci-evidence-32345638852-1` has digest
  `sha256:b5d2ac51cac0b70f9522afc134197af7bc1fc2e402fb71c00a13470a835b599e`.
- Node build, Director, Gateway, and Edge Trivy reports contain zero `HIGH` or
  `CRITICAL` findings. Director, Gateway, and Edge signatures and CycloneDX
  attestations were verified.
- Deploy only these immutable application references:
  - Director: `registry.digitalocean.com/dirizherpilotregistry/director@sha256:0433a40cc7fc34021b94a1f44562f349ef634f7d4e0b0c1539b65ea8adadad9e`
  - Gateway: `registry.digitalocean.com/dirizherpilotregistry/gateway@sha256:8593ed918fd57d9b3424be552277b675d8fed51ab6f8d9674931591bebed03e8`
  - Edge: `registry.digitalocean.com/dirizherpilotregistry/edge@sha256:ea5e542b1ae9638e67090656031b06a24c146d744b539db45b9c121dc0b754e9`
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

1. Prepare runtime mTLS, OIDC, database, registry-pull, and signing secrets
   outside git.
2. Render schema-v2 digest-only Kubernetes manifests with
   `public.exposure=internal`; Edge must remain `ClusterIP`.
3. Run all four server-side dry-runs against DOKS and retain their output.
4. Obtain explicit deployment approval, then apply prerequisites, migrations,
   runtime privilege checks, and workloads in the documented order.
5. Complete internal canaries before selecting the pilot DNS name or creating a
   public `LoadBalancer`.
6. Complete backup/restore verification, monitoring, and
   alerting before enabling ingress.
