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
- The restricted `dirizhor-pilot` namespace exists. No application pods, Jobs,
  PVCs, Services, ConfigMaps, NetworkPolicies, or PodDisruptionBudgets have been
  deployed. DigitalOcean automatically copied the registry pull Secret into
  the namespace; its value was not inspected.

## Kubernetes Structural Preflight

- On 2026-08-20 both DOKS workers were `Ready` on Kubernetes `v1.36.3`.
- A schema-v2 internal render used the retained OCI image digests, DOKS
  `do-block-storage-retain`, the current Cilium pod CIDRs, and the private
  PostgreSQL address. Its render digest was
  `sha256:fc7be0638ea6f40c3cf24b96dbd96066bb03630cbcb3bd226d8e2230273d0708`.
- DOKS server-side dry-run accepted 24 namespaced resources in the existing
  `default` namespace: prerequisites, migration, runtime privilege, and all
  three workloads. No resource was persisted.
- After explicit approval, the empty `dirizhor-pilot` namespace was created
  with restricted Pod Security labels. Exact server-side dry-run accepted all
  24 namespaced schema-v2 resources without persisting any of them.
- DOKS exposes `cilium.io/v2` and accepted both schema-v3 exact-FQDN
  `CiliumNetworkPolicy` resources in server-side dry-run. The schema-v3 test
  render digest was
  `sha256:7eee924d5bdda2d803fcc3815552f24fa9afae0fb9253f3f2c8b8d1df35fe5e1`;
  it used `.invalid` test FQDNs and is not deployment evidence.
- Schema v4 can render an external-only pilot without internal-provider route,
  Secret reference, TLS mount, token reference, or egress. This is only a
  deployment option; a concrete external model and provider data profile still
  require owner approval and live evidence.
- OIDC, internal provider, external provider names/models, runtime role, secret
  material, and PKI values remain unapproved.

## Reserved Public Identity

- The owner-controlled domain is `baza.fyi`; NIC.UA currently delegates it to
  the parking nameservers `parked1.uadns.com` and `parked2.uadns.com`.
- `pilot.baza.fyi` is reserved as the exact pilot `public.host`. It is not
  published to DigitalOcean yet and currently resolves through the registrar's
  parking configuration. The parking address is not deployment evidence and
  must never be copied into the Kubernetes target configuration.
- The ZITADEL Cloud instance `dirizhor-pilot` exists in the European Union Free
  region. Its verified exact issuer is
  `https://dirizhor-pilot-r5zsil.eu1.zitadel.cloud`.
- OIDC discovery is reachable at the issuer's standard
  `/.well-known/openid-configuration` endpoint. A Director project/client,
  client ID, callback registration, and client secret have not been created.
- The reserved Director callback is
  `https://pilot.baza.fyi/api/v1/auth/oidc/callback`; reserving this string does
  not authorize public DNS, a LoadBalancer, certificate issuance, or ingress.
- The exact non-secret ZITADEL application settings are frozen in the
  [OIDC/SSO operational runbook](oidc-operations-runbook.md#zitadel-pilot-registration-sheet).
  Project/application creation and secret generation still require explicit
  approval.

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

1. Reserve the exact pilot public host and register the matching confidential
   OIDC callback without publishing DNS. Prepare runtime mTLS, OIDC, database,
   registry-pull, and signing secrets outside git.
2. Approve exact OIDC discovery hosts and external AI API host, then render
   schema-v4 digest-only Kubernetes manifests with
   `public.exposure=internal`; Edge must remain `ClusterIP` and public provider
   egress must use exact Cilium FQDN rules.
3. Run all four server-side dry-runs against DOKS and retain their output.
4. Obtain explicit deployment approval, then apply prerequisites, migrations,
   runtime privilege checks, and workloads in the documented order.
5. Complete internal canaries before publishing the reserved pilot DNS name or
   creating a public `LoadBalancer`.
6. Complete backup/restore verification, monitoring, and
   alerting before enabling ingress.
