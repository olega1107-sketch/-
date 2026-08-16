# Dirizher Pilot Infrastructure

This folder defines the DigitalOcean pilot environment as Terraform code.

It is intentionally safe by default:

- no secrets are stored in the repository;
- local Terraform state and variable files are ignored by git;
- destructive resource deletion is blocked with `prevent_destroy`;
- `terraform apply` must be run manually after reviewing a plan.

## Prerequisites

Install:

- Terraform
- doctl
- kubectl

Provide the DigitalOcean token locally, without committing it:

```bash
export DIGITALOCEAN_TOKEN="dop_v1_..."
```

If Codex does not see your shell environment, store it in the ignored local file instead:

```bash
cd infra/terraform
read -s DIGITALOCEAN_TOKEN
printf 'DIGITALOCEAN_TOKEN=%s\n' "$DIGITALOCEAN_TOKEN" > environments/pilot/.env.local
chmod 600 environments/pilot/.env.local
```

Then create a local variable file from the example:

```bash
cp infra/terraform/environments/pilot/terraform.tfvars.example infra/terraform/environments/pilot/terraform.tfvars
```

Edit `terraform.tfvars` locally for the real project name, domain, and sizing.

## Safe Workflow

From `infra/terraform`:

```bash
terraform init
terraform validate
terraform plan -var-file=environments/pilot/terraform.tfvars
```

Do not run this until the plan has been reviewed and explicitly approved:

```bash
terraform apply -var-file=environments/pilot/terraform.tfvars
```

## kubectl and doctl

After the DOKS cluster exists:

```bash
doctl auth init --context dirizher-pilot
doctl auth switch --context dirizher-pilot
doctl kubernetes cluster kubeconfig save dirizher-pilot
kubectl get nodes
```

## Next Stages for 6/6 Pilot Readiness

1. Delivery: run the protected manual OCI workflow and retain its evidence.
2. Secrets: move runtime secrets into a managed secret source, then sync to Kubernetes with External Secrets Operator or sealed secrets.
3. Internal deployment: render and deploy only pinned OCI digest references, then complete internal canaries.
4. OIDC: configure the application identity provider and Kubernetes/service identities.
5. DNS and TLS: only after internal checks, create DNS records, install ingress-nginx and cert-manager, and issue Let's Encrypt certificates.
6. Monitoring and backups: add alerts and dashboards, verify PITR, test restore, and back up manifests and protected Terraform state.
