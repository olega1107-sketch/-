# Private Alertmanager to Resend relay

Status: prepared only. This runbook does not authorize a deployment, a DNS
change, creation of an API key, or a test email.

## Boundary

`Alertmanager -> ClusterIP relay -> api.resend.com:443` is the only route.
The relay has no Ingress, no LoadBalancer and no public listener. Cilium limits
egress to cluster DNS and `api.resend.com:443`; Alertmanager is the only allowed
in-cluster caller. The relay does not mount a Kubernetes service-account token.

The relay accepts only critical Alertmanager payloads, sends a compact
non-sensitive summary, uses a 8 second timeout and bounded retries only for
network, 429 and 5xx outcomes. It sends a deterministic Resend idempotency key
to prevent duplicate alert emails for 24 hours. It never logs request bodies,
API keys, webhook tokens or provider error bodies.

## Preconditions before application

1. In Resend, verify the exact sending subdomain, preferably `alerts.baza.fyi`.
   Copy the provider-generated SPF, MX and DKIM records from its dashboard;
   their values are account-specific and must not be guessed or changed by this
   runbook.
2. Wait until Resend reports the domain as verified. The `from` value must use
   that exact verified domain.
3. Create a Resend API key scoped to email sending and a random webhook token.
   Store their local source files outside Git with mode `0600`; do not put their
   contents in a manifest, terminal transcript or evidence artifact.
4. Create `dirizhor-alert-relay-runtime` in `monitoring` from those two files,
   with keys `resend-api-key` and `webhook-token`.
5. Replace only the example OCI image digest with a signed image digest produced
   by the controlled OCI release; retain the digest pin.

## Controlled rollout

1. Render the configuration with `scripts/alert-relay-render.mjs` to a new,
   mode-0700 local directory.
2. Run server-side dry-run on all rendered resources.
3. Apply relay Service, Deployment and policies first; wait for readiness.
4. Apply `AlertmanagerConfig` only after the relay is ready and Resend is
   verified. `alerts@alerts.baza.fyi` is the prepared sender value.
5. Fire one namespaced synthetic critical alert. Evidence must show all four
   states without secret values: Alertmanager fired, relay accepted, provider
   accepted and recipient delivered.
6. Remove or let expire the synthetic alert. A failed delivery leaves the
   alerting gate `BLOCKED`; do not fall back to SMTP or open mail ports.

## Current operational status

The existing Prometheus rules cover target availability, readiness over 120
seconds, HTTP 5xx rate over 1 percent for five minutes, p95 over 1500 ms, and
OIDC callback 5xx. The relay route remains intentionally unapplied until the
Resend domain is verified and a dedicated key exists.
