# Private Resend alert delivery evidence - 31 August 2026

## Scope

This record covers only the pilot critical-alert route:

`Alertmanager -> private relay -> Resend HTTPS API -> olega.1107@gmail.com`.

The relay is private in namespace `monitoring`; it has no Ingress or
LoadBalancer. Its Cilium policy permits DNS only to cluster DNS and HTTPS only
to `api.resend.com`.

## Release and runtime evidence

| Check | Result | Evidence |
| --- | --- | --- |
| OCI build, scan, SBOM, signing and verification | `PASS` | GitHub Actions run `33425613905`, all release steps succeeded. |
| Immutable relay image | `PASS` | `registry.digitalocean.com/dirizherpilotregistry/node-build@sha256:ba7a156dd5fb76e311fbe7208d6331dbdcc9039c2ae0e5fd5e3eab4199ac179b`. |
| Kubernetes admission and rollout | `PASS` | Server-side dry-run accepted the runtime Secret and all six non-Secret objects; Deployment `dirizhor-alert-relay` reached `1/1 Ready`. |
| Private provider egress | `PASS` | An unauthenticated HTTPS preflight from the relay Pod reached Resend and returned `401`; this proves DNS, TLS and TCP/443 without sending an email. |
| Alertmanager route | `PASS` | `AlertmanagerConfig` routes only `severity=critical` alerts to the private webhook using a Secret-backed bearer credential. |
| Provider acceptance | `PASS` | Relay emitted `resend_accepted` for the controlled route after the egress policy fix. |
| Recipient delivery | `PASS` | The designated recipient confirmed receipt of `FIRING` and `RESOLVED` messages for `DirizhorResendDeliveryTest` and `DirizhorResendDeliveryTestR1`. |

## Controlled test

The initial synthetic critical alert could reach Alertmanager and the relay but
returned `provider_503` while the Cilium DNS rule did not populate the FQDN
cache. Commit `1aae466` added the DNS L7 rule without widening external
egress. A replacement synthetic critical alert was then accepted by Resend and
delivered to the configured recipient. Both alerts had an automatic expiry;
the observed `RESOLVED` messages demonstrate the resolved branch as well.

No production incident, application workload, public route, DNS record or
existing Secret was modified. The Resend API key and webhook token are absent
from this record and from Git.

## Gate result

`ALERT ROUTING AND DELIVERY: PASS`

This is evidence for the critical pilot route only. It does not claim that
every planned PostgreSQL, backup/restore, queue and audit signal already has a
live exporter and rule.
