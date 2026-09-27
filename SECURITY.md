# Security

This cluster is a 4-node k3s homelab (Turing Pi 2, arm64) managed entirely from this repository by Argo CD. This document describes the security controls it runs, where each one lives in the repo, how to check it, and what is still open. It is a self-assessment, not an audit.

Last reviewed: **2026-09-27**. Mappings use the [CIS Kubernetes Benchmark v1.12](https://docs.k3s.io/security/self-assessment-1.12) (the version K3s documents for v1.32–v1.36) and [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).

## Layers

Each layer assumes the one above it can fail.

| Layer | What it stops | Where |
| --- | --- | --- |
| Git + Argo CD | Unreviewed or drifted config; manual changes are reverted (`selfHeal`) | `apps/`, `infrastructure/`, `workloads/` |
| CI supply chain | Vulnerable or unsigned images before they are published | [booking-engine `build-sign.yml`](https://github.com/monospaced-dev/booking-engine/blob/main/.github/workflows/build-sign.yml) |
| Admission: Pod Security Admission | Privileged / host-access pods, per namespace; built into the API server, always on | namespace labels |
| Admission: Kyverno | Fine-grained Pod Security (restricted, with documented exceptions); image signatures, digests and sources | `apps/kyverno-*.yaml`, `infrastructure/kyverno-*` |
| Network | Lateral movement and exfiltration: default-deny in every namespace, explicit allows | `*/networkpolicy.yaml` |
| Recovery | Data loss: replicated volumes, nightly off-cluster backups, tested restore | `apps/longhorn*.yaml`, `infrastructure/longhorn/` |

## Controls matrix

| # | Control | Implementation | Evidence | CIS 1.12 | NIST 800-53 r5 | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Pod Security floor in every namespace | PSA labels: `restricted` on app and platform namespaces; `baseline` enforce + `restricted` warn/audit on `kube-system`; privileged only where an exception below exists | `kubectl get ns -L pod-security.kubernetes.io/enforce` | 5.2.1 | CM-6, CM-7 | Met |
| 2 | Restricted Pod Security, enforced | Kyverno PSS policies (`kyverno-policies` chart, `podSecurityStandard: restricted`, `validationFailureAction: Enforce`) | `kubectl get validatingpolicies` → `[Deny]` | 5.2.2–5.2.12, 5.6.2, 5.6.3 | CM-6, CM-7, AC-6, SC-39 | Met |
| 3 | Deviations are explicit, justified and scoped | Kyverno `PolicyException`s, each with reason, compensating controls, scope and review date | [`infrastructure/kyverno-exceptions/`](infrastructure/kyverno-exceptions) | 5.2.x | CM-6 | Met (5 exceptions) |
| 4 | Policy engine fails safe | Pod Security policies `failurePolicy: Ignore` (a Kyverno outage degrades to PSA, never blocks the cluster); supply-chain policies `Fail` (opt-in namespaces fail closed) | `kubectl get validatingpolicies -o custom-columns=N:.metadata.name,F:.spec.failurePolicy` | — | SI-17 | Met |
| 5 | Workload hardening | Non-root numeric UIDs, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `allowPrivilegeEscalation: false`, seccomp `RuntimeDefault`, resource limits | e.g. [`workloads/booking-engine/app.yaml`](workloads/booking-engine/app.yaml) | 5.2.6, 5.2.7, 5.2.9, 5.6.2, 5.6.3 | CM-7, SC-39 | Met |
| 6 | No API credentials where none are needed | `automountServiceAccountToken: false` on app pods | same | 5.1.6 | AC-6 | Met for apps; charts use their defaults |
| 7 | Default-deny networking | `default-deny-all` (ingress + egress) plus explicit allows in every namespace except `kube-system` | `kubectl get networkpolicy -A` | 5.3.1, 5.3.2 | SC-7, SC-7(5), AC-4 | Met, except `kube-system` |
| 8 | Internet egress only where required | Only named components reach the internet, TCP 443 (plus 7844 for the tunnel), private ranges excluded: cloudflared, cert-manager controller, Alertmanager, Argo repo-server, Kyverno admission controller | per-namespace `networkpolicy.yaml` | 5.3.2 | SC-7(5), SC-7(10) | Met |
| 9 | No inbound ports on the home network | Public access only through an outbound Cloudflare Tunnel; admin UIs behind Cloudflare Access (email OTP) or port-forward | [`infrastructure/cloudflared/`](infrastructure/cloudflared) | — | SC-7, AC-17 | Met |
| 10 | TLS everywhere public | Let's Encrypt wildcard via cert-manager (DNS-01), Traefik default certificate | [`infrastructure/traefik/`](infrastructure/traefik) | — | SC-8, SC-12 | Met |
| 11 | Vulnerability scanning before release | Trivy gate in CI: fails on fixable HIGH/CRITICAL, before push | CI run logs | — | RA-5, SI-2 | Met for our images |
| 12 | Signed images, verified at admission | cosign keyless (GitHub OIDC → Fulcio → Rekor); Kyverno `ImageValidatingPolicy` admits `ghcr.io/monospaced-dev/*` only if signed by `build-sign.yml` on `main` | [`infrastructure/kyverno-image-verification/`](infrastructure/kyverno-image-verification); `cosign verify` (see booking-engine README) | 5.5.1 (via Kyverno instead of ImagePolicyWebhook) | SI-7, SI-7(15), CM-14, SR-4, SR-11 | Met in opted-in namespaces |
| 13 | Immutable, approved image references | Opted-in namespaces require `@sha256` digests and an approved source (`restrict-image-sources`) | same folder | 5.5.1 | CM-7(5), CM-2 | Met in opted-in namespaces |
| 14 | CI pipeline integrity | Third-party actions pinned to commit SHAs; least-privilege `GITHUB_TOKEN`; PRs build and scan but never push or sign | `build-sign.yml` | — | SA-10, SR-3, AC-6 | Met |
| 15 | Configuration as code | Every component is an Argo `Application` in Git; `selfHeal` reverts manual drift; chart versions pinned | [`apps/`](apps) | — | CM-2, CM-3, CM-8 | Met |
| 16 | Secrets never in Git in the clear | Sealed Secrets: only ciphertext is committed; controller key backed up off-cluster | `*-sealed.yaml` | 5.4.2 (partial) | SC-12, SC-28 | Met |
| 17 | Backups and tested restore | Longhorn: 2 replicas, snapshots every 2 days, nightly backups to a NAS (RAID 5); restore from backup and from `pg_dump` both exercised | [`infrastructure/longhorn/recurring-jobs.yaml`](infrastructure/longhorn/recurring-jobs.yaml) | — | CP-9, CP-10 | Met |
| 18 | Continuous monitoring | Prometheus + Alertmanager → Discord; Longhorn alert rules; Kyverno PolicyReports | [`infrastructure/monitoring/`](infrastructure/monitoring) | — | CA-7, SI-4 | Met |

## Documented exceptions

Full text, including compensating controls, is in [`infrastructure/kyverno-exceptions/`](infrastructure/kyverno-exceptions).

| Exception | Scope | Why |
| --- | --- | --- |
| `k3s-coredns`, `k3s-metrics-server` | Those two k3s-managed Deployments in `kube-system` | k3s re-applies their manifests on every restart; can't be changed through GitOps |
| `longhorn-storage-system` | Namespace `longhorn-system` (9 policies) | Block storage needs privileged containers, host paths and `SYS_ADMIN`; most pods are generated at runtime. Host namespaces, host ports and 5 other policies still apply |
| `metallb-speaker-l2` | MetalLB speaker DaemonSet | L2 mode answers ARP on the node's interface: host network and `NET_RAW` |
| `node-exporter-host-access` | node-exporter DaemonSet | Node metrics need host namespaces and read-only host paths |

Kyverno's chart excludes `kube-system` from its admission webhooks by design (so a Kyverno failure can't take down core components). That namespace is covered by Pod Security Admission `baseline` instead; the two k3s exceptions only affect Kyverno's background reports there.

## Known gaps

| Gap | Reference | Plan |
| --- | --- | --- |
| Secrets are not encrypted at rest in the k3s datastore (`--secrets-encryption` was not set at install) | CIS 1.2.27, 1.2.28; NIST SC-28 | Enable with `k3s secrets-encrypt`; verify with `k3s secrets-encrypt status` |
| API server audit logging not configured | CIS 1.2.16–1.2.19; NIST AU-2, AU-12 | Add an audit policy and log path to the k3s server config |
| booking-engine receives secrets as environment variables | CIS 5.4.1 | Mount as files once the app reads them from disk |
| No NetworkPolicies in `kube-system`; `hostNetwork` pods (node-exporter, MetalLB speaker) can't be governed by NetworkPolicy at all | CIS 5.3.2 | Accepted; documented |
| RBAC not reviewed beyond defaults; one cluster-admin kubeconfig on one workstation | CIS 5.1.1–5.1.13 | Review with the next phase |
| Signature, digest and source checks only apply in namespaces labelled `security.robotoh.io/verify-images: enforce` (today: `booking-engine`) | NIST CM-14 | Opt in each app namespace as it is deployed |
| Third-party images (charts, Postgres) are not signature-checked; Postgres digest bumps are manual | NIST SR-4 | Add a scheduled digest-update check |

## Verifying it yourself

```bash
# Pod Security level per namespace
kubectl get ns -L pod-security.kubernetes.io/enforce

# Kyverno: every policy enforcing, and how it fails
kubectl get validatingpolicies -o custom-columns=NAME:.metadata.name,ACTIONS:.spec.validationActions,FAILURE:.spec.failurePolicy
kubectl get imagevalidatingpolicies

# No failing results anywhere
kubectl get policyreports -A -o json | jq -r '[.items[].results[]?.result] | group_by(.) | map("\(.[0]): \(length)") | .[]'

# Default-deny present in every namespace
kubectl get networkpolicy -A | grep default-deny

# An image signature, independently of the cluster
cosign verify ghcr.io/monospaced-dev/booking-engine-nginx@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/monospaced-dev/booking-engine/\.github/workflows/build-sign\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Admission tests run on 2026-09-27, all with `kubectl … --dry-run=server` (nothing is created):

| Test | Namespace | Result |
| --- | --- | --- |
| Signed image by digest | booking-engine | Admitted |
| Unsigned image by digest | test namespace (opted in) | Denied: not signed by `build-sign.yml` on `main` |
| Own image by tag | booking-engine | Denied: must be pinned by digest |
| Image from an unapproved source | booking-engine | Denied: source not approved |
| Tagged image hidden in an init container | booking-engine | Denied |
| Pod sharing the host network | longhorn-system | Denied by Kyverno `disallow-host-namespaces` (PSA there only warns) |
| Privileged pod | kube-system | Denied by PSA `baseline` |

## Reporting a problem

This is a personal lab, but if you notice something wrong, please use GitHub's private vulnerability reporting on this repository rather than a public issue.
