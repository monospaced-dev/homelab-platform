# Security

This cluster is a 4-node k3s homelab (Turing Pi 2, arm64) managed entirely from this repository by Argo CD. This document describes the security controls it runs, where each one lives in the repo, how to check it, and what is still open. It is a self-assessment, not an audit.

Last reviewed: **2026-10-02**. Mappings use the [CIS Kubernetes Benchmark v1.12](https://docs.k3s.io/security/self-assessment-1.12) (the version K3s documents for v1.32–v1.36) and [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).

## Layers

Each layer assumes the one above it can fail.

| Layer | What it stops | Where |
| --- | --- | --- |
| Git + Argo CD | Unreviewed or drifted config; manual changes are reverted (`selfHeal`); `main` can't be force-pushed or deleted | `apps/`, `infrastructure/`, `workloads/`; node-level k3s settings in `bootstrap/k3s-server/` |
| CI supply chain | Vulnerable or unsigned images before they are published | [booking-engine `build-sign.yml`](https://github.com/monospaced-dev/booking-engine/blob/main/.github/workflows/build-sign.yml) |
| Admission: Pod Security Admission | Privileged / host-access pods, per namespace; built into the API server, always on | namespace labels |
| Admission: Kyverno | Fine-grained Pod Security (restricted, with documented exceptions); image signatures, digests and sources | `apps/kyverno-*.yaml`, `infrastructure/kyverno-*` |
| Network | Lateral movement and exfiltration: default-deny in every namespace, explicit allows | `*/networkpolicy.yaml` |
| Detection | Controls that silently stop working: admission outages, fail-open requests, denials, backups that don't run | `infrastructure/monitoring/` |
| Recovery | Data loss: replicated volumes, nightly off-cluster backups, tested restore | `apps/longhorn*.yaml`, `infrastructure/longhorn/` |

## Controls matrix

| # | Control | Implementation | Evidence | CIS 1.12 | NIST 800-53 r5 | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Pod Security floor in every namespace | PSA labels: `restricted` on app and platform namespaces; `baseline` enforce + `restricted` warn/audit on `kube-system`; privileged only where an exception below exists | `kubectl get ns -L pod-security.kubernetes.io/enforce` | 5.2.1 | CM-6, CM-7 | Met |
| 2 | Restricted Pod Security, enforced | Kyverno PSS policies (`kyverno-policies` chart, `podSecurityStandard: restricted`, `validationFailureAction: Enforce`) | `kubectl get validatingpolicies` → `[Deny]`; a privileged pod in a namespace where PSA only warns is denied by Kyverno itself | 5.2.2–5.2.12, 5.6.2, 5.6.3 | CM-6, CM-7, AC-6, SC-39 | Met |
| 3 | Deviations are explicit, justified and scoped | Kyverno `PolicyException`s, each with reason, compensating controls, scope and review date. Honored **at admission** (`features.policyExceptions.enabled: true`) and only from the `kyverno` namespace, so creating one requires admin write access there. Match conditions check `request.namespace` as well as `object.metadata.namespace` | [`infrastructure/kyverno-exceptions/`](infrastructure/kyverno-exceptions); server-side dry runs of the exempted workloads' real specs are admitted (see admission tests) | 5.2.x | CM-6, AC-6 | Met (5 exceptions; fixed 2026-10-02, see Incidents) |
| 4 | Policy engine fails safe, and failures are visible | Pod Security policies `failurePolicy: Ignore` (a Kyverno outage degrades to PSA, never blocks the cluster); supply-chain policies `Fail` (opt-in namespaces fail closed). Alerts: `KyvernoAdmissionDown` (no replicas for 5 min), `KyvernoWebhookFailOpen` (API server `apiserver_admission_webhook_fail_open_count` increases), `KyvernoDeniedRequests` (any denial in 15 min) | `kubectl get validatingpolicies -o custom-columns=N:.metadata.name,F:.spec.failurePolicy`; `kubectl get prometheusrule kyverno -n monitoring` | — | SI-17, SI-4 | Met |
| 5 | Workload hardening | Non-root numeric UIDs, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `allowPrivilegeEscalation: false`, seccomp `RuntimeDefault`, resource limits; `revisionHistoryLimit: 2` so stale, pre-fix templates don't linger | e.g. [`workloads/booking-engine/app.yaml`](workloads/booking-engine/app.yaml) | 5.2.6, 5.2.7, 5.2.9, 5.6.2, 5.6.3 | CM-7, SC-39 | Met |
| 6 | No API credentials where none are needed | `automountServiceAccountToken: false` on app pods | same | 5.1.6 | AC-6 | Met for apps; charts use their defaults |
| 7 | Default-deny networking | `default-deny-all` (ingress + egress) plus explicit allows in every namespace except `kube-system`; each namespace verified with must-work / must-be-blocked tests from inside the pod's network namespace (`kubectl debug`) | `kubectl get networkpolicy -A` | 5.3.1, 5.3.2 | SC-7, SC-7(5), AC-4 | Met, except `kube-system` |
| 8 | Internet egress only where required | Only named components reach the internet, TCP 443 (plus 7844 for the tunnel), private ranges excluded: cloudflared, cert-manager controller, Alertmanager, Argo repo-server, Kyverno admission controller. Longhorn: private ranges only, no internet | per-namespace `networkpolicy.yaml` | 5.3.2 | SC-7(5), SC-7(10) | Met |
| 9 | No inbound ports on the home network | Public access only through an outbound Cloudflare Tunnel; admin UIs behind Cloudflare Access (email OTP) or port-forward | [`infrastructure/cloudflared/`](infrastructure/cloudflared) | — | SC-7, AC-17 | Met |
| 10 | TLS everywhere public | Let's Encrypt wildcard via cert-manager (DNS-01), Traefik default certificate; the tunnel verifies the origin certificate (SNI match, no `noTLSVerify`) | [`infrastructure/traefik/`](infrastructure/traefik) | — | SC-8, SC-12 | Met |
| 11 | Vulnerability scanning before release; minimal runtime images | Trivy gate in CI (fresh DB): fails on fixable HIGH/CRITICAL, before push and signing. The fpm runtime image ships without the base image's build toolchain (`$PHPIZE_DEPS` — compilers, kernel headers) | CI run logs; `dpkg -l` in the image shows no `gcc`/`linux-libc-dev` | — | RA-5, SI-2, CM-7 | Met for our images |
| 12 | Signed images, verified at admission | cosign keyless (GitHub OIDC → Fulcio → Rekor); Kyverno `ImageValidatingPolicy` admits `ghcr.io/monospaced-dev/*` only if signed by `build-sign.yml` on `main` | [`infrastructure/kyverno-image-verification/`](infrastructure/kyverno-image-verification); `cosign verify` (see booking-engine README) | 5.5.1 (via Kyverno instead of ImagePolicyWebhook) | SI-7, SI-7(15), CM-14, SR-4, SR-11 | Met in opted-in namespaces |
| 13 | Immutable, approved image references | Opted-in namespaces require `@sha256` digests and an approved source (`restrict-image-sources`), for regular, init and ephemeral containers | same folder | 5.5.1 | CM-7(5), CM-2 | Met in opted-in namespaces |
| 14 | CI pipeline integrity | Third-party actions pinned to commit SHAs; least-privilege `GITHUB_TOKEN`; PRs build and scan but never push or sign | `build-sign.yml` | — | SA-10, SR-3, AC-6 | Met |
| 15 | Configuration as code | Every component is an Argo `Application` in Git; `selfHeal` reverts manual drift; chart versions pinned | [`apps/`](apps) | — | CM-2, CM-3, CM-8 | Met |
| 16 | Secrets never in Git in the clear | Sealed Secrets: only ciphertext is committed; controller key backed up off-cluster; the one-time plaintext export from the previous cluster was deleted after re-sealing | `*-sealed.yaml`; `grep -rnE "^kind: Secret[[:space:]]*$"` finds nothing | 5.4.2 (partial) | SC-12, SC-28 | Met |
| 17 | Backups and tested restore | Longhorn: 2 replicas, snapshots every 2 days, nightly backups to a NAS (RAID 5). Alert `LonghornBackupJobStale` if no daily backup has succeeded in 26 h | [`infrastructure/longhorn/recurring-jobs.yaml`](infrastructure/longhorn/recurring-jobs.yaml). Restore test 2026-10-02: fresh backup restored from the NAS into a separate volume, Postgres started on it, table count, migration count and an MD5 of every `api_keys` row matched production | — | CP-9, CP-10 | Met |
| 18 | Continuous monitoring | Prometheus + Alertmanager → Discord; Longhorn, Kyverno and backup-age alert rules; Kyverno PolicyReports | [`infrastructure/monitoring/`](infrastructure/monitoring) | — | CA-7, SI-4 | Met |
| 19 | Secrets encrypted at rest | k3s `secrets-encryption` (AES-CBC); key in `server/cred/encryption-config.json` on the node, backed up off-cluster, never in Git | `sudo k3s secrets-encrypt status` → Enabled, `reencrypt_finished`; raw `state.db` rows start with `k8s:enc:aescbc:v1:` | 1.2.27, 1.2.28 | SC-28, SC-28(1), SC-12 | Met (2026-09-27) |
| 20 | API audit log | Audit policy: every change logged with its request body, credential objects metadata-only, controller reads and health checks dropped; 30 days, 10 × 100 MB | [`bootstrap/k3s-server/`](bootstrap/k3s-server) | 1.2.16–1.2.19 | AU-2, AU-3, AU-9, AU-11, AU-12 | Met (2026-09-27) |
| 21 | Images stay patched | booking-engine rebuilds monthly with no layer cache (fresh base images, fresh Trivy DB); a monthly workflow opens one PR bumping every pinned digest; merging deploys through Argo + Kyverno | [`.github/workflows/image-digests.yml`](.github/workflows/image-digests.yml) | — | SI-2, RA-5, CM-3 | Met (2026-09-27) |
| 22 | Protected deployment branch | Ruleset on `main`: no deletion, no force-push, empty bypass list. Argo deploys `main`, and the signature policy trusts builds from `main`, so `main` history must not be rewritable | Repository → Settings → Rules; an amended `git push --force` was rejected (2026-10-02) | — | CM-3, CM-5, SI-7 | Met for this repo; booking-engine pending |
| 23 | Default credentials removed | Argo CD initial admin password rotated and `argocd-initial-admin-secret` deleted; Grafana admin from a sealed secret | `kubectl get secret argocd-initial-admin-secret -n argocd` → NotFound | — | IA-5 | Met (2026-10-02) |

## Documented exceptions

Full text, including compensating controls, is in [`infrastructure/kyverno-exceptions/`](infrastructure/kyverno-exceptions). Exceptions are honored at admission only from the `kyverno` namespace; exempted checks are reported as `skip`, so they stay visible in PolicyReports.

| Exception | Scope | Why |
| --- | --- | --- |
| `k3s-coredns`, `k3s-metrics-server` | Those two k3s-managed Deployments in `kube-system` | k3s re-applies their manifests on every restart; can't be changed through GitOps |
| `longhorn-storage-system` | Namespace `longhorn-system` (9 policies) | Block storage needs privileged containers, host paths and `SYS_ADMIN`; most pods (including recurring backup Jobs) are generated at runtime. Host namespaces, host ports and 6 other policies still apply. Accepted risk: any pod placed in this namespace inherits the 9 exemptions |
| `metallb-speaker-l2` | MetalLB speaker DaemonSet | L2 mode answers ARP on the node's interface: host network (so its ports are host ports) and `NET_RAW` |
| `node-exporter-host-access` | node-exporter DaemonSet | Node metrics need host namespaces and read-only host paths |

Kyverno's chart excludes `kube-system` from its admission webhooks by design (so a Kyverno failure can't take down core components). That namespace is covered by Pod Security Admission `baseline` instead; the two k3s exceptions only affect Kyverno's background reports there.

## Known gaps and accepted risks

| Gap | Reference | Plan |
| --- | --- | --- |
| booking-engine receives secrets as environment variables | CIS 5.4.1 | Mount as files once the app reads them from disk |
| No NetworkPolicies in `kube-system`; `hostNetwork` pods (node-exporter, MetalLB speaker) can't be governed by NetworkPolicy at all | CIS 5.3.2 | Accepted; documented |
| RBAC not reviewed beyond defaults; one cluster-admin kubeconfig on one workstation | CIS 5.1.1–5.1.13 | Review with the next phase |
| Signature, digest and source checks only apply in namespaces labelled `security.robotoh.io/verify-images: enforce` (today: `booking-engine`) | NIST CM-14 | Opt in each app namespace as it is deployed |
| Third-party images (charts, Postgres) are not signature-checked | NIST SR-4 | Accepted for now; they are digest-pinned (Postgres) or version-pinned (charts) |
| Pod Security policies fail open while Kyverno is unavailable | NIST SI-17 | Accepted: PSA enforces the same rules in restricted namespaces; outages and every fail-open request alert (#4) |
| Admission webhook ports accept traffic from any source | CIS 5.3.2 | Accepted: the API server calls from the host network and its source IP varies by node under flannel; the ports speak only TLS verified by the API server; other ports on those pods are denied |
| Longhorn egress allows any private address and port | NIST SC-7(5) | Accepted: storage data paths (replicas, iSCSI, NFS) aren't mapped port by port because a mistake costs data availability; internet egress is blocked |
| Fixable-only vulnerability gate: CVEs without a fix don't fail the build | NIST RA-5 | Accepted: they become blocking as soon as a fix exists; monthly no-cache rebuilds (#21) pick fixes up |

## Incidents

### 2026-09-27 → 2026-10-02: backups blocked by enforcement

**What happened.** After Kyverno moved from Audit to Enforce, every Longhorn backup and snapshot Job was denied at admission. No backups ran for five days, and the booking-engine database volume, created after enforcement, had never been backed up. Nothing alerted.

**How it was found.** A restore test while updating this document: the newest backups were five days old and the booking-engine volume was missing. CronJob events showed `FailedCreate` with Kyverno denials every ~15 minutes — on policies the `longhorn-storage-system` exception lists.

**Root cause.** Kyverno's `PolicyException` feature is **disabled by default at admission**. Background scans applied the exceptions anyway, so PolicyReports showed `skip` and the pre-Enforce check (0 failures) passed. A dry-run warning ("PolicyException resources would not be processed until it is enabled") had been seen earlier and misread as referring to a legacy mechanism. Every exempted workload was one pod recreation away from being denied; the daily Longhorn Jobs were simply the first.

| Check | Why it passed |
| --- | --- |
| PolicyReports (pre-flight for Enforce) | Background scans honor exceptions; admission did not |
| Running workloads | Pods admitted before Enforce kept running |
| Longhorn backup-failure alert | Fires only when a backup runs and errors; a Job that is never admitted produces no error |
| Admission tests (2026-09-27) | Tested denials, not that exempted workloads were still admitted |

**Fix.** `features.policyExceptions.enabled: true`, `namespace: kyverno`; match conditions also check `request.namespace`. Verified with server-side dry runs of the exact rejected Job and of the node-exporter DaemonSet, then by the CronJob's own next run and a restore test.

**New detection.** `LonghornBackupJobStale` (outcome: no successful backup in 26 h) and `KyvernoDeniedRequests` (any Kyverno denial). Either would have fired on the first day.

**Lessons.** Verify enforcement on the path that enforces (admission), not only on reports that describe it — and test that exempted workloads are still *admitted*, not just that violations are denied. Alert on outcomes, not on one failure mode. Restore tests find problems that health checks don't.

## Verifying it yourself

```bash
# Pod Security level per namespace
kubectl get ns -L pod-security.kubernetes.io/enforce

# Kyverno: every policy enforcing, and how it fails
kubectl get validatingpolicies -o custom-columns=NAME:.metadata.name,ACTIONS:.spec.validationActions,FAILURE:.spec.failurePolicy
kubectl get imagevalidatingpolicies

# No failing results anywhere
kubectl get policyreports -A -o json | jq -r '[.items[].results[]?.result] | group_by(.) | map("\(.[0]): \(length)") | .[]'

# Exceptions are honored at admission (expect "created (server dry run)")
kubectl get cronjob daily-backup -n longhorn-system -o json \
  | jq '{apiVersion: "batch/v1", kind: "Job", metadata: {name: "dryrun-backup-test"}, spec: .spec.jobTemplate.spec}' \
  | kubectl create -n longhorn-system --dry-run=server -f -

# Backups are recent (expect a timestamp within the last ~24 h)
kubectl get cronjob daily-backup -n longhorn-system -o jsonpath='{.status.lastSuccessfulTime}{"\n"}'

# Default-deny present in every namespace
kubectl get networkpolicy -A | grep default-deny

# An image signature, independently of the cluster
cosign verify ghcr.io/monospaced-dev/booking-engine-nginx@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/monospaced-dev/booking-engine/\.github/workflows/build-sign\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Admission tests, all with `kubectl … --dry-run=server` (nothing is created):

| Date | Test | Namespace | Result |
| --- | --- | --- | --- |
| 2026-09-27 | Signed image by digest | booking-engine | Admitted |
| 2026-09-27 | Unsigned image by digest | test namespace (opted in) | Denied: not signed by `build-sign.yml` on `main` |
| 2026-09-27 | Own image by tag | booking-engine | Denied: must be pinned by digest |
| 2026-09-27 | Image from an unapproved source | booking-engine | Denied: source not approved |
| 2026-09-27 | Tagged image hidden in an init container | booking-engine | Denied |
| 2026-09-27 | Pod sharing the host network | longhorn-system | Denied by Kyverno `disallow-host-namespaces` (PSA there only warns) |
| 2026-09-27 | Privileged pod | kube-system | Denied by PSA `baseline` |
| 2026-10-02 | Privileged pod | monitoring | Denied by Kyverno (four PSS policies); PSA only warns |
| 2026-10-02 | Longhorn backup Job, as the CronJob controller sends it | longhorn-system | Admitted (exception honored) |
| 2026-10-02 | node-exporter DaemonSet | monitoring | Admitted (exception honored) |

## Reporting a problem

This is a personal lab, but if you notice something wrong, please use GitHub's private vulnerability reporting on this repository rather than a public issue.
