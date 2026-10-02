# Security — homelab-platform

This document describes the security controls on a 4-node k3s cluster (Turing Pi 2, Rockchip RK1, arm64) managed entirely through GitOps from this repository. Every control below is defined in Git, applied by Argo CD, and has a repeatable way to verify it.

It is written the way a control set would be documented in a regulated environment: each control states what it does, how it is implemented, how to prove it works, and which framework requirement it maps to. Exceptions and accepted risks are recorded explicitly rather than hidden.

> Framework mappings are indicative (to show intent and coverage). This is a homelab, not a certified environment.

---

## 1. Scope

| In scope | Out of scope |
| --- | --- |
| k3s cluster workloads and namespaces | Home network devices beyond the cluster VLAN |
| Admission control (Pod Security Admission, Kyverno) | Physical security of the hardware |
| In-cluster network segmentation (NetworkPolicy) | Cloudflare account security (managed separately, MFA-protected) |
| Secrets management, TLS, supply chain for first-party images | k3s-managed system components in `kube-system` (see §5) |
| Backups, monitoring and alerting | |

## 2. Threat model (summary)

| Threat | Primary controls |
| --- | --- |
| A compromised or malicious workload escalates to the node | Pod Security Standards (C-01, C-02), exceptions register (§5) |
| Lateral movement after a pod is compromised | Default-deny NetworkPolicies (C-04, C-05) |
| Data exfiltration to the internet | Egress allow-lists per namespace; storage namespace blocked from the internet (C-05) |
| Tampered or vulnerable container images | Trivy gate, cosign signing, signature + digest enforcement at admission (C-08–C-10) |
| Secrets leaked through Git | Sealed Secrets, secret scanning (C-06, C-07) |
| Exposure of internal services | No inbound ports; Cloudflare Tunnel + Access (C-11, C-12) |
| Silent control failure (e.g. admission webhook down) | Fail-open is measured and alerted (C-03) |
| Data loss | Replicated storage, off-cluster backups, alerting on backup failure (C-14, C-15) |

## 3. Architecture at a glance

- **GitOps:** Argo CD app-of-apps (`bootstrap/root-app.yaml` → `apps/`). Argo CD is the only component installed by hand; everything else is a commit. `selfHeal` reverts manual drift.
- **Ingress:** Cloudflare Tunnel (`cloudflared`, 2 replicas, outbound-only) → Traefik → apps. MetalLB provides a LAN IP for Traefik. No ports are opened on the home router.
- **TLS:** cert-manager issues a Let's Encrypt wildcard certificate via DNS-01 (scoped Cloudflare API token), used as Traefik's default certificate. The tunnel verifies the origin certificate (no `noTLSVerify`).
- **Storage:** Longhorn, 2 replicas on NVMe nodes, nightly backups to an NFS target on a separate NAS.

## 4. Controls matrix

| ID | Control | Implementation | Evidence / how to verify | Mapping |
| --- | --- | --- | --- | --- |
| **C-01** | Pods must meet the Kubernetes **restricted** Pod Security Standard | Kyverno `kyverno-policies` chart, `podSecurityStandard: restricted`, `validationFailureAction: Enforce` (17 `ValidatingPolicy` objects). Documented exceptions are honored **at admission** (`features.policyExceptions.enabled: true`) and only from the `kyverno` namespace | A privileged test pod in a namespace where PSA allows it is **denied by Kyverno** (`kubectl run … --dry-run=server` → `admission webhook "vpol.validate.kyverno…" denied`). Cluster-wide PolicyReports: 0 failures | CIS K8s 5.2.x · NIST 800-53 AC-6, CM-7 · SOC 2 CC6.1, CC6.8 |
| **C-02** | Built-in admission backstop independent of Kyverno | Pod Security Admission labels on every namespace (`enforce: restricted` where possible; `enforce: privileged` + `warn/audit: restricted` where documented) set via Argo `managedNamespaceMetadata` | `kubectl get ns -L pod-security.kubernetes.io/enforce`; a privileged pod in a restricted namespace is rejected with `violates PodSecurity "restricted:latest"` | CIS K8s 5.2.1 · NIST AC-6 |
| **C-03** | Admission-control outages are detected; fail-open is measured | Kyverno PSS policies use `failurePolicy: Ignore` (see D-01). Alerts: `KyvernoAdmissionDown` (no available replicas for 5 min, critical), `KyvernoWebhookFailOpen` (API server `apiserver_admission_webhook_fail_open_count` increases, warning) and `KyvernoDeniedRequests` (any Kyverno rejection in 15 min, warning — surfaces unexpected denials of platform components) → Alertmanager → Discord | `kubectl get prometheusrule kyverno -n monitoring`; rules `health=ok` in the Prometheus rules API | NIST SI-4, AU-6 · SOC 2 CC7.2 |
| **C-04** | Network segmentation: default-deny in every namespace | `default-deny-all` (Ingress + Egress) in every namespace except `kube-system`, plus explicit allows: `allow-dns` (CoreDNS only, UDP+TCP 53), `allow-kube-api` (API server only), and per-workload rules using named ports | `kubectl get networkpolicy -A`. Per-namespace must-work / must-be-blocked tests run with `kubectl debug` inside the pod's network namespace (e.g. Traefik dashboard port blocked from other namespaces; Grafana profiling port blocked; NAS unreachable from the tunnel connector) | CIS K8s 5.3.2 · NIST SC-7, AC-4 · SOC 2 CC6.6 |
| **C-05** | Egress restricted to what each workload needs | Internet egress only where required, only on 443 (and 7844 for the tunnel), always excluding RFC 1918 ranges: cloudflared, cert-manager controller, Argo CD repo-server, Alertmanager (Discord). Longhorn: egress limited to private ranges (no internet) | From inside a Longhorn pod: `https://1.1.1.1` blocked, Longhorn manager API reachable | NIST SC-7(5) · SOC 2 CC6.6 |
| **C-06** | No plaintext secrets in Git | Sealed Secrets (`kubeseal`); every credential (Cloudflare tokens, Grafana admin, Discord webhook) committed only as a `SealedSecret` bound to its name and namespace. Values entered with `read -s` and length/prefix-checked before sealing | `grep -rnE "^kind: Secret[[:space:]]*$" apps infrastructure bootstrap` finds nothing; 4 `SealedSecret` manifests. Controller key backed up off-cluster; the one-time plaintext export of the old cluster's secrets was deleted after re-sealing | CIS K8s 5.4.1 · NIST IA-5, SC-12 · SOC 2 CC6.1 |
| **C-07** | Secret scanning before code is published | Every repository scanned with `gitleaks` across full history before being pushed/published; reviewed false positives recorded by fingerprint in `.gitleaksignore`; real findings rotated and scrubbed with `git filter-repo` | Migration log; `gitleaks git .` → `no leaks found` | NIST SA-11, IA-5 · SOC 2 CC8.1 |
| **C-08** | Vulnerable images don't ship | `build-sign.yml` builds the arm64 image, scans it with Trivy (fresh vulnerability database) **before** signing, and fails the build (`exit-code: 1`) on any **CRITICAL or HIGH** finding that has a fix available (`ignore-unfixed: true`). An image that fails the scan is never signed, so C-09 keeps it out of the cluster. CI actions are pinned to full commit SHAs, not tags (tags are mutable — trivy-action's tags were force-pushed with malicious code in a past supply-chain incident) | CI run history; workflow file | NIST RA-5, SI-2, SR-11 · SOC 2 CC7.1 |
| **C-09** | Image provenance: only signed first-party images run | Images signed with cosign **keyless** in GitHub Actions. Kyverno `ImageValidatingPolicy verify-monospaced-images` (`Deny`, `failurePolicy: Fail`) applies to every image matching `ghcr.io/monospaced-dev/*` in namespaces labeled `security.robotoh.io/verify-images: enforce`, and requires a signature whose certificate was issued by GitHub's OIDC provider (`token.actions.githubusercontent.com`) to the `build-sign.yml` workflow **on the `main` branch** of a `monospaced-dev` repository, checked against the Rekor transparency log. Images built from other branches, other workflows or other accounts are rejected. Policies live in `infrastructure/kyverno-image-verification/` | Tested: signed image admitted; unsigned, tag-only and third-party images denied | NIST SI-7, SR-4 · SOC 2 CC8.1 |
| **C-10** | Approved image sources, immutable references | `ValidatingPolicy restrict-image-sources` (`Deny`, `failurePolicy: Fail`) in the same labeled namespaces: every container, init container and ephemeral container image must come from an allow-list (`ghcr.io/monospaced-dev/`, official `postgres`) **and** be pinned by digest (`image@sha256:…`). Deployments keep `revisionHistoryLimit: 2` so stale templates don't linger | PolicyReports show 0 failures in `booking-engine` | NIST CM-2, CM-7(5), SI-7 |
| **C-11** | No inbound exposure of the home network | All public access through Cloudflare Tunnel (outbound-only, 2 connectors); no router port forwards. Tunnel token stored as a SealedSecret | Router has no port forwards; `530` from Cloudflare when connectors are down | NIST SC-7 · SOC 2 CC6.6 |
| **C-12** | Authentication in front of admin UIs | Cloudflare Access (one-time PIN, `Owner only` policy) in front of browser-only admin apps (Grafana), in addition to the app's own login | `curl -sI https://grafana.robotoh.io` → `302` to `cloudflareaccess.com` | NIST AC-3, IA-2 · SOC 2 CC6.1 |
| **C-13** | Encryption in transit, verified end to end | Let's Encrypt wildcard certificate (cert-manager, auto-renewed); tunnel routes use HTTPS to Traefik with SNI matching (certificate is verified, not skipped) | `openssl s_client -connect <traefik-ip>:443 -servername x.robotoh.io` → issuer Let's Encrypt | NIST SC-8, SC-13 |
| **C-14** | Resilient storage | Longhorn, 2 replicas across 2 NVMe nodes; replica count matches available disk nodes (no permanently degraded volumes) | `kubectl get volumes.longhorn.io -n longhorn-system` → `healthy` | NIST CP-2, SC-5 · SOC 2 A1.2 |
| **C-15** | Off-cluster backups, monitored | Recurring jobs on the `default` group (every volume covered from creation): daily backup to NAS (7 kept), snapshots every 2 days (4 kept). Alerts: `LonghornBackupJobStale` (no successful daily backup in 26 h — catches backups that never start), `LonghornBackupFailed`, `LonghornVolumeDegraded`, `LonghornVolumeFaulted`, `LonghornNodeStorageLow` | Restore test on the current cluster, 2026-10-02: a fresh backup of the booking-engine database was restored from the NAS into a separate volume, Postgres started on it, and schema (table count), migration count and an MD5 of every `api_keys` row matched production. `kubectl get backuptarget -n longhorn-system` → `AVAILABLE true` | NIST CP-9, CP-10 · SOC 2 A1.2 |
| **C-16** | Change management | All changes are Git commits applied by Argo CD; drift is reverted (`selfHeal`); one manual bootstrap step (Argo CD) and a small set of documented manual labels | `git log`; Argo CD sync history | NIST CM-3, CM-5 · SOC 2 CC8.1 |
| **C-17** | Monitoring and alerting | kube-prometheus-stack scrapes nodes, kubelets, the API server and platform components; Alertmanager routes to Discord with grouping, inhibition and resolved notifications | Test alert via `amtool` delivered and resolved | NIST SI-4, IR-5 · SOC 2 CC7.2 |
| **C-18** | Least functionality | Unused privileged components removed rather than excepted (MetalLB's FRR/BGP backend disabled in L2 mode); unused legacy Kyverno exception mechanism left disabled | `kubectl get pods -n metallb-system` shows no FRR pods | NIST CM-7 |
| **C-19** | Default credentials rotated | Argo CD initial admin password changed and bootstrap secret removed; Grafana admin from a sealed secret | `argocd-initial-admin-secret` absent | NIST IA-5 · CIS K8s 5.1 |

## 5. Exceptions register

Exceptions are `PolicyException` objects in `infrastructure/kyverno-exceptions/`. Each is scoped by CEL match conditions and carries its own reason, compensating controls, scope and review date. Exempted checks are reported as `skip`, so they remain visible in PolicyReports.

Exceptions are honored at admission only because `features.policyExceptions.enabled` is set (off by default), and only from the `kyverno` namespace — so creating an exception requires write access to that namespace. Match conditions check both `object.metadata.namespace` and `request.namespace`, so they match objects created by controllers as well as by kubectl.

| Exception | Scope | Exempt from | Reason | Compensating controls |
| --- | --- | --- | --- | --- |
| `node-exporter-host-access` | `monitoring`, label `app.kubernetes.io/name: prometheus-node-exporter` | host namespaces, host path, host ports, volume types | Reads node-level metrics | Read-only mounts; non-root (65534); no privilege escalation; seccomp; all capabilities dropped |
| `k3s-coredns` | `kube-system`, `k8s-app: kube-dns` | capabilities-strict, run-as-nonroot, seccomp-strict | k3s-managed; manifest re-applied by k3s on restart | Namespace writable by cluster admins only; tracked with k3s upgrades |
| `k3s-metrics-server` | `kube-system`, `k8s-app: metrics-server` | seccomp-strict | Same | Same |
| `metallb-speaker-l2` | `metallb-system`, component `speaker` | host namespaces, host ports, capabilities (×2), run-as-nonroot | L2 ARP announcement needs `hostNetwork` + `NET_RAW` | Seccomp applied; FRR removed |
| `longhorn-storage-system` | whole `longhorn-system` namespace | 9 policies (privileged, host path, capabilities, etc.) | Block storage needs privileged host access; most components are generated at runtime with hashed names | Namespace writable by admins/Argo only; chart NetworkPolicies + default-deny; no internet egress; 8 other policies still enforced. **Accepted risk:** any pod placed in this namespace inherits the exemptions |

`kube-system` is not labeled for Pod Security Admission and has no default-deny NetworkPolicy: it is managed by k3s.

## 6. Accepted risks and known gaps

| ID | Risk / gap | Why accepted | Mitigation |
| --- | --- | --- | --- |
| R-01 | Kyverno PSS policies fail open (`failurePolicy: Ignore`) | Single-replica admission controller; `Fail` would turn a Kyverno restart into a cluster-wide deployment outage | PSA (C-02) enforces the same standard in restricted namespaces regardless; outages and every fail-open request are alerted (C-03); background scan reports anything admitted unchecked |
| R-02 | `hostNetwork` pods (node-exporter, MetalLB speakers) are outside NetworkPolicy | Kubernetes NetworkPolicy does not apply to host-network pods | Narrow Kyverno exceptions; read-only (node-exporter); minimal function (speakers) |
| R-03 | Admission webhook ports accept traffic from any source | The API server calls webhooks from the host network; with flannel its source IP varies by node and cannot be pinned reliably | Webhook ports speak only TLS verified by the API server; all other ports on those pods are denied |
| R-04 | Longhorn egress allows any private address/port | Storage data paths (replicas, iSCSI, NFS) are complex; a mapping error costs data availability | Internet egress is blocked (the exfiltration path); ingress governed by chart policies + default-deny |
| R-05 | Monitoring namespace is a trust boundary (pods talk freely inside it) | Tightly coupled stack; pod-level rules would be fragile across chart upgrades | All cross-namespace flows explicit; Grafana not reachable except from Traefik; profiling port blocked |
| R-06 | CRITICAL/HIGH vulnerabilities **without an available fix** don't fail the build (`ignore-unfixed`) | Blocking on unfixable CVEs would block every release with no remediation possible | Re-scanned on every build with a fresh database, so a fix becomes blocking as soon as it exists. Gap: deployed images are not re-scanned on a schedule between builds. Runtime controls (restricted PSS, default-deny networking) limit exploitability |

## 7. Decision log

| ID | Date | Decision | Rationale |
| --- | --- | --- | --- |
| D-01 | 2026-09-27 | PSS policies: `failurePolicy: Ignore`; image-signature and image-source policies: `Fail` | Availability vs. strictness: PSA backstops the PSS rules, so fail-open costs little; nothing backstops image provenance, so those policies fail closed (and only apply to namespaces that opt in with the `verify-images` label) |
| D-02 | 2026-09-27 | Kyverno `Audit` → `Enforce` | Pre-flight showed 0 failures across all PolicyReports; exceptions in place |
| D-03 | 2026-09-26 | Default-deny networking rolled out one namespace per commit, each with must-work / must-be-blocked tests | Limits blast radius; every allow rule is evidenced |
| D-04 | 2026-09-26 | Disable MetalLB FRR rather than except it | Removing an unused privileged component beats documenting an exception for it |
| D-05 | 2026-09-25 | Git source of truth moved to GitHub; self-hosted Git removed from the cluster | Removes a circular dependency (cluster built from Git hosted inside itself) and simplifies rebuilds |
| D-06 | 2026-10-02 | Enable PolicyExceptions at admission, restricted to the `kyverno` namespace | Exceptions were only applied by background scans; restricting their namespace keeps exception creation an admin-only action |

## 8. Incident: backups blocked by enforcement (2026-09-27 → 2026-10-02)

**What happened.** After Kyverno moved from Audit to Enforce, every Longhorn backup and snapshot Job was denied at admission. No backups ran for five days, and the booking-engine database volume — created after enforcement — had never been backed up. Nothing alerted.

**How it was found.** A restore test for this document: the Longhorn backup list showed the newest backups were five days old and the booking-engine volume was absent. CronJob events showed `FailedCreate` with Kyverno denials every ~15 minutes.

**Root cause.** The Kyverno `PolicyException` feature is **disabled by default at admission**. Background scans applied the exceptions anyway, so PolicyReports showed `skip` and the pre-Enforce pre-flight passed. A warning about this ("PolicyException resources would not be processed until it is enabled") had been seen earlier and misread as referring only to a legacy mechanism. Every exempted workload was therefore one pod recreation away from being denied; Longhorn's daily Jobs were simply the first.

**Why every check missed it.**

| Check | Why it passed |
| --- | --- |
| PolicyReports (pre-flight for Enforce) | Background scans honor exceptions; admission did not |
| Running workloads | Pods admitted before Enforce kept running |
| `LonghornBackupFailed` alert | Only fires when a backup runs and errors — a backup that never starts produces no error |

**Fix.** `features.policyExceptions.enabled: true` with `namespace: kyverno` (D-06); match conditions also check `request.namespace`. Verified with server-side dry runs of the exact rejected Job and of the node-exporter DaemonSet, then a real backup.

**New detection.** `LonghornBackupJobStale` (time since last successful backup > 26 h) and `KyvernoDeniedRequests` (any Kyverno denial). Either would have fired on the first day.

**Lessons.** Verify enforcement on the path that enforces (admission), not only on the reports that describe it. Alert on the outcome you care about (a recent successful backup), not on one failure mode. Restore tests find problems that health checks don't.

## 9. Verifying the controls

```bash
# Policy results across the cluster (expect 0 failures)
kubectl get policyreport -A -o json | jq '[.items[].summary.fail // 0] | add'

# Pod Security Admission levels
kubectl get ns -L pod-security.kubernetes.io/enforce,pod-security.kubernetes.io/warn

# Kyverno enforces independently of PSA (expect a Kyverno denial)
kubectl run kyverno-enforce-test -n monitoring --image=busybox:1.36 --dry-run=server \
  --overrides='{"spec":{"containers":[{"name":"t","image":"busybox:1.36","securityContext":{"privileged":true}}]}}'

# Network policies present
kubectl get networkpolicy -A

# Exceptions in force
kubectl get policyexceptions.policies.kyverno.io -n kyverno

# Exceptions are honored at admission (expect "created (server dry run)")
kubectl get cronjob daily-backup -n longhorn-system -o json \
  | jq '{apiVersion: "batch/v1", kind: "Job", metadata: {name: "dryrun-backup-test"}, spec: .spec.jobTemplate.spec}' \
  | kubectl create -n longhorn-system --dry-run=server -f -

# Backups are recent (expect a timestamp within the last ~24 h)
kubectl get cronjob daily-backup -n longhorn-system -o jsonpath='{.status.lastSuccessfulTime}{"\n"}'
```

## 10. Review

Exceptions carry a `reviewed` date and are re-reviewed when the related chart is upgraded or at least every six months. The sealed-secrets controller key is re-exported after key rotation (every 30 days by default).
