# Driftify Extended Findings — Design Spec

**Date:** 2026-07-01
**Status:** Approved (R4 — EL8 target mapping + networking-as-inventory)
**Scope:** driftify additions + companion inspectah enhancements
**Implementation:** One spec, two plans (driftify plan + inspectah plan)

---

## 1. Goals

Make driftify-generated systems look like enterprise RHEL, not dev boxes with extra packages. Plant drift that exercises inspectah's ability to advise on image-mode migration feasibility — not just detect what's on the system, but flag what matters for the package→image transition.

Add a new **advisory** finding type to inspectah that provides migration guidance without producing Containerfile output. Introduce **section grouping** in the HTML report, refine view, TUI, and audit report to organize increased finding density.

## 2. Scope

### Approved — 8 driftify additions

| # | Item | Sections affected | Profile tiers |
|---|------|-------------------|---------------|
| 1 | Auth & identity infrastructure | users, config | standard, kitchen-sink |
| 2 | tmpfiles.d + /var state gaps | config, storage | standard |
| 3 | Files in /usr | nonrpm/unmanaged | standard, kitchen-sink |
| 4 | Performance tuning depth | kernel | standard, kitchen-sink |
| 5 | Logging & monitoring | config, services | standard, kitchen-sink |
| 6 | Cross-tree symlinks | config | standard, kitchen-sink |
| 7 | systemd unit shadows | services | standard |
| 8 | Legacy compatibility | services, config, network, scheduled | standard (SysVinit, ifcfg), kitchen-sink (xinetd, anacrontab) |

### Companion inspectah enhancements

- Advisory finding type (`FindingKind` enum)
- Section grouping in HTML report, refine view, TUI, and audit report
- tmpfiles.d-backed vs. unbacked /var dir detection
- Full /usr walk with rpm-dump diff + noise filtering
- Cross-tree symlink migration advisory
- Modernization advisory system (legacy cruft flagging)
- systemd drop-in vs. full shadow distinction
- EL8+ platform support

### Deferred — infrastructure-coupled tier

Subscription & entitlement, custom CA certificates, repo complexity, and FIPS mode are deferred as a group. All share the characteristic that planted artifacts can affect the downstream build pipeline (broken builds on unsubscribed hosts, failed TLS, missing repos, altered runtime behavior). These require a unified `--with-infra` design before implementation.

### Dropped

- **Container runtime config** — registries.conf/storage.conf are RPM-owned config files; no special handling needed.
- **ld.so.conf.d** — `ldconfig.service` regenerates the cache at boot; the drop-in is just another config file.
- **Host identity references** — roadmap item. Too noisy and hard to do right; false-positive risk outweighs signal.

---

## 3. Driftify Additions — Detail

### 3.1 Auth & Identity Infrastructure

**Enriches:** users section, config section

**Standard tier:**
- IPA client enrollment artifacts: `/etc/ipa/ca.crt`, `/var/lib/ipa-client/sysrestore/` directory
- Kerberos keytab at `/etc/krb5.keytab` (synthetic, non-functional)
- SSSD config at `/etc/sssd/sssd.conf` with IPA domain
- SSSD cache directories under `/var/lib/sss/`
- PAM faillock config: `/etc/security/faillock.conf` with custom settings
- authselect profile: run `authselect select sssd --force` (or plant the profile files directly if authselect is unavailable)
- Custom PAM config: modifications to `/etc/pam.d/system-auth` or drop-in at `/etc/pam.d/custom-sshd`

**Kitchen-sink tier:**
- AD join artifacts: `/etc/samba/smb.conf` with AD realm, machine keytab
- Winbind/SSSD hybrid config
- LDAP client cert at `/etc/openldap/certs/`

**inspectah detection:** PAM configs exercise the existing `pam_configs: Vec<CarryForwardFile>` field. SSSD/Kerberos/IPA configs are detected as modified RPM-owned configs. No new inspectah detection needed — this is a driftify-only addition.

### 3.2 tmpfiles.d + /var State Gaps

**Enriches:** config section, storage section

**Standard tier:**

Plant both patterns to enable comparison:

*With runtime backing (correct for image mode):*
- `/etc/tmpfiles.d/appone.conf` containing `d /var/lib/appone/cache 0750 appuser appgroup 30d`
- Corresponding `/var/lib/appone/cache/` directory created by the entry

*Without any backing mechanism (advisory concern):*
- `/var/lib/pgsql/data/` created via `mkdir -p` + `chown postgres:postgres`
- `/var/log/myapp/` created via `mkdir -p`
- `/var/cache/myapp/` created via `mkdir -p`
- No tmpfiles.d entries, no `StateDirectory=` in any service unit, not seeded in an image layer

*Additional tmpfiles.d fixtures:*
- `/etc/tmpfiles.d/cleanup.conf` with volatile dir: `D /run/myapp 0755 root root -`
- Exercises `ConfigCategory::Tmpfiles` classification (currently untested)

**Kitchen-sink tier:**
- tmpfiles.d entries with age-based cleanup timers on persistent dirs
- Nested /var directory trees with mixed backing (some levels have tmpfiles.d, deeper ones don't)

**Companion inspectah enhancement:** New advisory for /var dirs without any declarative backing mechanism. The advisory is always emitted as a factual observation — inspectah does not model the operator's intended migration path.

A /var directory is considered **declaratively backed** if any of the following **host-observable** signals apply:
- A `tmpfiles.d` entry in `/etc/tmpfiles.d/` or `/usr/lib/tmpfiles.d/` creates or manages it (detectable by parsing tmpfiles.d conf files for matching path directives)
- A systemd unit references it via `StateDirectory=`, `CacheDirectory=`, or `LogsDirectory=` (detectable by parsing unit files for these directives; the dir path is derived from the directive value under `/var/lib/`, `/var/cache/`, or `/var/log/` respectively)
- The directory path appears in the RPM file database (detectable via membership in the `rpm -qa --dump` path set — same source as §3.3)

Directories not matching any of these are **unbacked**. They receive two treatments:

1. **Containerfile output:** `RUN mkdir -p /var/lib/myapp/data && chown user:group /var/lib/myapp/data` — this is functional and familiar to sysadmins. On fresh `bootc install`, the image's `/var` is seeded from the image layer, so the directory exists. However, it is a one-shot: bootc never updates `/var` content after initial provisioning.

2. **Advisory:** "These /var directories have no declarative backing (tmpfiles.d, StateDirectory=). Consider adding tmpfiles.d entries for a more reproducible, declarative approach." This is a single grouped advisory per scan, not per-directory — it lists all unbacked dirs together.

The advisory educates without forcing a decision. A future `--var-strategy tmpfiles|mkdir` flag (see §9) will let operators who've absorbed the guidance switch to tmpfiles.d output globally.

**Spec annotation:** This interacts with existing storage fstab fixtures — NFS/CIFS mount targets in /var depend on the same backing mechanisms.

### 3.3 Files in /usr

**Enriches:** nonrpm/unmanaged files section

**Standard tier:**
- Wrapper script at `/usr/bin/custom-tool` (shell script, non-RPM)
- Custom systemd unit at `/usr/lib/systemd/system/myapp.service` (not from any RPM)
- Shared data directory at `/usr/share/myapp/` with a few files

**Kitchen-sink tier:**
- Binary in `/usr/sbin/custom-daemon`
- Library in `/usr/lib64/libcustom.so` (or a `.so` stub)
- Script in `/usr/libexec/myapp-helper`

**Companion inspectah enhancement:** Full /usr walk using rpm-dump diff.

**Canonical ownership source:** `rpm -qa --dump | cut -d' ' -f1`. This is the only accepted source. Do NOT use `rpm -ql $(rpm -qa)` (hits argv limits on large installs, different path normalization).

**Path normalization:** All paths from rpm-dump are normalized before insertion into the HashSet: absolute paths, no trailing slashes, no double slashes. Filesystem walk paths are normalized identically before lookup.

**Algorithm:**
1. Run `rpm -qa --dump`, extract field 1 (file path), normalize, insert into `HashSet<String>`.
2. Walk `/usr` using `walkdir`, excluding the prune list (§6.1).
3. For each path not in the RPM-owned set, classify as unmanaged.
4. Collapse to shallowest unowned ancestor (§6.2).
5. Report with `FileType` classification (same as existing unmanaged files).

**Finding type:** Files in /usr are actionable findings (not advisories) — they need `COPY` into the image build layer. `/usr` is a read-only composefs mount in image mode.

### 3.4 Performance Tuning Depth

**Enriches:** kernel section

**Standard tier:**
- Custom tuned profile: create `/etc/tuned/myapp/tuned.conf` with sysctl overrides, disk scheduler settings, and CPU governor configuration
- Hugepage sysctl: `vm.nr_hugepages=128` in `/etc/sysctl.d/hugepages.conf`
- Transparent hugepages disabled: `echo never > /sys/kernel/mm/transparent_hugepage/enabled` (and corresponding sysctl/GRUB arg)

**Kitchen-sink tier:**
- CPU isolation GRUB args: `isolcpus=2-3 nohz_full=2-3 rcu_nocbs=2-3`
- IRQ affinity: `/etc/sysconfig/irqbalance` with `IRQBALANCE_BANNED_CPULIST=2-3`
- NUMA-aware sysctl: `vm.zone_reclaim_mode=1`
- Custom udev rule for disk scheduler: `/etc/udev/rules.d/60-scheduler.rules`

**inspectah detection:** Already detects sysctl, GRUB args, and tuned profile switches. Custom tuned profile directories (`/etc/tuned/*/tuned.conf`) may need verification — confirm inspectah detects custom tuned profiles, not just the active profile name.

### 3.5 Logging & Monitoring

**Enriches:** config section, services section

**Standard tier:**
- rsyslog forwarding: `/etc/rsyslog.d/forward-to-siem.conf` with remote log target
- journald customization: `/etc/systemd/journald.conf.d/custom.conf` with `Storage=persistent`, `SystemMaxUse=2G`, `RateLimitIntervalSec=60s`, `RateLimitBurst=10000`
- Prometheus node_exporter: install the real `golang-github-prometheus-node_exporter` RPM (or equivalent), enable the systemd unit. Real package tests both RPM detection and service detection.

**Kitchen-sink tier:**
- AIDE: install `aide` RPM, create initial database with `aide --init`, plant `/etc/aide.conf` with custom rules
- Custom logrotate: `/etc/logrotate.d/myapp` with app-specific rotation
- Custom auditd rules: `/etc/audit/rules.d/custom.rules` (enriches existing audit coverage)

**inspectah detection:** rsyslog and journald exercise `ConfigCategory::Rsyslog` and `ConfigCategory::Journal` classification. Services exercise standard service detection. No new inspectah enhancement needed.

### 3.6 Cross-tree Symlinks

**Enriches:** config section

**Standard tier:**
- `/etc/mydb/config.yaml` → `/var/lib/mydb/config.yaml` (database config externalized to persistent storage)
- `/opt/myapp/lib` → `/usr/lib64/myapp/` (application linking into /usr tree)

**Kitchen-sink tier:**
- `/etc/app/ssl` → `/var/lib/app/ssl/` (TLS certs in persistent storage)
- Nested symlinks: `/opt/tool/bin/run` → `/usr/local/bin/run-tool` → `/usr/bin/actual-tool`

**Companion inspectah enhancement:** New advisory for cross-tree symlinks. When a symlink in `/etc` points to `/var`, the config is stateful — it persists via /var, not via /etc 3-way merge. When a symlink crosses into `/usr`, the target is in the immutable composefs layer.

**Allowlist:** Some cross-tree symlinks are legitimate system defaults and must not produce advisories. See §6.3 for the allowlist format and matching semantics.

**Advisory rationale examples:**
- "Symlink crosses /etc → /var: config is stateful via /var persistence, not subject to /etc 3-way merge"
- "Symlink crosses /opt → /usr: target is in the immutable /usr layer"

### 3.7 systemd Unit Shadows

**Enriches:** services section

**Standard tier:**
- Full unit override: create `/etc/systemd/system/sshd.service` that completely replaces the RPM-shipped unit at `/usr/lib/systemd/system/sshd.service`. Content should be a modified copy with a changed setting (e.g., different `ExecStart` flags).

This contrasts with the existing driftify coverage of drop-in overrides (`/etc/systemd/system/httpd.service.d/`).

**Companion inspectah enhancement (required):** Distinguish drop-in overrides from full unit shadows. Detection: if a file at `/etc/systemd/system/<unit>` exists AND a corresponding file exists at `/usr/lib/systemd/system/<unit>`, it is a full shadow. If only a `.d/` directory exists under `/etc/systemd/system/<unit>.d/`, it is a drop-in.

**Data model:** Add a `shadow_type` field to the service finding:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowType {
    DropIn,
    FullShadow,
}
```

**Rendering:** Full shadows display an advisory-style rationale line below the service finding: "Full unit shadow — base image updates to this unit will be silently ignored." The finding itself remains actionable (it maps to a Containerfile COPY). The rationale is informational context on an actionable finding, not a standalone advisory.

### 3.8 Legacy Compatibility

**Enriches:** services, config, network, scheduled sections

**Standard tier:**
- SysVinit script: `/etc/init.d/legacy-app` with LSB headers, no matching systemd unit
- ifcfg network config: `/etc/sysconfig/network-scripts/ifcfg-eth1` (deprecated on RHEL 9+ in favor of NM keyfiles)

**Kitchen-sink tier:**
- xinetd config: install `xinetd` RPM (if available), plant `/etc/xinetd.d/custom-service`
- anacrontab: `/etc/anacrontab` with custom entries
- cron.allow/cron.deny: `/etc/cron.allow` with restricted user list

**Companion inspectah enhancement:** Modernization advisory system. When inspectah detects a legacy pattern, it produces an advisory with the recommended modern replacement.

**Enumerated legacy patterns with OS version predicates:**

| Legacy pattern | Detection | Modern replacement | Advisory text | OS predicate |
|---|---|---|---|---|
| SysVinit script | File in `/etc/init.d/`, no matching `.service` unit | systemd unit | "SysVinit script with no systemd equivalent — create a .service unit for image mode" | All (EL8+) |
| xinetd config | File in `/etc/xinetd.d/` | systemd socket activation | "xinetd is deprecated — convert to systemd socket activation" | All (EL8+) |
| anacrontab | Custom entries in `/etc/anacrontab` | systemd timer | "anacrontab is superseded by systemd timers" | All (EL8+) |

**Note:** ifcfg-* is NOT in this table. Networking config is treated as host-specific inventory, not a modernization advisory. See §6.6 for the networking treatment.

This is the exhaustive list for this pass. Additional legacy patterns are deferred (see §8).

**EL8+ support:** driftify must detect EL8 via `/etc/os-release` (`VERSION_ID` starting with `8`). Key EL8 differences:
- ifcfg modernization advisory suppressed (ifcfg is still the standard format)
- Package availability differences (some packages may not exist on EL8; driftify must guard installs)
- systemd 239 (EL8) vs. 252+ (EL9+) — some tmpfiles.d directives unavailable
- `authselect` behavior differences

---

## 4. Data Model Changes (inspectah)

### 4.1 FindingKind Enum

Replace the current `include: bool` field with a `FindingKind` enum that structurally separates actionable findings from advisories:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FindingKind {
    Actionable {
        include: bool,
    },
    Advisory {
        advisory_type: AdvisoryType,
        rationale: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryType {
    /// /var dir without tmpfiles.d, StateDirectory=, or RPM backing
    UnbackedVarDir,
    /// Symlink crossing /etc//var//usr boundaries
    CrossTreeSymlink,
    /// Legacy pattern with a modern replacement
    Modernization,
}
```

**Why this shape:** `Actionable` carries mutable toggle state (`include`). `Advisory` carries immutable classification (`advisory_type`) and rationale text. These are structurally different — an advisory can never be toggled, and an actionable finding never carries a rationale. The tagged enum makes invalid states unrepresentable.

**AdvisoryType** provides stable machine-readable identity for fleet aggregation and filtering. The rationale is human-readable context text, not the identity.

### 4.2 Schema Version Contract

This spec introduces a breaking schema change (`include: bool` → `FindingKind`). The schema version bumps to the next integer (currently 20; this change bumps to 21, or whatever is next at implementation time).

**Existing gating pattern (preserved):** inspectah already uses exact-match schema gating — `MIN_SCHEMA == SCHEMA_VERSION`, rejecting anything below or above. This spec does not change that behavior. The new version is accepted; all others are rejected with: "Unsupported schema version: N (accepted: 21)."

**No version reset now.** The schema version resets to 1.0 at GA. Until then, the pre-GA integer sequence continues incrementing. No backwards compatibility is maintained between pre-GA schema versions.

**Affected consumers:** Refine (web), TUI, fleet aggregate, audit report, and any external tools consuming snapshot JSON. All must handle `FindingKind` instead of `include: bool`. The existing fleet aggregate validation (all snapshots must share the same schema version) applies unchanged.

**Re-scan requirement:** Existing snapshots from prior schema versions cannot be upgraded in place. Operators must re-scan hosts to produce current-version snapshots. This is the existing behavior — no change.

### 4.3 Section Grouping

Section grouping is a **presentation concern** derived at render time from snapshot section identifiers. It is NOT persisted in the snapshot JSON. The mapping is a const in the rendering layer, not a schema field.

**Rationale:** Keeping grouping out of the snapshot avoids baking a UI taxonomy into the data contract. Future regrouping requires only a rendering change, not a schema migration.

**Group enum (rendering layer only):**

```rust
pub enum SectionGroup {
    Packages,
    SystemConfig,
    Services,
    Identity,
    Network,
    Storage,
    Software,
    Secrets,
}
```

**Section-to-group mapping (strictly section-based):**

| Section | Group |
|---------|-------|
| rpm | Packages |
| config | SystemConfig |
| kernel_boot | SystemConfig |
| selinux | SystemConfig |
| services | Services |
| scheduled_tasks | Services |
| containers | Services |
| users_groups | Identity |
| network | Network |
| storage | Storage |
| non_rpm_software | Software |
| unmanaged_files | Software |
| secrets | Secrets |
| subscription | Secrets |

Grouping is strictly section-to-group. Auth/identity findings that land in the `config` section (e.g., SSSD configs, PAM files) remain in `SystemConfig` — they are not promoted to `Identity`. This avoids a secondary finding-level taxonomy. The `Identity` group contains `users_groups` only.

---

## 5. Presentation Changes (inspectah)

### 5.1 Advisory Rendering

#### HTML report (PatternFly 6)

- **Icon:** `pf-icon-info` (info circle) instead of wrench for actionable findings
- **Badge:** `<Label color="blue">Advisory</Label>` inline with finding title
- **Rationale:** one-line text below the finding title, styled as helper text
- **Sort order:** advisories appear below actionable findings within the same section
- **No toggle switch rendered**
- **Keyboard:** advisory rows are focusable via Tab (part of normal document flow) but non-interactive (no toggle activation on Enter/Space)
- **ARIA:** `role="listitem"` with `aria-label` including the advisory type and rationale. No `aria-pressed` or toggle semantics.

#### TUI (ratatui)

- **Prefix:** `ℹ` character before advisory items (no prefix for actionable findings)
- **Navigation:** advisory items are reachable via arrow keys in the list but non-selectable (Enter/Space has no effect)
- **Detail pane:** rationale text shown when advisory row is focused
- **No selection/toggle capability**

#### Audit report (markdown)

- Advisories listed under a `### Advisories` subheading within each group (see §5.2)
- Format: `- ℹ **[path/pattern]** — [rationale]`

### 5.2 Section Grouping Rendering

#### HTML report

- Group headings rendered as `<h2>` elements
- Count badge on group heading shows actionable finding count only (advisories excluded from count)
- Sections within a group are collapsible via a disclosure control
- Default state: expanded
- **Collapsed summary:** when collapsed, heading shows "[N actionable, M advisories]"
- **Keyboard:** group disclosure toggle activated via Enter or Space when heading is focused. Focus moves to first item within expanded group. When collapsing, focus returns to the group heading.
- **ARIA:** `aria-expanded="true|false"` on the disclosure control. `aria-controls` references the collapsible content region. Group heading is the accessible name for the region.

#### Refine view

- Same grouping structure as HTML report
- **Batch toggle:** "Include all" / "Exclude all" controls at the group heading level
  - **Scope:** affects all `Actionable` findings within the group. Advisories are unaffected.
  - **Mixed state:** when a group contains both included and excluded items, the batch control shows an indeterminate/mixed state (checkbox with dash or PatternFly mixed indicator)
  - **Count display:** batch control label shows "Include all (N items)" where N counts only actionable findings, not advisories
  - **Post-action:** focus remains on the batch control. Screen reader announces "[N] items [included/excluded]."
  - **Collapsed groups:** batch action applies to all items in the group regardless of collapse state. A confirmation is not required (consistent with per-item toggles being instant).
- **Collapse state persistence:** refine view preserves user-set collapse/expand state within the active session. Navigation and search do not reset collapse state. Search results within collapsed groups auto-expand the containing group.

#### TUI (ratatui)

- Groups rendered as navigable tree nodes
- **Keys:** Left arrow collapses a group, Right arrow expands. Enter toggles inclusion on actionable items only.
- **Collapsed display:** group node shows "[N actionable, M advisories]"
- Advisory items within expanded groups are navigable (arrow keys) but non-toggleable (Enter has no effect, visual indicator distinguishes from actionable items)

#### Audit report (markdown)

- Group headings rendered as `## [Group Name]` (h2)
- Sections within groups rendered as `### [Section Name]` (h3)
- Advisories under `### Advisories` within each group, after all section content
- This mirrors the interactive surfaces' information architecture

---

## 6. Technical Requirements

### 6.1 /usr Walk Prune List

The full /usr walk must prune directories that produce noise without migration value:

```
/usr/share/doc/
/usr/share/man/
/usr/share/locale/
/usr/share/info/
/usr/share/licenses/
/usr/share/icons/
/usr/share/pixmaps/
/usr/share/fonts/
/usr/share/mime/
/usr/share/zoneinfo/
/usr/lib/.build-id/
```

Generated file patterns to exclude:
- `*.pyc`, `__pycache__/`
- `*.cache`
- Font cache files
- `ld.so.cache` (regenerated at boot)

The prune list lives in the collect crate as a const array. It is product behavior, not an implementation detail — additions require a design decision.

### 6.2 Unowned Ancestor Collapse Algorithm

When reporting unmanaged files in /usr, collapse to the shallowest unowned ancestor directory to reduce noise.

**Definition of "unowned":** A directory is unowned if its path does not appear in the RPM-owned path set built from `rpm -qa --dump` (see §3.3 for the canonical source and normalization rules).

**Algorithm:**
1. For each unmanaged file, walk up the directory tree toward `/usr`.
2. At each parent directory, check if the parent path is in the RPM-owned HashSet.
3. The shallowest directory NOT in the set is the report target.
4. If the file itself is directly under an RPM-owned parent (parent is owned, file is not), report the file individually.

**Acceptance cases:**

| RPM owns | File found | Report target | Rationale |
|----------|-----------|---------------|-----------|
| `/usr/lib64/` | `/usr/lib64/myapp/libfoo.so` | `/usr/lib64/myapp/` (directory) | Shallowest unowned ancestor |
| `/usr/lib64/` | `/usr/lib64/myapp/sub/deep.so` | `/usr/lib64/myapp/` (directory) | Collapse past nested dirs |
| `/usr/lib64/`, `/usr/lib64/myapp/` | `/usr/lib64/myapp/custom/x.so` | `/usr/lib64/myapp/custom/` (directory) | Owned intermediate, unowned child |
| `/usr/bin/` | `/usr/bin/custom-tool` | `/usr/bin/custom-tool` (file) | Direct child of owned parent |
| `/usr/share/` | `/usr/share/myapp/data.json` | `/usr/share/myapp/` (directory) | Shallowest unowned ancestor |

**Symlinked paths:** Only the symlink's own path is checked against the RPM-owned set. If the symlink itself is NOT RPM-owned, it is reported as unmanaged regardless of whether its target is RPM-owned. An unmanaged symlink pointing to an RPM-owned target (e.g., `/usr/bin/custom-link → /usr/bin/bash`) is real drift — the symlink is copy-worthy even though the target ships with the base image.

**Output:** Collapsed entries report the directory path, the count of files beneath it, and the total size.

### 6.3 Cross-tree Symlink Allowlist

The allowlist suppresses advisories for known-good system symlinks that cross /etc//var//usr boundaries.

**Format:** Each entry is a `(source_prefix, target_prefix)` pair. An allowlist match requires BOTH:
- The symlink's source path starts with `source_prefix`
- The symlink's fully resolved target path starts with `target_prefix`

Matching is always on the **fully resolved** target, not intermediate hops. Multi-hop symlinks are resolved to their final target before matching.

**Initial allowlist:**

| Source prefix | Target prefix | Reason |
|---------------|---------------|--------|
| `/etc/localtime` | `/usr/share/zoneinfo/` | System timezone |
| `/etc/alternatives/` | `/usr/` | alternatives system |
| `/etc/ssl/certs/ca-bundle.crt` | `/etc/pki/` | PKI symlink chain |
| `/etc/pki/tls/cert.pem` | `/etc/pki/` | PKI symlink chain |
| `/etc/crypto-policies/back-ends/` | `/usr/share/crypto-policies/` | Crypto policy backends |
| `/etc/resolv.conf` | `/run/` | systemd-resolved |

The allowlist lives in the core crate as a `const` slice. It is product behavior — additions require a design decision, not a code change.

**Negative test cases (must NOT be suppressed):**

| Source | Target | Why not suppressed |
|--------|--------|-------------------|
| `/etc/alternatives/foo` | `/var/lib/custom/foo` | alternatives retargeted to /var (not /usr) |
| `/etc/mydb/config` | `/var/lib/mydb/config` | Application cross-tree symlink |
| `/etc/myapp/ssl` | `/var/lib/myapp/ssl/` | Application TLS in /var |

**Broken symlinks:** A symlink whose target does not exist produces an advisory regardless of allowlist. Broken symlinks are always flagged.

### 6.4 EL8 Platform Support

**driftify:**
- Detect EL8 via `/etc/os-release` (`VERSION_ID` starting with `8`)
- Guard EL8-incompatible operations:
  - Package installs: check availability before `dnf install`, skip unavailable packages with a log message
  - tmpfiles.d: avoid directives unavailable on systemd 239
  - authselect: check for presence before use
- ifcfg is NOT a modernization advisory on any platform — it's network inventory (see §6.6)
- Add EL8 to supported platforms in README and `--help`

**inspectah:**
- `rpm -qa --dump` format compatibility between EL8 and EL9+ rpm versions (verify field layout is consistent; if not, add version-specific parsing)
- systemd 239 (EL8) service/timer inspection differences
- OS version predicate in modernization advisory emission (§3.8 table)

**EL8 acceptance tests:** driftify must run cleanly on EL8 with `--profile standard`. All modernization advisories with "EL9+ only" predicates must NOT fire on EL8 snapshots.

### 6.5 EL8 Target Image Mapping

EL8 support means **scanning** EL8 hosts — image mode does not exist for RHEL 8. The target base image in the generated Containerfile is always RHEL 9+.

**Default target image mapping:**

| Source host OS | Default target base image |
|---|---|
| RHEL 8.x | `registry.redhat.io/rhel9/rhel-bootc:latest` |
| RHEL 9.x | `registry.redhat.io/rhel9/rhel-bootc:latest` |
| RHEL 10.x | `registry.redhat.io/rhel10/rhel-bootc:latest` |
| CentOS Stream 8 | `quay.io/centos-bootc/centos-bootc:stream9` |
| CentOS Stream 9 | `quay.io/centos-bootc/centos-bootc:stream9` |
| CentOS Stream 10 | `quay.io/centos-bootc/centos-bootc:stream10` |
| Fedora | `quay.io/fedora/fedora-bootc:latest` |

The minimum RHEL image-mode version is 9.6, but users typically pick `$latest` for their major version. Operators can override the target image via inspectah's existing `--base-image` flag.

**Baseline subtraction:** When scanning an EL8 host, the baseline comparison is against the RHEL 9 base image (since that's the target). Packages present on EL8 but absent from the RHEL 9 base image are flagged as additions. This is correct behavior — the Containerfile needs to install them on the target.

### 6.6 Networking Config Treatment

**Networking config does NOT belong in the Containerfile.** It is host-specific state provisioned at deploy time via Ignition, cloud-init, kickstart, nmstate, or equivalent. The bootc model is "generic image + host-specific state at first boot." Networking is the canonical example of host-specific state.

**inspectah treatment:** When inspectah detects networking customizations (ifcfg files, NM keyfiles, custom zones, static routes):
- Show them in the **network section** of the report as informational inventory
- Do NOT include them in the Containerfile
- Do NOT produce modernization advisories for ifcfg format

**Contextual note for EL8→EL9 scans:** When the source host uses ifcfg format and the target is RHEL 9+, the network section displays: "Source host uses ifcfg network scripts. RHEL 9+ targets use NetworkManager keyfiles by default. ifcfg support is deprecated in RHEL 9 and removed in RHEL 10. Plan network configuration separately for the target environment."

**Rationale:** Network config is preserved during `bootc switch` (existing `/etc` carries over), so in-place migration doesn't lose it. For fleet/golden-image deploys, networking is injected at provisioning time, not baked into the image. Inspectah's value is surfacing the gap, not automating the conversion.

### 6.7 Modernization Advisory Scope

The enumerated list in §3.8 is the complete scope for this pass.

**Explicitly deferred (need product-level decisions):**
- Legacy PAM configurations (unclear what "legacy" means in PAM context)
- Old cron.d format patterns vs. systemd timers (too broad — most cron usage is legitimate)
- Deprecated sysctl parameters (requires per-parameter assessment)
- Legacy mount options in fstab (requires per-option assessment)

The modernization advisory system is designed for extension — new patterns are added to the table in §3.8 with detection rule, replacement, advisory text, and OS predicate. No infrastructure changes needed for future additions.

---

## 7. Acceptance Matrix

Representative fixture-to-finding mapping. One row per planted pattern. This is not exhaustive — it covers the key cases and boundary conditions.

| Profile | Platform | Planted artifact | Expected section | Expected finding kind | Expected rationale / note | Negative control |
|---------|----------|-----------------|-----------------|----------------------|--------------------------|-----------------|
| standard | EL9 | `/etc/sssd/sssd.conf` (modified) | config | Actionable | Modified RPM-owned config | — |
| standard | EL9 | `/etc/pam.d/custom-sshd` | config | Actionable | Unowned config file | — |
| standard | EL9 | `/etc/tmpfiles.d/appone.conf` | config | Actionable | ConfigCategory::Tmpfiles | — |
| standard | EL9 | `/var/lib/pgsql/data/` (no backing) | storage | Advisory (UnbackedVarDir) | "No tmpfiles.d, StateDirectory=, or RPM backing..." | `/var/lib/appone/cache/` (has tmpfiles.d) must NOT get advisory |
| standard | EL9 | `/usr/bin/custom-tool` | unmanaged_files | Actionable | Non-RPM file in /usr | RPM-owned `/usr/bin/bash` must NOT appear |
| standard | EL9 | `/usr/share/myapp/` (3 files) | unmanaged_files | Actionable | Collapsed: "/usr/share/myapp/ (3 files)" | `/usr/share/doc/` (pruned) must NOT appear |
| standard | EL9 | `/etc/mydb/config.yaml` → `/var/lib/mydb/` | config | Advisory (CrossTreeSymlink) | "Symlink crosses /etc → /var..." | `/etc/localtime` → `/usr/share/zoneinfo/` must NOT get advisory |
| standard | EL9 | `/etc/systemd/system/sshd.service` (full shadow) | services | Actionable | `shadow_type: FullShadow`, rationale line on finding | Drop-in in `httpd.service.d/` must show `DropIn` |
| standard | EL9 | `/etc/init.d/legacy-app` | config | Advisory (Modernization) | "SysVinit script with no systemd equivalent..." | — |
| standard | EL9 | `/etc/sysconfig/network-scripts/ifcfg-eth1` | network | Informational inventory | Network section note: "ifcfg format, deprecated on target" | NOT in Containerfile, NOT a modernization advisory |
| standard | EL8 | `/etc/sysconfig/network-scripts/ifcfg-eth1` | network | Informational inventory | Network section note: "ifcfg format, plan network config separately" | NOT in Containerfile |
| standard | EL9 | `/etc/tuned/myapp/tuned.conf` | config | Actionable | Custom tuned profile directory | — |
| standard | EL9 | node_exporter RPM + enabled service | services, rpm | Actionable | Detected as added package + enabled service | — |
| kitchen-sink | EL9 | `/etc/xinetd.d/custom-service` | config | Advisory (Modernization) | "xinetd is deprecated..." | — |
| kitchen-sink | EL9 | `/usr/lib64/myapp/libfoo.so` | unmanaged_files | Actionable | Collapsed under `/usr/lib64/myapp/` | — |
| standard | EL9 | `/etc/alternatives/python3` → `/usr/bin/python3.9` | — | — | — | Allowlisted, must NOT produce advisory |
| standard | EL9 | Broken symlink `/etc/myapp/conf` → `/var/lib/myapp/gone` | config | Advisory (CrossTreeSymlink) | "Broken cross-tree symlink..." | Must fire even if source matches allowlist prefix |

---

## 8. Implementation Approach

**One spec (this document), two implementation plans:**

**Plan A — driftify additions:**
- 8 new drift categories across existing sections
- EL8+ platform support
- Profile tier assignments per §3
- No new driftify sections — all additions enrich existing `drift_*()` methods or add new methods within existing sections

**Plan B — inspectah companion enhancements:**
- `FindingKind` enum replacing `include: bool` (schema version bump)
- Schema version boundary and rejection contract (§4.2)
- `SectionGroup` enum and rendering (derived, not persisted) (§4.3)
- Full /usr walk with rpm-dump diff, prune list, ancestor collapse (§3.3, §6.1, §6.2)
- tmpfiles.d / StateDirectory= / RPM-backed /var dir advisory (§3.2)
- Cross-tree symlink advisory with allowlist (§3.6, §6.3)
- Modernization advisory system with OS-predicated pattern table (§3.8) — ifcfg excluded, handled as network inventory (§6.6)
- systemd drop-in vs. full shadow distinction with `ShadowType` (§3.7)
- EL8 target image mapping — default base image selection per source OS (§6.5)
- Network config as informational inventory, not Containerfile output (§6.6)
- Section grouping presentation across HTML, refine, TUI, audit (§5.2)
- Advisory presentation across all surfaces (§5.1)
- EL8 platform compatibility in collect crate (§6.4)

**Dependency:** The two plans can execute independently. driftify additions work without inspectah changes — inspectah already detects the planted artifacts as config files, services, etc. The inspectah enhancements add advisory intelligence on top. Section grouping and the advisory type can ship in any order relative to each other and relative to the driftify additions.

---

## 9. Future Work (Out of Scope)

- **Infrastructure-coupled tier** (`--with-infra`): subscription, CA certs, repo complexity, FIPS. Needs unified safe-vs-realistic mode design.
- **Host identity references**: machine-id/hostname in configs. Roadmap item.
- **bootc-owned path awareness**: files bootc itself manages (Ember's observation).
- **Layered RPMs on bootc systems**: auditing drift FROM base image on image-mode systems (requires bootc host, outside driftify's scope).
- **Additional modernization patterns**: legacy PAM, deprecated sysctl, legacy mount options.
- **`--var-strategy tmpfiles|mkdir` flag**: global preference for /var directory output strategy. Default `mkdir` (current behavior). `tmpfiles` generates tmpfiles.d entries using type `d` (non-destructive create-if-missing). Graduated path from the advisory in §3.2.
- **Cross-section domain grouping**: promoting findings from one section into another group (e.g., identity-related config findings into Identity group). Deferred pending real-world usage feedback on section-based grouping.
