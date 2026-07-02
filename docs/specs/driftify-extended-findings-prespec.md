# Driftify Extended Findings — Pre-Spec Catalog

**Date:** 2026-06-30
**Status:** Pre-brainstorm — working document
**Sources:** Ember (product/market lens), Collins (image-mode architecture lens)
**Excluded:** Crypto-policies (testing burden — may revisit)
**Flagged:** FIPS mode (related testing concerns — figure out approach)

---

## How to Read This

Each candidate is a gap area identified by Ember and/or Collins. For each:
- **What to plant** — what driftify would create on the VM
- **What inspectah detects** — the detection path this exercises
- **Profile tier** — which driftify profile (minimal/standard/kitchen-sink)
- **Source** — who identified it and their reasoning
- **Open questions** — things to resolve in brainstorm

Items are numbered for reference during brainstorm. Ordering is not priority — that's what the brainstorm decides.

---

## 1. Subscription & Entitlement

**Section type:** New driftify section (`--skip-subscription`)

**What to plant:**
- Fake RHSM config (`/etc/rhsm/rhsm.conf` with custom server URL)
- Synthetic entitlement cert/key pair in `/etc/pki/entitlement/`
- Fake CA cert in `/etc/rhsm/ca/`
- Consumer identity in `/etc/pki/consumer/`
- (standard) Multiple entitlement certs (some expired), Satellite-style server URL, org ID in syspurpose

**What inspectah detects:** inspectah already has a full `SubscriptionSection` — entitlement certs, CA certs, config files, expiry dates, org ID, system UUID, RHSM server. `--preserve-subscription` flag exists. None of this is currently exercised by driftify.

**Profile tier:** minimal (basic RHSM artifacts), standard (complex: multiple certs, Satellite URL, expired certs)

**Source:** Ember — "Every production RHEL system has subscription state. Without it, demos look like a toy scanning a toy." Also: inspectah's `inspectah-build` script does automatic subscription cert handling for non-RHEL build hosts — without driftify fixtures, that entire path is tested manually or not at all. This is Ember's #1 recommendation.

**Competitive angle (Ember):** No competitor has this problem — Talos, Flatcar, Bottlerocket don't have subscription state. This is uniquely RHEL and plays to "we understand enterprise Linux" positioning.

**Open questions:**
- New section or fold into existing? inspectah has a dedicated SubscriptionSection, suggesting a dedicated driftify section.
- How realistic can fake certs be without touching actual RHSM infrastructure?
- Should driftify detect if it's running on an already-subscribed system and layer on top?

---

## 2. Custom CA Certificates

**Section type:** Enrich config section or new subsection

**What to plant:**
- (minimal) Fake internal CA cert at `/etc/pki/ca-trust/source/anchors/mycompany-root-ca.pem` + run `update-ca-trust`
- (standard) Apache/nginx TLS cert/key pair in `/etc/pki/tls/`
- (kitchen-sink) Java truststore with custom CA, client cert for mutual TLS

**What inspectah detects:** inspectah classifies `ConfigCategory` for PKI paths. The tricky migration concern: `update-ca-trust` generates derived files in `/etc/pki/ca-trust/extracted/` — inspectah should detect the source cert and flag that `update-ca-trust` needs to run in the Containerfile.

**Profile tier:** minimal (nearly universal in enterprise), standard (app TLS), kitchen-sink (Java truststore)

**Source:** Both — Collins: "near-universal in enterprise, breaks TLS without it." Ember: "table-stakes for enterprise credibility."

**Open questions:**
- Should inspectah distinguish between source certs (anchors/) and derived state (extracted/)?
- Does the Containerfile renderer already handle `update-ca-trust`?

---

## 3. Authentication & Identity Infrastructure

**Section type:** Enrich users section + config section

**What to plant:**
- (standard) IPA client enrollment artifacts: `/etc/ipa/ca.crt`, `/var/lib/ipa-client/sysrestore/`, keytab at `/etc/krb5.keytab`, SSSD cache dirs, PAM config for SSSD, authselect profile
- (standard) Custom PAM config: `/etc/pam.d/` modifications, `/etc/security/faillock.conf`
- (kitchen-sink) AD join artifacts: Samba winbind config, machine keytab, `/etc/samba/smb.conf` with AD realm, LDAP cert

**What inspectah detects:** inspectah's selinux section has `pam_configs: Vec<CarryForwardFile>`, suggesting PAM collection exists but is untested. SSSD/Kerberos config files are detected as modified RPM-owned configs, but the identity infrastructure story is richer than individual config files.

**Profile tier:** standard (IPA/SSSD + PAM), kitchen-sink (AD/winbind)

**Source:** Both — Ember: "80%+ of production RHEL is domain-joined. 'Will my machines still authenticate?' is the #1 migration fear." Collins: "PAM drift is one of the hardest things to migrate — a silently dropped PAM rule could lock users out."

**Competitive angle (Ember):** Talos and Bottlerocket are Kubernetes-only — they don't have user authentication problems. This is a uniquely RHEL migration challenge. Demonstrating inspectah detects identity infrastructure separates it from any file-diffing tool.

**Collins detail:** PAM files are RPM-owned (from `pam` package), so modifications show up as rpm -Va differences, but they're deeply interconnected — changing one PAM stack file can break auth entirely. In image mode, PAM config is subject to /etc 3-way merge. The coverage gaps spec explicitly listed PAM as "Out of Scope" but inspectah has PAM collection infrastructure already.

**Open questions:**
- Is this one driftify section or does it enrich multiple existing sections?
- Should inspectah produce specific migration advice for identity (e.g., "keytabs expire — re-enroll after migration")?
- How much IPA/AD infrastructure can driftify fake without a real directory server?

---

## 4. tmpfiles.d + /var State Gaps

**Section type:** Enrich config section + storage section

**What to plant:**
- (standard) Custom tmpfiles.d drop-ins: `d /var/lib/myapp/cache 0750 appuser appgroup 30d`, `D /run/myapp 0755 root root -`
- (standard) App directories under `/var/lib/`, `/var/log/`, `/var/cache/` created by hand (no tmpfiles.d backing) — contrasted with dirs that DO have tmpfiles.d entries
- (kitchen-sink) tmpfiles.d entries with age-based cleanup timers, volatile dirs in /run

**What inspectah detects:** inspectah classifies `ConfigCategory::Tmpfiles` for `/etc/tmpfiles.d/` paths, but driftify never creates any — that classification path is untested. The deeper gap: inspectah should distinguish /var dirs backed by tmpfiles.d from hand-created dirs (the latter won't exist on a fresh deploy from the image).

**Profile tier:** standard (tmpfiles.d is bread-and-butter RHEL administration)

**Source:** Collins — "The single biggest surprise in image-mode adoption: 'where did my /var directories go?'" Also: "The converse is also important — a custom tmpfiles.d entry that purges files on a timer (`30d` age) carries forward into the image and might surprise users."

**Collins layer analysis:** In image mode, `/var` is the persistent stateful tree. tmpfiles.d is the *correct* mechanism for ensuring directory structure exists under `/var` on every boot. But on package-mode, admins just `mkdir -p` and never write tmpfiles.d entries. If an app expects `/var/lib/myapp/cache` to exist but there's no tmpfiles.d entry, that directory vanishes on first image-mode boot from a fresh deployment.

**Open questions:**
- Does inspectah currently distinguish tmpfiles.d-backed vs hand-created /var dirs?
- Should this drive a new inspectah finding type ("this /var dir has no tmpfiles.d backing")?
- How does this interact with the existing storage inspector?

---

## 5. Files in /usr (Image-Mode Violation)

**Section type:** Enrich nonrpm section or new detection concern

**What to plant:**
- (minimal) Wrapper script at `/usr/local/bin/custom-tool` (already partially covered)
- (standard) Script dropped directly in `/usr/bin/custom-tool`, custom systemd unit at `/usr/lib/systemd/system/myapp.service`, shared data at `/usr/share/myapp/`
- (kitchen-sink) Binary in `/usr/sbin/`, library in `/usr/lib64/`, config generator in `/usr/libexec/`

**What inspectah detects:** inspectah's unmanaged files scanner covers `/opt`, `/srv`, `/usr/local` — but NOT `/usr/bin`, `/usr/lib`, `/usr/share`. Files dropped into the RPM-owned `/usr` tree are a different and arguably more critical category of drift. In image mode, `/usr` is a composefs mount — read-only, integrity-verified. Anything placed there that isn't from an RPM will be invisible.

**Profile tier:** minimal (/usr/local — already exists), standard (/usr/bin, /usr/lib/systemd), kitchen-sink (/usr/sbin, /usr/lib64, /usr/libexec)

**Source:** Collins — "THE canonical image-mode violation. If inspectah can't see these, migration advice is incomplete." Note: this is also a detection gap in inspectah itself, not just driftify.

**Collins layer analysis:** In image mode, `/usr` is a composefs mount — read-only, integrity-verified via fs-verity. Any file placed directly in `/usr` on the source system that isn't from an RPM is invisible in the image unless explicitly handled. The existing unmanaged files scanner covers `/opt`, `/srv`, `/usr/local` — but the RPM-owned `/usr` tree (`/usr/bin`, `/usr/lib`, `/usr/share`) is a different and arguably more critical category. `rpm -Va` flags *modified* RPM files; the gap is files that aren't from ANY RPM but live in RPM-owned paths.

**Open questions:**
- Does inspectah currently scan /usr/bin, /usr/lib etc. for non-RPM files? If not, this is an inspectah feature + driftify fixture.
- Performance concern: scanning all of /usr is expensive. Need a targeted approach (rpm -Va already flags modified RPM files; the gap is files that aren't from ANY RPM).
- Should this be a new inspectah section or extend unmanaged_files?

---

## 6. Performance Tuning Depth

**Section type:** Enrich kernel section

**What to plant:**
- (standard) Custom tuned profile directory (`/etc/tuned/myapp/tuned.conf`) with sysctl, disk scheduler, CPU governor overrides. Hugepage sysctl (`vm.nr_hugepages`). Transparent hugepages disabled.
- (kitchen-sink) CPU isolation GRUB args (`isolcpus`, `nohz_full`, `rcu_nocbs`). IRQ affinity config (`/etc/sysconfig/irqbalance`). NUMA-aware sysctl. Custom udev rules for disk schedulers.

**What inspectah detects:** inspectah already detects sysctl and GRUB args. The gap is custom tuned profiles (directory in /etc/tuned/) and hardware-specific tuning that characterizes production workloads.

**Profile tier:** standard (custom tuned profile, hugepages), kitchen-sink (CPU isolation, IRQ, NUMA)

**Source:** Ember — "The difference between a web server and a database server. Engineering leadership cares about 'can this handle our production workloads?'" Also: "Every telco NFV host and many financial services workloads use CPU isolation. IRQ affinity and NUMA tuning are standard in database servers, HPC nodes, and latency-sensitive workloads."

**Open questions:**
- Does inspectah detect custom tuned profile directories or just the active profile name?
- Should tuned profiles be in the kernel section or a new performance section?
- How much of this is already covered by existing sysctl/GRUB detection?

---

## 7. Logging & Monitoring

**Section type:** Enrich config + services sections

**What to plant:**
- (standard) Custom rsyslog forwarding config (`/etc/rsyslog.d/forward-to-siem.conf`). Custom journald config (`/etc/systemd/journald.conf.d/custom.conf` — persistent, size limits, rate limits). Prometheus node_exporter systemd unit.
- (kitchen-sink) AIDE database + config. Custom logrotate entries. Custom auditd rules (partially exists). Collectd/Telegraf config.

**What inspectah detects:** inspectah classifies `ConfigCategory::Journal` for journald.conf.d, `ConfigCategory::Rsyslog` for rsyslog.d. Monitoring agent services would be detected as enabled services. The fleet prevalence story: 100% have journald config, 80% have node_exporter, 40% have a legacy agent.

**Profile tier:** standard (rsyslog + journald + one agent), kitchen-sink (AIDE + multi-agent)

**Source:** Both — Ember: "every production system has monitoring infrastructure." Collins: "journald config affects whether logs survive image upgrades."

**Open questions:**
- Should monitoring agents be real packages (node_exporter RPM) or fake unit files?
- Real packages are more realistic but add install time. Fake units test service detection but not package detection.
- Is AIDE relevant to the migration story or just noise?

---

## 8. Repo Complexity

**Section type:** Enrich rpm section

**What to plant:**
- (standard) Custom internal mirror repo file with `baseurl=https://repo.internal.example.com/rhel9/`, GPG key import, `exclude=kernel*` in dnf.conf, one third-party repo (HashiCorp/Grafana pattern with their actual repo structure)
- (kitchen-sink) Multiple third-party repos with different GPG keys, dnf module stream resets, package group installations, versionlock entries at standard tier (currently kitchen-sink only)

**What inspectah detects:** inspectah detects repos and classifies source repos. The gap: internal mirrors with custom baseurls, exclude patterns, and the "are these repos available at image build time?" question.

**Profile tier:** standard (internal mirror + excludes + one third-party), kitchen-sink (complex repo landscape)

**Source:** Ember — "Every company with >50 RHEL hosts has internal mirrors. The Containerfile `RUN dnf install` is only valid if the repos are available at build time."

**Open questions:**
- Can driftify create a repo file pointing to a non-existent internal mirror? (Yes — inspectah doesn't need to resolve it, just detect it.)
- Should driftify create real third-party repos (e.g., actually add HashiCorp repo) or just fake repo files?
- How does this interact with inspectah's repo classification (source_repos)?

---

## 9. Container Runtime Config

**Section type:** Enrich config section or containers section

**What to plant:**
- (standard) Custom `/etc/containers/registries.conf` with mirror configuration and blocked registries. Custom `/etc/containers/storage.conf` with custom graph root. Custom `/etc/containers/containers.conf` with default settings.
- (kitchen-sink) registries.conf.d drop-in with enterprise mirror pattern, policy.json with signature verification

**What inspectah detects:** These are RPM-owned configs (from `containers-common`), so modifications appear as rpm -Va changes. But they're semantically special — they configure the infrastructure that bootc uses to pull images. Misconfigured registries.conf in the image could prevent bootc from pulling its own updates.

**Profile tier:** standard (Podman/bootc users almost always customize these)

**Source:** Collins — "Misconfigured registries.conf in the image could prevent bootc from pulling its own updates."

**Open questions:**
- Should inspectah flag container runtime configs with a special warning about image-mode implications?
- Is this a config finding or does it deserve a dedicated advisory?
- Does driftify need containers-common installed first? (It should be on most RHEL systems.)

---

## 10. Cross-tree Symlinks

**Section type:** Enrich config section

**What to plant:**
- (standard) Symlink `/etc/myapp/config.yaml → /var/lib/myapp/config.yaml` (config that's actually stateful). Symlink `/opt/myapp/lib → /usr/lib64/myapp/` (app pointing into /usr).
- (kitchen-sink) Symlink farm in /etc/alternatives style. Circular symlink edge case. Symlink from /etc into /opt.

**What inspectah detects:** inspectah's unmanaged files scanner notes `FileType::Symlink` and tracks `link_target`, but driftify never creates cross-tree symlinks that exercise this logic. The migration impact: a symlink `/etc/myapp.conf → /var/lib/myapp/myapp.conf` means config is stateful (in /var), which is fine in image mode but invisible to /etc 3-way merge.

**Profile tier:** standard (cross-tree symlinks), kitchen-sink (edge cases)

**Source:** Collins — "Symlinks that cross the /etc//var//usr boundaries create ambiguity for the 3-way merge."

**Open questions:**
- Does inspectah currently trace symlink targets across filesystem boundaries?
- Should this be a finding/advisory ("this config is actually stateful via symlink")?
- How many real-world systems actually have cross-tree symlinks? Is this common or edge-case?

---

## 11. systemd Unit Shadows

**Section type:** Enrich services section

**What to plant:**
- (standard) Full unit override at `/etc/systemd/system/sshd.service` that completely shadows the RPM-shipped unit in `/usr/lib/systemd/system/sshd.service`. Contrast with existing drop-in approach (which is already covered).

**What inspectah detects:** inspectah detects service state changes, but the distinction between drop-in overrides (composable, base image updates still apply) and full unit shadows (base image updates silently ignored) is migration-critical. A full shadow prevents the base image's updated unit from taking effect.

**Profile tier:** standard (full unit overrides are common for sshd, postfix, httpd)

**Source:** Collins — "A full replacement prevents the base image update from taking effect — silently."

**Open questions:**
- Does inspectah currently distinguish drop-in vs full shadow?
- Is this an inspectah detection improvement or just a driftify fixture gap?
- Should the migration advice differ? (Drop-in: carry forward. Full shadow: review whether the customization is still needed.)

---

## 12. Legacy Compatibility

**Section type:** kitchen-sink only, enriches multiple sections

**What to plant:**
- SysVinit scripts in `/etc/init.d/` with no matching systemd unit
- `ifcfg-*` network config files (deprecated in favor of NM keyfiles on RHEL 9+)
- xinetd configs in `/etc/xinetd.d/`
- anacrontab, cron.allow/cron.deny files

**What inspectah detects:** inspectah would detect these as config files, but may not flag the "this is a legacy pattern that should be modernized" advisory. The migration story: these are the artifacts of systems upgraded through multiple RHEL versions.

**Profile tier:** kitchen-sink only (stress test scenario)

**Source:** Ember — "A system upgraded from RHEL 7→8→9 is the hardest migration target and the most valuable one to demonstrate."

**Open questions:**
- Should inspectah produce modernization advisories (e.g., "convert ifcfg to keyfile")?
- Is this a driftify section or scattered across existing sections?
- How realistic is it to have SysVinit scripts on a RHEL 9 system? (More common than people admit.)

---

## 13. ld.so.conf.d Custom Library Paths

**Section type:** Enrich config section

**What to plant:**
- (kitchen-sink) Drop-in at `/etc/ld.so.conf.d/myapp.conf` pointing to `/opt/myapp/lib`. Run `ldconfig` to rebuild cache.

**What inspectah detects:** inspectah classifies `ConfigCategory::LibraryPath` for `/etc/ld.so.conf.d/` — driftify never creates any, so that path is untested. Migration impact: the linker cache at `/etc/ld.so.cache` must be regenerated at image build time if custom paths are baked in.

**Profile tier:** kitchen-sink (Oracle, IBM tools, third-party software)

**Source:** Collins — "Custom library paths are common for third-party software."

**Open questions:**
- Does the Containerfile renderer emit `ldconfig` after custom ld.so.conf.d entries?
- Should this pair with an actual binary in /opt that uses the custom lib path?

---

## 14. Host Identity References

**Section type:** Enrich config section, kitchen-sink

**What to plant:**
- (kitchen-sink) `/etc/hostname` with custom hostname, `/etc/machine-info` with custom fields. Config files that embed the hostname or machine-id value.

**What inspectah detects:** inspectah could flag configs that contain the current hostname/machine-id as "stale after reprovisioning." In image mode, machine-id regenerates per deployment — any config referencing the old one carries stale values.

**Profile tier:** kitchen-sink (edge case, nasty when it hits)

**Source:** Collins — "When it bites, it's confusing to debug."

**Open questions:**
- Is machine-id reference detection realistic? (Searching all config files for a UUID pattern?)
- Is this worth the implementation cost vs. the rarity of the issue?
- Should this just be a migration advisory rather than a finding?

---

## 15. Application State Directories

**Section type:** Enrich storage section

**What to plant:**
- (standard) Database data directories: `/var/lib/pgsql/data/` and `/var/lib/mysql/` with proper ownership and permissions. App log rotation: logrotate configs for app-specific logs. Temp and cache: `/var/cache/myapp/`, tmpfiles.d entries.

**What inspectah detects:** inspectah already handles storage, but richer state directories with proper ownership patterns would make demos more realistic. Connects to item #4 (tmpfiles.d backing).

**Profile tier:** standard

**Source:** Ember — "richer state directories would make the demo more realistic."

**Open questions:**
- How much does this overlap with item #4 (tmpfiles.d)?
- Should database dirs be real (install PostgreSQL) or fake (just mkdir)?
- Is this worth a dedicated effort or does it naturally come with other items?

---

## 16. FIPS Mode

**Section type:** Enrich kernel section

**What to plant:**
- (standard) Plant `/etc/system-fips`, GRUB arg `fips=1`. Full enablement requires reboot, so driftify may only plant config files.

**What inspectah detects:** inspectah already has `fips_mode: bool` in its data model. Driftify should exercise this detection.

**Profile tier:** standard (FIPS is required in government and financial services)

**Source:** Collins — "FIPS is a cross-cutting concern touching kernel cmdline, crypto policies, and OpenSSL."

**Open questions:**
- FLAGGED: closely related to crypto-policies. Testing concerns — figure out approach.
- Can we plant the FIPS indicator files without actually enabling FIPS mode (which changes system behavior)?
- If planting fips=1 in GRUB without rebooting, does inspectah detect FIPS as "configured but not active"?

---

## Appendix A: Explicitly Deprioritized (Ember)

These were considered and rejected by Ember:

- **Hardware-specific device drivers** — too hard to simulate on VMs, not relevant to image-mode story (drivers come from base image)
- **Desktop/GUI state** — RHEL 11 image mode is server-first. Not relevant to the migration story.
- **Cloud-init / cloud-specific configs** — important but better as an inspectah detection enhancement than driftify drift
- **More secret patterns** — current secret fixtures (AWS keys, PEM blocks, DB strings, PATs, .env files) are already solid. Diminishing returns.

## Appendix B: Out of Scope for Driftify (Collins)

- **Layered RPMs on bootc systems** (Collins #11) — testing inspectah-on-image-mode (audit drift FROM base image). Requires actual bootc system, can't be tested on package-mode VM. Worth noting as a gap in the overall test matrix but outside driftify's scope.

## Appendix C: Strategic Framing

**Ember's meta-insight:** "The single biggest positioning gap is that driftify-generated systems don't look like enterprise RHEL. They look like dev boxes with extra packages. A real production RHEL system is domain-joined, has subscription state, runs monitoring agents, has custom internal repos, and carries performance tuning."

**Ember's profile philosophy:** minimal = CI-fast. standard = "looks like a real production server." kitchen-sink = "looks like a server that has been running since RHEL 7."

**Collins's meta-insight:** "Driftify currently exercises inspectah's *detection* of what's on the system, but doesn't plant drift that tests inspectah's ability to *advise on image-mode feasibility*. The gaps are all things where the migration recommendation changes depending on which filesystem layer the drift lives in."

**Collins's layer priority:** The most critical gaps are those where the package→image filesystem model change creates real surprises: /var dirs vanishing (no tmpfiles.d), /usr files invisible (composefs), /etc merge breaking (cross-tree symlinks, PAM, full unit shadows).
