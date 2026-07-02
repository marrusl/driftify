# Driftify Extended Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 8 new drift categories to driftify, enriching existing sections with enterprise-realistic drift patterns and EL8+ platform support.

**Architecture:** All changes are in the single `driftify.py` file. Each task enriches existing `drift_*()` methods following the established pattern: profile gating via `self.needs_profile()`, file creation via `self._write_managed_text()`, commands via `self.run_cmd()`, OS gating via `self.os_id` and `self.os_major`. The method `_is_fedora()` (private, with underscore) is the existing Fedora check.

**Tech Stack:** Python 3 (stdlib-only, no pip dependencies)

**Spec:** `docs/specs/driftify-extended-findings-design.md` (approved R3)

## Global Constraints

- Single-file, stdlib-only Python 3. No pip dependencies.
- `--dry-run` must be respected for every operation.
- OS auto-detection via `/etc/os-release`. EL8, EL9, EL10, and Fedora supported.
- All `drift_*()` changes must be idempotent (safe to run twice).
- Profile gating: `self.needs_profile("standard")` / `self.needs_profile("kitchen-sink")`.
- No new driftify sections — all additions enrich existing sections.
- Use `self._is_fedora()` (existing private method), not `self.is_fedora`.
- Execution order: `drift_rpm` → `drift_services` → `drift_config` → `drift_network` → `drift_storage` → `drift_users` → `drift_scheduled` → `drift_containers` → `drift_kernel` → `drift_selinux` → `drift_nonrpm` → `drift_secrets`. Code that depends on users/groups created in `drift_users()` must handle missing principals gracefully since `drift_config()` and `drift_storage()` run first.
- On EL8 (systemd 239): avoid `D` (cleanup) tmpfiles.d type — use `d` (create) only. Avoid tmpfiles.d directives added in systemd 240+.
- Commit format: `feat(driftify): <description>` with `Assisted-by: Claude Code (<model>)`.

---

### Task 1: EL8 Platform Support

**Files:**
- Modify: `driftify.py` — `detect_os()` function (~line 391), class properties, `--help` text, tmpfiles.d EL8 guard

**Interfaces:**
- Produces: `self.os_major` values of 8, 9, or 10 for RHEL/CentOS; `self.is_el8` property; `self._try_install()` helper; `self._tmpfiles_safe(directive)` helper

- [ ] **Step 1: Modify `detect_os()` to accept EL8**

In `detect_os()` (~line 416), change the version guard:

```python
elif os_id not in ("rhel", "centos") or os_major not in (8, 9, 10):
    _warn(f"Detected {os_id} {version_id} — driftify targets RHEL/CentOS Stream 8/9/10 or Fedora")
```

- [ ] **Step 2: Add `is_el8` property and `_try_install()` helper**

After the existing `_is_fedora()` method (~line 1239):

```python
@property
def is_el8(self) -> bool:
    return self.os_id in ("rhel", "centos") and self.os_major == 8

def _try_install(self, packages: list, label: str = "") -> bool:
    """Install packages if available, skip gracefully if not."""
    if self.dry_run:
        _dry(f"dnf install -y {' '.join(packages)}")
        return True
    result = self.run_cmd(
        ["dnf", "install", "-y", "--skip-unavailable"] + packages,
        check=False,
    )
    if result is not None and result.returncode != 0:
        _warn(f"Some packages unavailable{f' ({label})' if label else ''} — skipping")
        return False
    return True
```

- [ ] **Step 3: Add tmpfiles.d EL8 compatibility helper**

```python
def _el8_safe_tmpfiles(self, directive: str) -> str:
    """On EL8 (systemd 239), replace unsupported tmpfiles.d directives.

    - 'D' (create-or-cleanup) → 'd' (create only) on EL8
    - Age-based cleanup (e.g. '30d') → '-' (no cleanup) on EL8
    """
    if not self.is_el8:
        return directive
    # Replace 'D' type with 'd' — systemd 239 supports 'd' but 'D'
    # cleanup behavior may differ
    if directive.startswith("D "):
        directive = "d" + directive[1:]
    return directive
```

- [ ] **Step 4: Update README and `--help` for EL8**

In the README `## Requirements > Supported platforms` section, add:
```
- RHEL 8.x / CentOS Stream 8
```

In the argparse help text (~line 3170), update the description:

```python
description="Apply synthetic drift to a RHEL/CentOS Stream 8/9/10 or Fedora system"
```

- [ ] **Step 5: Verify**

Run: `sudo ./driftify.py --help 2>&1 | head -5`
Expected: description mentions 8/9/10.

Run: `sudo ./driftify.py --dry-run --profile standard 2>&1 | head -20`
Expected: no unsupported-platform error on EL8.

- [ ] **Step 6: Commit**

```bash
git add driftify.py README.md
git commit -m "feat(driftify): add EL8 platform support with tmpfiles.d compat"
```

---

### Task 2: Auth & Identity Infrastructure

**Files:**
- Modify: `driftify.py` — `drift_users()` method and `drift_config()` method

**Interfaces:**
- Consumes: `self.needs_profile()`, `self._write_managed_text()`, `self.run_cmd()`, `self._ensure_dir()`
- Produces: IPA/SSSD/PAM artifacts on disk for inspectah to detect

- [ ] **Step 1: Add IPA/SSSD artifacts to `drift_users()` at standard tier**

After the existing standard-tier user creation block in `drift_users()`:

```python
        if self.needs_profile("standard"):
            # ... (existing user creation code above) ...

            # Identity infrastructure: IPA client enrollment artifacts
            _info(f"{_I.SHIELD}  Planting IPA client enrollment artifacts")
            self._ensure_dir(Path("/etc/ipa"))
            self._write_managed_text(
                "/etc/ipa/ca.crt",
                "-----BEGIN CERTIFICATE-----\n"
                "MIIDfTCCAmWgAwIBAgIJAKDriftifyFakeCA0DQELBQAwXzELMAkGA1UE\n"
                "BhMCVVMxDTALBgNVBAoMBERFTU8xGDAWBgNVBAsMD0RyaWZ0aWZ5IFRl\n"
                "c3QgQ0ExEzARBgNVBAMMCmlwYS5sb2NhbA==\n"
                "-----END CERTIFICATE-----\n",
            )
            self._ensure_dir(Path("/var/lib/ipa-client/sysrestore"))
            self._write_managed_text(
                "/var/lib/ipa-client/sysrestore/sysrestore.state",
                "[authconfig]\nprofile = sssd\n",
            )

            # Kerberos keytab (synthetic, non-functional)
            self._write_managed_text(
                "/etc/krb5.keytab",
                "# Synthetic keytab — driftify fixture\n"
                "# inspectah should detect keytab presence\n",
            )

            # SSSD config
            self._ensure_dir(Path("/etc/sssd"))
            self._write_managed_text(
                "/etc/sssd/sssd.conf",
                "[sssd]\n"
                "services = nss, pam, sudo\n"
                "domains = ipa.local\n"
                "config_file_version = 2\n\n"
                "[domain/ipa.local]\n"
                "id_provider = ipa\n"
                "auth_provider = ipa\n"
                "ipa_server = ipa.local\n"
                "ipa_domain = ipa.local\n",
            )
            if not self.dry_run:
                Path("/etc/sssd/sssd.conf").chmod(0o600)

            # SSSD cache dirs
            for d in ("db", "mc", "pipes", "pipes/private"):
                self._ensure_dir(Path(f"/var/lib/sss/{d}"))
```

- [ ] **Step 2: Add PAM artifacts to `drift_config()` at standard tier**

```python
            # PAM faillock config
            _info(f"{_I.SHIELD}  Planting PAM faillock config")
            self._write_managed_text(
                "/etc/security/faillock.conf",
                "# PAM faillock — driftify synthetic fixture\n"
                "deny = 5\n"
                "unlock_time = 900\n"
                "fail_interval = 900\n"
                "audit\n"
                "even_deny_root\n",
            )

            # Custom PAM drop-in (exercises inspectah pam_configs collection)
            _info(f"{_I.SHIELD}  Planting custom PAM config")
            self._write_managed_text(
                "/etc/pam.d/custom-sshd",
                "#%PAM-1.0\n"
                "# Custom SSH PAM stack — driftify fixture\n"
                "auth       required     pam_sepermit.so\n"
                "auth       substack     password-auth\n"
                "auth       required     pam_faillock.so preauth\n"
                "account    required     pam_nologin.so\n"
                "account    include      password-auth\n"
                "password   include      password-auth\n"
                "session    required     pam_loginuid.so\n"
                "session    include      password-auth\n",
            )

            # authselect: run if available, plant files directly if not
            import shutil as _shutil_authselect
            if _shutil_authselect.which("authselect"):
                _info(f"{_I.SHIELD}  Setting authselect profile to sssd")
                self.run_cmd(
                    ["authselect", "select", "sssd", "with-faillock", "--force"],
                    check=False,
                )
            else:
                _info(f"{_I.SHIELD}  authselect not found — planting profile files directly")
                self._ensure_dir(Path("/etc/authselect"))
                self._write_managed_text(
                    "/etc/authselect/authselect.conf",
                    "profile-id = sssd\n"
                    "features = with-faillock\n",
                )
```

- [ ] **Step 3: Add kitchen-sink AD/winbind artifacts to `drift_users()`**

```python
        if self.needs_profile("kitchen-sink"):
            _info(f"{_I.SHIELD}  Planting AD/winbind artifacts")
            self._ensure_dir(Path("/etc/samba"))
            self._write_managed_text(
                "/etc/samba/smb.conf",
                "[global]\n"
                "workgroup = DRIFTIFY\n"
                "realm = AD.DRIFTIFY.LOCAL\n"
                "security = ads\n"
                "kerberos method = secrets and keytab\n"
                "template shell = /bin/bash\n"
                "template homedir = /home/%U\n"
                "idmap config * : backend = tdb\n"
                "idmap config * : range = 10000-999999\n\n"
                "# Winbind/SSSD hybrid — driftify fixture\n"
                "[homes]\n"
                "browseable = no\n"
                "writable = yes\n",
            )

            # Machine keytab for AD join
            self._write_managed_text(
                "/etc/krb5.keytab.ad",
                "# AD machine keytab — driftify fixture\n"
                "# Synthetic keytab for AD-joined host\n",
            )

            self._ensure_dir(Path("/etc/openldap/certs"))
            self._write_managed_text(
                "/etc/openldap/certs/ldap-client.pem",
                "-----BEGIN CERTIFICATE-----\n"
                "MIICfTCCAeagAwIBAgIJAKDriftifyFakeLDAP\n"
                "-----END CERTIFICATE-----\n",
            )

            # Winbind/SSSD hybrid: SSSD config referencing AD domain
            self._write_managed_text(
                "/etc/sssd/conf.d/ad-domain.conf",
                "[domain/ad.driftify.local]\n"
                "id_provider = ad\n"
                "auth_provider = ad\n"
                "ad_server = dc.ad.driftify.local\n"
                "ad_domain = ad.driftify.local\n"
                "ldap_id_mapping = true\n"
                "fallback_homedir = /home/%u@%d\n",
            )
            if not self.dry_run:
                Path("/etc/sssd/conf.d/ad-domain.conf").chmod(0o600)
```

- [ ] **Step 4: Verify**

Run: `sudo ./driftify.py --dry-run --profile kitchen-sink 2>&1 | grep -iE 'ipa|pam|sssd|authselect|winbind|AD|keytab|hybrid'`
Expected: log lines for all planted artifacts including PAM drop-in, authselect fallback, machine keytab, hybrid config.

- [ ] **Step 5: Commit**

```bash
git add driftify.py
git commit -m "feat(driftify): add auth & identity infrastructure drift"
```

---

### Task 3: tmpfiles.d + /var State Gaps

**Files:**
- Modify: `driftify.py` — `drift_config()` method and `drift_storage()` method

**Interfaces:**
- Consumes: `self._write_managed_text()`, `self._ensure_dir()`, `self._el8_safe_tmpfiles()`
- Produces: tmpfiles.d entries + hand-created /var dirs (with and without backing)

**Dependency note:** `drift_config()` runs before `drift_users()` in the execution order. The `appone` tmpfiles.d entry references `appuser:appgroup` which won't exist yet. The ownership chown uses a try/except KeyError to handle this gracefully — the dir is created with root ownership, and `drift_users()` can fix ownership later if needed. The tmpfiles.d *entry text* is correct regardless (it declares the intended owner).

- [ ] **Step 1: Add tmpfiles.d fixtures to `drift_config()` at standard tier**

```python
            # tmpfiles.d fixtures: exercises ConfigCategory::Tmpfiles
            _info(f"{_I.FILE}  Planting tmpfiles.d drop-ins")
            self._write_managed_text(
                "/etc/tmpfiles.d/appone.conf",
                "# tmpfiles.d — driftify fixture (backed dir)\n"
                + self._el8_safe_tmpfiles(
                    "d /var/lib/appone/cache 0750 appuser appgroup 30d\n"
                ),
            )
            self._write_managed_text(
                "/etc/tmpfiles.d/cleanup.conf",
                "# tmpfiles.d — driftify fixture (volatile runtime dir)\n"
                + self._el8_safe_tmpfiles(
                    "D /run/myapp 0755 root root -\n"
                ),
            )
            # Create the dir that tmpfiles.d would manage
            self._ensure_dir(Path("/var/lib/appone/cache"))
            if not self.dry_run:
                try:
                    import pwd, grp
                    uid = pwd.getpwnam("appuser").pw_uid
                    gid = grp.getgrnam("appgroup").gr_gid
                    os.chown("/var/lib/appone/cache", uid, gid)
                    os.chmod("/var/lib/appone/cache", 0o750)
                except KeyError:
                    # appuser/appgroup not yet created (drift_users runs later)
                    # tmpfiles.d entry text is still correct
                    pass
```

- [ ] **Step 2: Add unbacked /var dirs to `drift_storage()` at standard tier**

```python
        if self.needs_profile("standard"):
            # Hand-created /var dirs WITHOUT any backing mechanism
            # inspectah should flag these as unbacked — advisory
            _info(f"{_I.FOLDER}  Creating unbacked /var app directories")
            for d in [
                "/var/lib/pgsql/data",
                "/var/log/myapp",
                "/var/cache/myapp",
            ]:
                self._ensure_dir(Path(d))

            # Ownership on pgsql data dir (postgres user may not exist yet)
            if not self.dry_run:
                try:
                    import pwd
                    pw = pwd.getpwnam("postgres")
                    os.chown("/var/lib/pgsql/data", pw.pw_uid, pw.pw_gid)
                except KeyError:
                    pass  # postgres user not installed — dir stays root-owned
            else:
                _dry("chown postgres:postgres /var/lib/pgsql/data")
```

- [ ] **Step 3: Add kitchen-sink tmpfiles.d + mixed /var fixtures**

In `drift_config()`, kitchen-sink block:

```python
        if self.needs_profile("kitchen-sink"):
            # tmpfiles.d with age-based cleanup on persistent dirs
            _info(f"{_I.FILE}  Planting kitchen-sink tmpfiles.d fixtures")
            self._write_managed_text(
                "/etc/tmpfiles.d/apptwo-cleanup.conf",
                "# tmpfiles.d — driftify fixture (persistent dir with cleanup)\n"
                + self._el8_safe_tmpfiles(
                    "d /var/lib/apptwo/sessions 0755 root root 7d\n"
                )
                + self._el8_safe_tmpfiles(
                    "d /var/lib/apptwo/cache 0755 root root 1d\n"
                ),
            )
            self._ensure_dir(Path("/var/lib/apptwo/sessions"))
            self._ensure_dir(Path("/var/lib/apptwo/cache"))
```

In `drift_storage()`, kitchen-sink block:

```python
        if self.needs_profile("kitchen-sink"):
            # Nested /var tree with mixed backing:
            # /var/lib/mixed-app/ — has tmpfiles.d
            # /var/lib/mixed-app/data/ — has tmpfiles.d
            # /var/lib/mixed-app/data/uploads/ — NO backing (hand-created)
            # /var/lib/mixed-app/data/uploads/tmp/ — NO backing (hand-created)
            _info(f"{_I.FOLDER}  Creating mixed-backing /var directory tree")
            for d in [
                "/var/lib/mixed-app",
                "/var/lib/mixed-app/data",
                "/var/lib/mixed-app/data/uploads",
                "/var/lib/mixed-app/data/uploads/tmp",
            ]:
                self._ensure_dir(Path(d))
```

And add the corresponding tmpfiles.d entries for the backed levels in `drift_config()` kitchen-sink:

```python
            self._write_managed_text(
                "/etc/tmpfiles.d/mixed-app.conf",
                "# tmpfiles.d — driftify fixture (mixed backing)\n"
                "d /var/lib/mixed-app 0755 root root -\n"
                "d /var/lib/mixed-app/data 0755 root root -\n"
                "# /var/lib/mixed-app/data/uploads/ intentionally unbacked\n",
            )
```

- [ ] **Step 4: Verify**

Run: `sudo ./driftify.py --dry-run --profile kitchen-sink 2>&1 | grep -iE 'tmpfiles|unbacked|appone|mixed|apptwo'`
Expected: log lines for all tmpfiles.d and /var fixtures at both tiers.

- [ ] **Step 5: Commit**

```bash
git add driftify.py
git commit -m "feat(driftify): add tmpfiles.d and unbacked /var state fixtures"
```

---

### Task 4: Files in /usr

**Files:**
- Modify: `driftify.py` — `drift_nonrpm()` method

**Interfaces:**
- Consumes: `self._write_managed_text()`, `self._ensure_dir()`, `self.needs_profile()`
- Produces: Non-RPM files in RPM-owned /usr paths

- [ ] **Step 1: Add /usr file fixtures to `drift_nonrpm()` at standard tier**

```python
        if self.needs_profile("standard"):
            # ... (existing standard non-RPM code) ...

            # Files in RPM-owned /usr tree (image-mode violation)
            _info(f"{_I.WARN}  Planting non-RPM files in /usr (image-mode violation fixtures)")
            self._write_managed_text(
                "/usr/bin/custom-tool",
                "#!/bin/bash\n"
                "# Non-RPM script in /usr/bin — driftify fixture\n"
                "# In image mode, /usr is read-only (composefs). This file\n"
                "# must be COPY'd into the image at build time.\n"
                'echo "custom-tool running"\n',
            )
            if not self.dry_run:
                os.chmod("/usr/bin/custom-tool", 0o755)

            self._write_managed_text(
                "/usr/lib/systemd/system/myapp.service",
                "[Unit]\n"
                "Description=Custom App Service (driftify fixture)\n"
                "After=network.target\n\n"
                "[Service]\n"
                "Type=simple\n"
                "ExecStart=/usr/bin/custom-tool\n"
                "Restart=on-failure\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n",
            )

            self._ensure_dir(Path("/usr/share/myapp"))
            self._write_managed_text(
                "/usr/share/myapp/config.default",
                "# Shared data — driftify fixture\n"
                "default_timeout=30\n",
            )
            self._write_managed_text(
                "/usr/share/myapp/templates.json",
                '{"version": 1, "templates": ["base", "extended"]}\n',
            )
```

- [ ] **Step 2: Add deeper /usr fixtures at kitchen-sink tier**

```python
        if self.needs_profile("kitchen-sink"):
            _info(f"{_I.WARN}  Planting deep /usr fixtures (kitchen-sink)")
            self._write_managed_text(
                "/usr/sbin/custom-daemon",
                "#!/bin/bash\n# Daemon stub — driftify fixture\nexit 0\n",
            )
            if not self.dry_run:
                os.chmod("/usr/sbin/custom-daemon", 0o755)

            # Stub library in /usr/lib64
            self._write_managed_text(
                "/usr/lib64/libcustom.so",
                "# Stub .so — driftify fixture\n"
                "# Not a real ELF binary; exercises /usr unmanaged file detection\n",
            )

            # Helper script at spec-exact path
            self._write_managed_text(
                "/usr/libexec/myapp-helper",
                "#!/bin/bash\n# Helper script — driftify fixture\nexit 0\n",
            )
            if not self.dry_run:
                os.chmod("/usr/libexec/myapp-helper", 0o755)
```

- [ ] **Step 3: Verify**

Run: `sudo ./driftify.py --dry-run --profile kitchen-sink 2>&1 | grep '/usr/'`
Expected: log lines for `/usr/bin/custom-tool`, `/usr/lib/systemd/system/myapp.service`, `/usr/share/myapp/`, `/usr/sbin/custom-daemon`, `/usr/lib64/libcustom.so`, `/usr/libexec/myapp-helper`.

- [ ] **Step 4: Commit**

```bash
git add driftify.py
git commit -m "feat(driftify): add non-RPM files in /usr fixtures"
```

---

### Task 5: Performance Tuning Depth

**Files:**
- Modify: `driftify.py` — `drift_kernel()` method

**Interfaces:**
- Consumes: `self._write_managed_text()`, `self._ensure_dir()`, `self._append_kernel_cmdline_arg()`
- Produces: Custom tuned profiles, hugepage sysctl, THP disable, CPU isolation GRUB args

- [ ] **Step 1: Add custom tuned profile + hugepages + THP at standard tier**

In `drift_kernel()`, in the standard block:

```python
            # Custom tuned profile directory
            _info(f"{_I.LINUX}  Creating custom tuned profile")
            self._ensure_dir(Path("/etc/tuned/myapp"))
            self._write_managed_text(
                "/etc/tuned/myapp/tuned.conf",
                "[main]\n"
                "summary=Custom app server profile — driftify fixture\n"
                "include=throughput-performance\n\n"
                "[sysctl]\n"
                "vm.dirty_ratio=15\n"
                "vm.dirty_background_ratio=5\n\n"
                "[disk]\n"
                "readahead=>4096\n\n"
                "[cpu]\n"
                "governor=performance\n"
                "energy_perf_bias=performance\n",
            )

            # Hugepages sysctl
            self._write_managed_text(
                "/etc/sysctl.d/hugepages.conf",
                "# Hugepages — driftify fixture\n"
                "vm.nr_hugepages = 128\n",
            )
            self.run_cmd(
                ["sysctl", "-p", "/etc/sysctl.d/hugepages.conf"],
                check=False,
            )

            # Disable transparent hugepages: live runtime change + persisted config
            _info(f"{_I.LINUX}  Disabling transparent hugepages")
            thp_path = "/sys/kernel/mm/transparent_hugepage/enabled"
            if not self.dry_run:
                try:
                    with open(thp_path, "w") as f:
                        f.write("never")
                except (OSError, IOError):
                    _warn(f"Could not write to {thp_path}")
            else:
                _dry(f"echo never > {thp_path}")
            # Persist via GRUB arg
            self._append_kernel_cmdline_arg("transparent_hugepage=never")
            # Also persist via sysctl for the defrag side
            self._write_managed_text(
                "/etc/sysctl.d/thp.conf",
                "# Disable THP defrag — driftify fixture\n"
                "vm.compaction_proactiveness = 0\n",
            )
```

- [ ] **Step 2: Add CPU isolation + IRQ affinity at kitchen-sink tier**

```python
        if self.needs_profile("kitchen-sink"):
            _info(f"{_I.LINUX}  Adding CPU isolation GRUB args")
            self._append_kernel_cmdline_arg(
                "isolcpus=2-3 nohz_full=2-3 rcu_nocbs=2-3"
            )

            self._write_managed_text(
                "/etc/sysconfig/irqbalance",
                '# IRQ affinity — driftify fixture\n'
                'IRQBALANCE_BANNED_CPULIST=2-3\n'
                '#IRQBALANCE_ARGS=\n',
            )

            self._write_managed_text(
                "/etc/sysctl.d/numa.conf",
                "# NUMA tuning — driftify fixture\n"
                "vm.zone_reclaim_mode = 1\n",
            )
            self.run_cmd(
                ["sysctl", "-p", "/etc/sysctl.d/numa.conf"],
                check=False,
            )

            self._write_managed_text(
                "/etc/udev/rules.d/60-scheduler.rules",
                '# Disk scheduler — driftify fixture\n'
                'ACTION=="add|change", KERNEL=="sd[a-z]", '
                'ATTR{queue/scheduler}="mq-deadline"\n',
            )
```

- [ ] **Step 3: Verify**

Run: `sudo ./driftify.py --dry-run --profile kitchen-sink 2>&1 | grep -iE 'tuned|hugepage|transparent|thp|isolation|irq|numa|scheduler'`

- [ ] **Step 4: Commit**

```bash
git add driftify.py
git commit -m "feat(driftify): add performance tuning depth fixtures"
```

---

### Task 6: Logging & Monitoring

**Files:**
- Modify: `driftify.py` — `drift_config()`, `drift_services()`, and `drift_rpm()` methods

**Interfaces:**
- Consumes: `self._write_managed_text()`, `self.run_cmd()`, `self._try_install()`
- Produces: rsyslog, journald, node_exporter, AIDE fixtures

- [ ] **Step 1: Add rsyslog + journald to `drift_config()` at standard tier**

```python
            # rsyslog forwarding
            _info(f"{_I.FILE}  Planting rsyslog forwarding config")
            self._ensure_dir(Path("/etc/rsyslog.d"))
            self._write_managed_text(
                "/etc/rsyslog.d/forward-to-siem.conf",
                "# Remote log forwarding — driftify fixture\n"
                "*.* @@siem.internal.example.com:514\n",
            )

            # journald customization
            _info(f"{_I.FILE}  Planting custom journald config")
            self._ensure_dir(Path("/etc/systemd/journald.conf.d"))
            self._write_managed_text(
                "/etc/systemd/journald.conf.d/custom.conf",
                "[Journal]\n"
                "Storage=persistent\n"
                "SystemMaxUse=2G\n"
                "RateLimitIntervalSec=60s\n"
                "RateLimitBurst=10000\n",
            )
```

- [ ] **Step 2: Add node_exporter to `drift_rpm()` + `drift_services()`**

In `drift_rpm()` at standard tier:

```python
            self._try_install(
                ["golang-github-prometheus-node_exporter"],
                label="node_exporter",
            )
```

In `drift_services()` at standard tier:

```python
            _info(f"{_I.TOGGLE}  Enabling node_exporter")
            self.run_cmd(
                ["systemctl", "enable", "node_exporter"],
                check=False,
            )
```

- [ ] **Step 3: Add AIDE with custom config + logrotate + auditd at kitchen-sink tier**

In `drift_rpm()` kitchen-sink:

```python
        if self.needs_profile("kitchen-sink"):
            self._try_install(["aide"], label="AIDE")
```

In `drift_config()` kitchen-sink:

```python
        if self.needs_profile("kitchen-sink"):
            # AIDE config with custom rules
            _info(f"{_I.SHIELD}  Planting custom AIDE config and initializing")
            self._write_managed_text(
                "/etc/aide.conf",
                "# AIDE config — driftify fixture\n"
                "@@define DBDIR /var/lib/aide\n"
                "@@define LOGDIR /var/log/aide\n"
                "database_in=file:@@{DBDIR}/aide.db.gz\n"
                "database_out=file:@@{DBDIR}/aide.db.new.gz\n"
                "database_new=file:@@{DBDIR}/aide.db.new.gz\n"
                "gzip_dbout=yes\n\n"
                "# Custom rules — driftify fixture\n"
                "DRIFTIFY_WEB = p+u+g+sha256\n"
                "/var/www DRIFTIFY_WEB\n"
                "/opt/myapp DRIFTIFY_WEB\n\n"
                "# Standard rules\n"
                "/etc NORMAL\n"
                "/boot NORMAL\n",
            )
            import shutil as _shutil_aide
            if _shutil_aide.which("aide"):
                self.run_cmd(["aide", "--init"], check=False)
                if not self.dry_run and Path("/var/lib/aide/aide.db.new.gz").exists():
                    self.run_cmd(
                        ["cp", "/var/lib/aide/aide.db.new.gz",
                         "/var/lib/aide/aide.db.gz"],
                        check=False,
                    )
            else:
                _warn("aide not found — skipping AIDE init")

            # Custom logrotate
            self._write_managed_text(
                "/etc/logrotate.d/myapp",
                "/var/log/myapp/*.log {\n"
                "    daily\n"
                "    rotate 14\n"
                "    compress\n"
                "    missingok\n"
                "    notifempty\n"
                "    create 0640 root root\n"
                "}\n",
            )

            # Custom auditd rules
            self._ensure_dir(Path("/etc/audit/rules.d"))
            self._write_managed_text(
                "/etc/audit/rules.d/custom.rules",
                "# Custom audit rules — driftify fixture\n"
                "-w /etc/shadow -p wa -k shadow-changes\n"
                "-w /etc/passwd -p wa -k passwd-changes\n"
                "-w /etc/sudoers -p wa -k sudoers-changes\n",
            )
```

- [ ] **Step 4: Verify**

Run: `sudo ./driftify.py --dry-run --profile kitchen-sink 2>&1 | grep -iE 'rsyslog|journald|node_exporter|aide|logrotate|audit'`
Expected: lines for all logging/monitoring artifacts including `/etc/aide.conf`.

- [ ] **Step 5: Commit**

```bash
git add driftify.py
git commit -m "feat(driftify): add logging and monitoring fixtures"
```

---

### Task 7: Cross-tree Symlinks

**Files:**
- Modify: `driftify.py` — `drift_config()` method

**Interfaces:**
- Consumes: `self._ensure_dir()`, `self._write_managed_text()`
- Produces: Symlinks crossing /etc → /var and /opt → /usr boundaries

- [ ] **Step 1: Add cross-tree symlinks at standard tier**

In `drift_config()`, standard block:

```python
            # Cross-tree symlinks (exercises inspectah advisory)
            _info(f"{_I.LINK}  Creating cross-tree symlinks")
            # /etc -> /var: config externalized to persistent storage
            self._ensure_dir(Path("/var/lib/mydb"))
            self._write_managed_text(
                "/var/lib/mydb/config.yaml",
                "# Database config — lives in /var (persistent)\n"
                "host: localhost\n"
                "port: 5432\n"
                "max_connections: 100\n",
            )
            self._ensure_dir(Path("/etc/mydb"))
            if not self.dry_run:
                link = Path("/etc/mydb/config.yaml")
                if not link.exists():
                    link.symlink_to("/var/lib/mydb/config.yaml")
                    _sub("Created /etc/mydb/config.yaml -> /var/lib/mydb/config.yaml")
            else:
                _dry("ln -s /var/lib/mydb/config.yaml /etc/mydb/config.yaml")

            # /opt -> /usr: application linking into immutable tree
            self._ensure_dir(Path("/usr/lib64/myapp"))
            self._write_managed_text(
                "/usr/lib64/myapp/libhelper.so",
                "# Stub library — driftify fixture\n",
            )
            self._ensure_dir(Path("/opt/myapp"))
            if not self.dry_run:
                link = Path("/opt/myapp/lib")
                if not link.exists():
                    link.symlink_to("/usr/lib64/myapp")
                    _sub("Created /opt/myapp/lib -> /usr/lib64/myapp/")
            else:
                _dry("ln -s /usr/lib64/myapp /opt/myapp/lib")
```

- [ ] **Step 2: Add kitchen-sink symlinks including nested chain**

```python
        if self.needs_profile("kitchen-sink"):
            # TLS certs externalized to /var (spec path: /etc/app/ssl)
            self._ensure_dir(Path("/var/lib/app/ssl"))
            self._write_managed_text(
                "/var/lib/app/ssl/cert.pem",
                "-----BEGIN CERTIFICATE-----\n"
                "MIICfTCCAeagAwIBAgIJAKDriftifyFakeTLS\n"
                "-----END CERTIFICATE-----\n",
            )
            self._ensure_dir(Path("/etc/app"))
            if not self.dry_run:
                link = Path("/etc/app/ssl")
                if not link.exists():
                    link.symlink_to("/var/lib/app/ssl")
                    _sub("Created /etc/app/ssl -> /var/lib/app/ssl/")
            else:
                _dry("ln -s /var/lib/app/ssl /etc/app/ssl")

            # Nested symlink chain: /opt -> /usr/local -> /usr
            _info(f"{_I.LINK}  Creating nested symlink chain")
            self._write_managed_text(
                "/usr/bin/actual-tool",
                "#!/bin/bash\necho 'actual-tool'\n",
            )
            if not self.dry_run:
                os.chmod("/usr/bin/actual-tool", 0o755)
                # /usr/local/bin/run-tool -> /usr/bin/actual-tool
                link1 = Path("/usr/local/bin/run-tool")
                if not link1.exists():
                    self._ensure_dir(Path("/usr/local/bin"))
                    link1.symlink_to("/usr/bin/actual-tool")
                    _sub("Created /usr/local/bin/run-tool -> /usr/bin/actual-tool")
                # /opt/tool/bin/run -> /usr/local/bin/run-tool
                self._ensure_dir(Path("/opt/tool/bin"))
                link2 = Path("/opt/tool/bin/run")
                if not link2.exists():
                    link2.symlink_to("/usr/local/bin/run-tool")
                    _sub("Created /opt/tool/bin/run -> /usr/local/bin/run-tool")
            else:
                _dry("ln -s /usr/bin/actual-tool /usr/local/bin/run-tool")
                _dry("ln -s /usr/local/bin/run-tool /opt/tool/bin/run")
```

- [ ] **Step 3: Verify**

Run: `sudo ./driftify.py --dry-run --profile kitchen-sink 2>&1 | grep -iE 'symlink|ln -s|chain'`
Expected: log lines for all 5 symlinks: mydb, myapp/lib, app/ssl, run-tool, opt/tool.

- [ ] **Step 4: Commit**

```bash
git add driftify.py
git commit -m "feat(driftify): add cross-tree symlink fixtures"
```

---

### Task 8: systemd Unit Shadows

**Files:**
- Modify: `driftify.py` — `drift_services()` method

**Interfaces:**
- Consumes: `self._write_managed_text()`, `self.run_cmd()`
- Produces: Full unit replacement at `/etc/systemd/system/sshd.service`

- [ ] **Step 1: Add full unit shadow at standard tier**

In `drift_services()`, standard block:

```python
            # Full unit shadow (contrasts with existing drop-in pattern)
            _info(f"{_I.TOGGLE}  Creating full sshd.service shadow")
            result = self.run_cmd(
                ["cat", "/usr/lib/systemd/system/sshd.service"],
                check=False, capture=True,
            )
            if not self.dry_run and result is not None and result.returncode == 0:
                unit_content = result.stdout
                modified = unit_content.replace(
                    "ExecStart=/usr/sbin/sshd",
                    "ExecStart=/usr/sbin/sshd -o LogLevel=VERBOSE",
                )
                if modified != unit_content:
                    self._write_managed_text(
                        "/etc/systemd/system/sshd.service",
                        modified,
                    )
                    _sub("Full shadow: /etc/systemd/system/sshd.service")
                else:
                    self._write_managed_text(
                        "/etc/systemd/system/sshd.service",
                        "[Unit]\n"
                        "Description=OpenSSH server daemon (driftify shadow)\n"
                        "After=network.target\n\n"
                        "[Service]\n"
                        "Type=notify\n"
                        "ExecStart=/usr/sbin/sshd -D -o LogLevel=VERBOSE\n"
                        "ExecReload=/bin/kill -HUP $MAINPID\n"
                        "Restart=on-failure\n\n"
                        "[Install]\n"
                        "WantedBy=multi-user.target\n",
                    )
                    _sub("Full shadow (fallback): /etc/systemd/system/sshd.service")
            elif self.dry_run:
                _dry("Write full unit shadow to /etc/systemd/system/sshd.service")

            self.run_cmd(["systemctl", "daemon-reload"], check=False)
```

- [ ] **Step 2: Verify**

Run: `sudo ./driftify.py --dry-run --profile standard 2>&1 | grep -i 'shadow\|sshd.service'`

- [ ] **Step 3: Commit**

```bash
git add driftify.py
git commit -m "feat(driftify): add systemd full unit shadow fixture"
```

---

### Task 9: Legacy Compatibility

**Files:**
- Modify: `driftify.py` — `drift_services()`, `drift_config()`, `drift_network()`, `drift_scheduled()` methods

**Interfaces:**
- Consumes: `self._write_managed_text()`, `self._ensure_dir()`, `self.is_el8`, `self.os_major`, `self._is_fedora()`, `self._try_install()`
- Produces: SysVinit scripts, ifcfg files, xinetd configs, anacrontab entries

- [ ] **Step 1: Add SysVinit script to `drift_services()` at standard tier**

```python
            _info(f"{_I.WARN}  Planting SysVinit legacy script")
            self._ensure_dir(Path("/etc/init.d"))
            self._write_managed_text(
                "/etc/init.d/legacy-app",
                "#!/bin/bash\n"
                "# chkconfig: 2345 95 05\n"
                "# description: Legacy application — driftify fixture\n"
                "### BEGIN INIT INFO\n"
                "# Provides:          legacy-app\n"
                "# Required-Start:    $network $syslog\n"
                "# Required-Stop:     $network $syslog\n"
                "# Default-Start:     2 3 4 5\n"
                "# Default-Stop:      0 1 6\n"
                "# Short-Description: Legacy app service\n"
                "### END INIT INFO\n\n"
                "case \"$1\" in\n"
                "  start)   echo 'Starting legacy-app' ;;\n"
                "  stop)    echo 'Stopping legacy-app' ;;\n"
                "  restart) echo 'Restarting legacy-app' ;;\n"
                "  *)       echo 'Usage: $0 {start|stop|restart}' ;;\n"
                "esac\n",
            )
            if not self.dry_run:
                os.chmod("/etc/init.d/legacy-app", 0o755)
```

- [ ] **Step 2: Add ifcfg file to `drift_network()` at standard tier**

```python
            # ifcfg network config — plant on all platforms for inspectah detection
            # On EL9+/Fedora: ifcfg is deprecated (inspectah emits modernization advisory)
            # On EL8: ifcfg is standard format (inspectah emits no advisory)
            _info(f"{_I.GLOBE}  Planting ifcfg network config")
            self._ensure_dir(Path("/etc/sysconfig/network-scripts"))
            self._write_managed_text(
                "/etc/sysconfig/network-scripts/ifcfg-eth1",
                "TYPE=Ethernet\n"
                "BOOTPROTO=static\n"
                "NAME=eth1\n"
                "DEVICE=eth1\n"
                "ONBOOT=yes\n"
                "IPADDR=10.0.1.100\n"
                "NETMASK=255.255.255.0\n"
                "GATEWAY=10.0.1.1\n",
            )
```

- [ ] **Step 3: Add xinetd + anacrontab + cron.allow at kitchen-sink tier**

In `drift_config()` kitchen-sink:

```python
            self._try_install(["xinetd"], label="xinetd")
            self._ensure_dir(Path("/etc/xinetd.d"))
            self._write_managed_text(
                "/etc/xinetd.d/custom-service",
                "# xinetd service — driftify fixture\n"
                "service custom-echo\n"
                "{\n"
                "    disable     = no\n"
                "    type        = UNLISTED\n"
                "    socket_type = stream\n"
                "    protocol    = tcp\n"
                "    port        = 9999\n"
                "    wait        = no\n"
                "    user        = nobody\n"
                "    server      = /bin/echo\n"
                "}\n",
            )
```

In `drift_scheduled()` kitchen-sink:

```python
            _info(f"{_I.CLOCK}  Planting anacrontab entries")
            self._append_managed_block(
                "/etc/anacrontab",
                "driftify-anacron",
                "# Custom anacron job — driftify fixture\n"
                "7\t15\tcron.driftify-weekly\t/usr/local/bin/weekly-maintenance.sh\n",
            )

            self._write_managed_text(
                "/etc/cron.allow",
                "# Restricted cron access — driftify fixture\n"
                "root\n"
                "appuser\n",
            )
```

- [ ] **Step 4: Verify**

Run: `sudo ./driftify.py --dry-run --profile kitchen-sink 2>&1 | grep -iE 'sysvinit|ifcfg|xinetd|anacron|legacy|init.d|cron.allow'`

- [ ] **Step 5: Commit**

```bash
git add driftify.py
git commit -m "feat(driftify): add legacy compatibility fixtures"
```

---

### Task 10: Update Coverage Documentation

**Files:**
- Modify: `docs/coverage-detail.md`
- Modify: `README.md` — coverage map table and supported platforms
- Modify: `design.md` — coverage map

- [ ] **Step 1: Update `docs/coverage-detail.md`**

Add per-profile breakdown entries for all 8 new fixture categories.

- [ ] **Step 2: Update `README.md` coverage map table**

Add rows for: auth/identity, tmpfiles.d, /usr files, performance tuning, logging/monitoring, cross-tree symlinks, unit shadows, legacy compat.

- [ ] **Step 3: Update `design.md` coverage map**

Mirror README changes.

- [ ] **Step 4: Commit**

```bash
git add docs/coverage-detail.md README.md design.md
git commit -m "docs(driftify): update coverage docs for extended findings"
```

---

### Task 11: Integration Validation

**Purpose:** Verify all fixtures on real VMs, not just `--dry-run`.

**Files:**
- No code changes — verification only

- [ ] **Step 1: Standard profile real run (EL9)**

Run on a fresh EL9 VM:
```bash
sudo ./driftify.py --profile standard -y
```

Post-run assertions:
```bash
# Auth & identity
test -f /etc/ipa/ca.crt
test -f /etc/krb5.keytab
test -f /etc/sssd/sssd.conf && stat -c %a /etc/sssd/sssd.conf | grep -q 600
test -f /etc/pam.d/custom-sshd
test -f /etc/security/faillock.conf

# tmpfiles.d
test -f /etc/tmpfiles.d/appone.conf
test -d /var/lib/appone/cache
test -d /var/lib/pgsql/data
test -d /var/log/myapp
! test -f /etc/tmpfiles.d/pgsql.conf  # unbacked — no tmpfiles.d

# Files in /usr
test -x /usr/bin/custom-tool
test -f /usr/lib/systemd/system/myapp.service
test -d /usr/share/myapp

# Performance tuning
test -f /etc/tuned/myapp/tuned.conf
test -f /etc/sysctl.d/hugepages.conf

# Logging
test -f /etc/rsyslog.d/forward-to-siem.conf
test -f /etc/systemd/journald.conf.d/custom.conf

# Cross-tree symlinks
test -L /etc/mydb/config.yaml && readlink /etc/mydb/config.yaml | grep -q /var/lib/mydb
test -L /opt/myapp/lib && readlink /opt/myapp/lib | grep -q /usr/lib64/myapp

# systemd shadow
test -f /etc/systemd/system/sshd.service
test -f /usr/lib/systemd/system/sshd.service  # original still exists

# Legacy
test -x /etc/init.d/legacy-app
test -f /etc/sysconfig/network-scripts/ifcfg-eth1
```

- [ ] **Step 2: Kitchen-sink profile real run (EL9)**

Run on a fresh EL9 VM:
```bash
sudo ./driftify.py --profile kitchen-sink -y
```

Post-run assertions (in addition to standard-tier checks):
```bash
# Kitchen-sink auth
test -f /etc/samba/smb.conf
test -f /etc/krb5.keytab.ad
test -f /etc/sssd/conf.d/ad-domain.conf

# Kitchen-sink tmpfiles.d
test -f /etc/tmpfiles.d/apptwo-cleanup.conf
test -f /etc/tmpfiles.d/mixed-app.conf
test -d /var/lib/mixed-app/data/uploads/tmp

# Kitchen-sink /usr
test -f /usr/lib64/libcustom.so
test -x /usr/libexec/myapp-helper

# Kitchen-sink symlinks
test -L /etc/app/ssl && readlink /etc/app/ssl | grep -q /var/lib/app/ssl
test -L /opt/tool/bin/run && readlink /opt/tool/bin/run | grep -q /usr/local/bin/run-tool
test -L /usr/local/bin/run-tool && readlink /usr/local/bin/run-tool | grep -q /usr/bin/actual-tool

# Kitchen-sink logging
test -f /etc/aide.conf && grep -q DRIFTIFY_WEB /etc/aide.conf

# Kitchen-sink legacy
test -f /etc/xinetd.d/custom-service
test -f /etc/cron.allow
```

- [ ] **Step 3: Idempotence test**

Run driftify twice on the same VM:
```bash
sudo ./driftify.py --profile standard -y
sudo ./driftify.py --profile standard -y
```
Expected: second run completes without errors and produces the same result.

- [ ] **Step 4: EL8 standard profile run**

Run on a fresh EL8 VM:
```bash
sudo ./driftify.py --profile standard -y
```

Post-run assertions:
```bash
# EL8 ifcfg: planted but NO modernization advisory expected from inspectah
test -f /etc/sysconfig/network-scripts/ifcfg-eth1

# tmpfiles.d: should use 'd' type only (no 'D' on systemd 239)
grep -q '^d ' /etc/tmpfiles.d/appone.conf
! grep -q '^D ' /etc/tmpfiles.d/cleanup.conf  # should be downgraded to 'd'

# All standard fixtures should exist
test -f /etc/ipa/ca.crt
test -x /usr/bin/custom-tool
test -f /etc/tuned/myapp/tuned.conf
```
