# Tool Design: driftify

## Purpose

driftify is a companion tool to yoinkc. It runs on a fresh RHEL, CentOS Stream (9.x or 10.x), or Fedora install and applies a curated set of system modifications that exercise every yoinkc inspector. This serves three goals:

1. **Demo environments.** Run driftify, then run yoinkc, and you get a compelling demonstration with real findings across every category — packages, configs, services, containers, non-RPM software, secrets, the works.
2. **Development testing.** Every yoinkc code path that detects something needs a system where that something exists. driftify is the fixture. When you add a new detection capability to yoinkc, you add a corresponding drift to driftify.
3. **Regression testing.** Run driftify → yoinkc → validate output. If yoinkc stops detecting something driftify creates, that's a bug.

## Design Principles

**Explicit coverage mapping.** Every modification driftify makes is tagged with the yoinkc inspector(s) it exercises. This isn't a random junk drawer — it's a structured test fixture.

**Profiles for different contexts.** A quick CI run doesn't need 200MB of Go binaries. A live demo wants enough to be impressive but not so much that it takes 20 minutes to apply. A full stress test wants everything, including the ugly edge cases.

**Idempotent enough.** Running driftify twice shouldn't break the system. It won't be perfectly idempotent (you can't `dnf install` an already-installed package without it being a no-op, which is fine), but it shouldn't fail or produce a worse state on re-run. Kernel argument appending is fully idempotent — it checks existing `GRUB_CMDLINE_LINUX` args before appending, so re-runs don't duplicate values. `useradd`/`groupadd` failures are handled gracefully: if a user already exists or creation fails, dependent operations (SSH key writes, chown, sudoers) are skipped rather than silently corrupted.

**No real secrets.** driftify plants fake secrets that look realistic enough to trigger yoinkc's redaction patterns, but they're obviously synthetic. Nobody should be able to accidentally leak a real credential from a driftify-prepared system.

**Disposable targets.** driftify is designed for throwaway VMs that exist solely to exercise yoinkc. System state is restored via VM snapshots, not an undo mechanism. There is no `--undo` flag.

**Fast by default.** The standard profile should complete in under 3 minutes on a system with decent network. Expensive operations (compiling binaries, pulling large images) are opt-in via the `kitchen-sink` profile.

## Runtime Model

driftify is a single-file Python script. No pip dependencies — stdlib only. The reasoning:

- **Python 3 is always available.** It ships on minimal RHEL and CentOS Stream installs (9 and 10) as a weak dependency of `dnf`. No bootstrapping problem.
- **The logic warrants real data structures.** driftify has profile-gated sections, OS version branching, stamp file serialization, binary provisioning, and conditional file creation across a dozen categories. In shell, this means associative arrays, fragile string parsing, and heredocs inside heredocs. In Python, it's dictionaries, `pathlib`, `json`, and `subprocess.run()`. Cleaner, more testable, harder to get wrong.
- **Still transparent.** A sysadmin reading `subprocess.run(["dnf", "install", "-y", "httpd", "nginx"])` knows exactly what happens. The system commands are the same — Python is just the control flow.
- **Still easy to deploy.** Single file, `#!/usr/bin/python3`, `curl` it onto a VM and `chmod +x && sudo ./driftify.py`. No different from a shell script in practice.

Shell was the initial instinct (sysadmin muscle memory), but the complexity of what driftify needs to track — especially OS-version-conditional logic and profile-gated sections — tips the balance to Python.

The script requires root. It checks for this upfront and exits if not root.

### OS Version Handling

driftify detects the host's OS from `/etc/os-release` and adapts:

```python
# Parsed from /etc/os-release
os_id       # "rhel", "centos", or "fedora"
os_version  # "9.4", "9", "10.0", "10", "41", etc.
os_major    # 9, 10, 41, etc. (integer)
```

Most driftify operations are identical across RHEL 9, 10, and Fedora — the same packages, configs, and system commands work on all three. Where they differ:

| Area | What varies | How driftify handles it |
|---|---|---|
| Third-party repo | EPEL on RHEL/CentOS (version-keyed URL); RPM Fusion Free on Fedora (version-keyed URL) | `_is_fedora()` branch selects the right repo |
| EPEL packages on Fedora | htop, bat, fd-find, etc. ship in the default Fedora repos | EPEL package lists are folded into the base install on Fedora |
| RHEL-only packages | `insights-client`, `rhc`, `epel-release`, `initscripts-*` don't exist on Fedora | `_RHEL_ONLY_PACKAGES` set is filtered out when `os_id == "fedora"` |
| RPM Fusion packages | ffmpeg, unrar, chromaprint-tools require RPM Fusion Free on Fedora | `RPMFUSION_PACKAGES` dict, installed only on Fedora after enabling the repo |
| Package names | Occasional renames between majors (rare) | `dnf install --setopt=strict=0` with a warning for packages that don't exist on the detected version |
| SELinux policy | Module compilation tools may differ | Detect `checkmodule`/`semodule_package` availability before attempting |
| Default service set | Some services added/removed between versions (e.g. kdump absent on Fedora minimal) | driftify checks unit existence via `systemctl cat` before disabling/masking |

The principle: driftify should work on RHEL/CentOS Stream 9.x, 10.x, and recent Fedora releases without modification. If a specific package or operation isn't available on a given version, it logs a warning and skips that item rather than failing.

It sources a config file (`driftify.conf`) if present, but works entirely with built-in defaults if not. The config file is for overriding things like which packages to install or which fake secrets to plant — useful for customizing demo scenarios without forking the script.

## Profiles

### `minimal`

Just enough to light up every yoinkc inspector card with at least one finding. Optimized for speed — no network-heavy operations beyond basic `dnf install`. Suitable for CI.

Approximate time: **1–2 minutes.**

### `standard` (default)

A realistic "moderately customized application server" scenario. Multiple findings per inspector, enough to make the HTML report look populated and the Containerfile non-trivial. This is the demo profile.

Approximate time: **2–4 minutes.**

### `kitchen-sink`

Everything. Multiple packages from every category, complex configs, edge cases, non-RPM software with various provenance levels (pip with C extensions, npm with lockfiles, mystery binaries). Exercises yoinkc's deep-scan and edge-case handling.

Approximate time: **5–10 minutes** (depends on network speed and whether Go/Rust binaries are downloaded or compiled).

## Coverage Map

This is the core of the design. Each section maps to a yoinkc inspector and specifies exactly what driftify creates to exercise it.

### RPM Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Enable EPEL repo (EL) or RPM Fusion Free (Fedora) | Additional repo beyond base | minimal |
| `dnf install` ~10 base-repo packages (httpd, nginx, vim-enhanced, tmux, jq, etc.) | Added packages vs. base image | minimal |
| `dnf install` ~3 EPEL packages (htop, bat, etc.) — folded into base install on Fedora | Cross-repo packages | minimal |
| `dnf install` RPM Fusion packages on Fedora (x264, x265 at minimal, chromaprint-tools and unrar at standard, ffmpeg at kitchen-sink) | Third-party repo packages | varies |
| `dnf install` then `dnf remove` a package (e.g., `words`) | dnf history ghost — installed-then-removed package | standard |
| `dnf install` ~10 more packages across profiles | Larger package delta, more realistic Containerfile | standard |
| `dnf install` development tools (gcc, make, kernel-devel) | Build dependencies that shouldn't be in prod image | kitchen-sink |

On Fedora, the `_RHEL_ONLY_PACKAGES` set (`epel-release`, `initscripts-rename-device`, `initscripts-service`, `insights-client`, `rhc`) guards against accidentally installing RHEL-specific packages; any package in this set that appears in a profile's install list is excluded when `os_id == "fedora"`.

The installed packages are chosen to be small, fast to install, and useful for other driftify operations (e.g., httpd gets installed so we can modify its config; python3-pip gets installed so we can create pip venvs).

### Service Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| `systemctl enable httpd` | Non-default enabled service | minimal |
| `systemctl enable nginx` | Second non-default enabled service | minimal |
| `systemctl disable kdump` (if present) | Default service disabled | minimal |
| `systemctl mask bluetooth` (if present) | Masked service | standard |
| Drop-in override `httpd.service.d/override.conf` (`TimeoutStartSec=600`, `LimitNOFILE=65535`) | systemd drop-in override for service tuning | standard |
| Drop-in override `nginx.service.d/override.conf` (`LimitNOFILE=131072`, `ExecStartPost` hook) | systemd drop-in with post-start hook | kitchen-sink |
| Enable generated timers (see Scheduled Tasks) | Timer enablement | standard |

### Config Inspector

#### Modified RPM-owned configs

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Modify `/etc/httpd/conf/httpd.conf` — change `Listen`, `ServerName`, `MaxRequestWorkers` | Modified RPM-owned config (triggers `rpm -Va`) | minimal |
| Modify `/etc/nginx/nginx.conf` — change `worker_processes`, add `server` block | Modified RPM-owned config | minimal |
| Modify `/etc/ssh/sshd_config` — disable root login, change port | Modified RPM-owned config (security-relevant) | standard |
| Modify `/etc/chrony.conf` — add NTP servers | Modified RPM-owned config | standard |
| Modify `/etc/security/limits.conf` — add nofile limits | Modified RPM-owned config | kitchen-sink |
| Modify `/etc/audit/auditd.conf` — increase log size | Modified RPM-owned config | kitchen-sink |

#### Unowned config files (not from any RPM)

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Drop `/etc/myapp/app.conf` with application config | Unowned config file in /etc | minimal |
| Drop `/etc/myapp/database.yml` with DB connection (fake creds) | Unowned config + secret detection | minimal |
| Drop `/etc/profile.d/custom-env.sh` with env vars | Unowned config in standard location | standard |
| Drop `/etc/logrotate.d/myapp` with rotation config | Unowned config in logrotate.d | standard |
| Drop `/etc/cron.d/` job files (see Scheduled Tasks) | Unowned config in cron.d | standard |
| Drop `/etc/sudoers.d/appusers` (see Users) | Unowned config in sudoers.d | standard |

#### Orphaned configs from removed packages

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Install `words`, modify its config, then remove the package | Config file orphaned by removed package | standard |

### Network Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Add firewalld service allowances (http, https, 8080/tcp) | Non-default firewall rules | minimal |
| Add custom firewalld zone XML | Custom zone definition | standard |
| Add entries to `/etc/hosts` | Non-default hosts entries | minimal |
| Drop a static NM connection profile in `/etc/NetworkManager/system-connections/` | Static NM profile (bake-into-image candidate) | standard |
| Add proxy config in `/etc/profile.d/proxy.sh` | System-wide proxy detection | standard |
| Add a static route file `/etc/sysconfig/network-scripts/route-eth0` | Static route detection | kitchen-sink |
| Create `/etc/firewalld/direct.xml` with direct rules | Direct firewall rules (legacy pattern) | kitchen-sink |

### Storage Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Add NFS entry to `/etc/fstab` (non-functional — uses `noauto`) | NFS mount dependency in fstab | standard |
| Add CIFS entry to `/etc/fstab` (non-functional — uses `noauto`) | CIFS mount with credential reference | standard |
| Create `/etc/auto.master.d/app.autofs` and `/etc/auto.app` | Automount map | kitchen-sink |
| Create app data dirs under `/var/lib/myapp/`, `/var/log/myapp/` | Application state in /var (data migration plan) | minimal |

### Scheduled Task Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Add cron job to `/etc/cron.d/backup-daily` | Cron job → timer conversion | minimal |
| Add script to `/etc/cron.daily/cleanup.sh` | Cron daily script | minimal |
| Add per-user crontab for an app user | Per-user crontab (FIXME case) | standard |
| Create a custom systemd timer + service pair | Existing local timer (COPY + enable) | standard |
| Queue an `at` job | Pending at job (FIXME case) | standard |
| Add cron job with `MAILTO` and env vars | Edge case: cron with env dependencies | kitchen-sink |

### Container Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Drop a `.container` quadlet unit in `/etc/containers/systemd/` | Quadlet unit with `Image=` parsing | minimal |
| Drop a `.container` quadlet with volumes, ports, env vars, and secrets | Richer quadlet detection — multiple parsed fields | standard |
| Drop a second `.container` quadlet for a database container | Multiple quadlet units | standard |
| Drop a `.network` quadlet in `/etc/containers/systemd/` | Quadlet network unit detection | standard |
| Drop a `docker-compose.yml` in `/opt/myapp/` | Compose file detection + FIXME for conversion | standard |
| Drop a user-level quadlet in `~appuser/.config/containers/systemd/` | User-level quadlet detection | kitchen-sink |

None of these actually pull or run container images. yoinkc's file-based scanner only needs the unit files on disk. The `--query-podman` flag would find nothing, which is itself a valid test case (no running containers, but quadlet definitions exist).

**Quadlet unit details:**

The quadlet files are designed to exercise the specific fields yoinkc's container inspector parses:

**`/etc/containers/systemd/webapp.container`** (minimal):
```ini
[Unit]
Description=Web Application
After=network-online.target

[Container]
Image=registry.example.com/myorg/webapp:v2.1.3
PublishPort=8080:8080
PublishPort=8443:8443
Environment=APP_ENV=production
Environment=LOG_LEVEL=info
# This fake secret should trigger yoinkc's redaction
Environment=DATABASE_URL=postgresql://dbuser:s3cret@db.internal:5432/myapp
Volume=/var/lib/myapp/data:/app/data:Z
Volume=/var/log/myapp:/app/logs:Z
Network=myapp.network
AutoUpdate=registry

[Service]
Restart=always
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target default.target
```

This exercises: `Image=` parsing (with registry, org, tag), `PublishPort=` (multiple), `Environment=` (including one with an embedded secret that should trigger redaction), `Volume=` (multiple, with SELinux `:Z` relabel — ties to storage migration), `Network=` (references the `.network` quadlet), `AutoUpdate=` (bootc-relevant metadata).

**`/etc/containers/systemd/redis.container`** (standard):
```ini
[Unit]
Description=Redis Cache
Before=webapp.service

[Container]
Image=docker.io/library/redis:7-alpine
PublishPort=127.0.0.1:6379:6379
Volume=redis-data.volume:/data:Z
Environment=REDIS_PASSWORD=DRIFTIFY_FAKE_r3d1s_p4ss
# Exercises healthcheck detection
HealthCmd=/usr/local/bin/redis-cli ping
HealthInterval=10s

[Service]
Restart=always

[Install]
WantedBy=multi-user.target default.target
```

This exercises: a different image registry (docker.io vs. custom), localhost-bound port publishing, named volume reference, secret in environment variable, healthcheck fields.

**`/etc/containers/systemd/myapp.network`** (standard):
```ini
[Unit]
Description=Application Network

[Network]
Subnet=10.89.1.0/24
Gateway=10.89.1.1
Label=app=myapp
```

This exercises: `.network` quadlet detection (not just `.container`), custom subnet configuration.

**`/opt/myapp/docker-compose.yml`** (standard):
```yaml
# Legacy compose file — should be converted to quadlets
version: "3.8"
services:
  app:
    image: registry.example.com/myorg/webapp:v2.1.3
    ports:
      - "9090:8080"
    environment:
      - APP_ENV=staging
    volumes:
      - ./data:/app/data
    depends_on:
      - db
  db:
    image: docker.io/library/postgres:16
    environment:
      POSTGRES_PASSWORD: DRIFTIFY_FAKE_pgpass123
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
```

This exercises: compose file detection in `/opt`, multi-service `image:` extraction, secret in environment, volume definitions, `depends_on` relationships. yoinkc should flag this with a `# FIXME: converted from docker-compose, verify quadlet translation` comment.

**`~appuser/.config/containers/systemd/dev-tools.container`** (kitchen-sink):
```ini
[Unit]
Description=Development tools (user-level)

[Container]
Image=quay.io/toolbox/toolbox:latest
Volume=%h/projects:/projects:Z

[Install]
WantedBy=default.target
```

This exercises: user-level quadlet detection (UID 1000–59999 path scan), `%h` specifier usage, `quay.io` as a third registry variant.

### Non-RPM Software Inspector

This is the most involved section because it needs to exercise multiple detection strategies.

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Create a Python venv at `/opt/myapp/venv` with pip packages (flask, gunicorn, requests) | pip venv detection, package list capture | minimal |
| Install a small npm project at `/opt/webapp/` with `package.json` and `node_modules` | npm project detection, lockfile capture | standard |
| Install system-level Ruby gems (2–3 gems) | gem detection | standard |
| Place a small pre-compiled Go binary at `/usr/local/bin/driftify-probe` | Go binary detection (ELF with `.note.go.buildid`) | minimal |
| Place a small pre-compiled binary with no metadata at `/usr/local/bin/mystery-tool` | Unknown-provenance binary (FIXME) | minimal |
| Create a venv with `--system-site-packages` at `/opt/legacy-app/venv` | System-site-packages warning | standard |
| Create a git-cloned directory at `/opt/tools/some-tool/` with `.git` | Git-managed directory with remote URL | standard |
| Place a shell script with a shebang at `/usr/local/bin/deploy.sh` | Script detection (non-binary) | standard |
| Place pip packages with `.so` files (e.g., numpy) in a venv | C extension detection → multi-stage build hint | kitchen-sink |

**Binary provisioning:**

The Go and mystery binaries need to exist as real ELF files for yoinkc's `readelf` / `file` detection to work. Options:

1. **Compile at driftify time** (kitchen-sink only): Install Go toolchain, compile a trivial `main.go`. Produces a genuine Go binary with build ID. Slow (~30s) and requires Go.
2. **Download pre-built binaries** (standard/minimal): Download small, well-known Go binaries from GitHub releases. Candidates: `yq` (~10MB, Go, has version string), `gojq` (~5MB, Go). These are real tools, small, and available on GitHub releases as static binaries.
3. **Synthetic ELF** (minimal fallback): Ship a tiny pre-built ELF binary embedded in the script (base64-encoded). This is ~1KB, can be crafted to have the right ELF sections. Only useful for testing detection, not for demo realism.

Recommendation: option 2 for standard/minimal (download `yq` — it's broadly useful and ~10MB), option 1 additionally for kitchen-sink. The mystery binary is a stripped C binary compiled from a trivial source, or a renamed copy of `/usr/bin/true` with sections stripped.

### Kernel/Boot Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Add sysctl overrides in `/etc/sysctl.d/99-driftify.conf` | Non-default sysctl values with source attribution | minimal |
| Apply sysctls live (`sysctl -p`) so runtime matches | Runtime vs. shipped default diff | minimal |
| Add module load in `/etc/modules-load.d/driftify.conf` | Explicitly loaded module | standard |
| Add dracut config in `/etc/dracut.conf.d/driftify.conf` | Custom dracut configuration | standard |
| Modify `/etc/default/grub` to add kernel args | Custom kernel boot parameters | kitchen-sink |

**Sysctl values chosen to be safe and realistic:**

```ini
# /etc/sysctl.d/99-driftify.conf
# Network performance tuning (exercises yoinkc sysctl detection)
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
vm.swappiness = 10
fs.file-max = 2097152
net.ipv4.tcp_keepalive_time = 600
```

These are all common production tuning values, safe to apply, and clearly non-default.

**Module loading:**

```ini
# /etc/modules-load.d/driftify.conf
# Exercise yoinkc kernel module detection
br_netfilter
```

`br_netfilter` is safe (available on any RHEL 9/10 kernel), commonly loaded for container networking, and clearly an operator choice rather than an auto-loaded dependency.

### SELinux/Security Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| `setsebool -P httpd_can_network_connect on` | Non-default SELinux boolean | minimal |
| `setsebool -P httpd_can_network_relay on` | Second non-default boolean | standard |
| Drop custom audit rules in `/etc/audit/rules.d/driftify.rules` | Custom audit rules | standard |
| Create and install a custom SELinux policy module | Custom policy module at priority 400 | kitchen-sink |

**Custom SELinux module (kitchen-sink):**

A minimal type enforcement policy that allows a hypothetical `myapp_t` domain to connect to a port. This is the simplest possible custom module — a `.te` file compiled with `checkmodule` + `semodule_package` + `semodule -i`. It's realistic (many production systems have custom modules for in-house apps) and exercises the priority-400 module store scan.

```
# myapp.te
module myapp 1.0;

require {
    type httpd_t;
    type http_port_t;
    class tcp_socket name_connect;
}

allow httpd_t http_port_t:tcp_socket name_connect;
```

This is a no-op (httpd_can_network_connect already grants this when enabled) but it's a syntactically valid module that installs at priority 400.

### User/Group Inspector

| What driftify does | What yoinkc should detect | Profile |
|---|---|---|
| Create user `appuser` (UID 1001) with home dir | Non-system user in 1000–59999 range | minimal |
| Create user `dbuser` (UID 1002) with `/sbin/nologin` shell | Service account pattern | standard |
| Create group `appgroup` (GID 1001) and add appuser | Non-system group + membership | minimal |
| Add sudoers rule in `/etc/sudoers.d/appusers` | Sudoers config for app users | standard |
| Create SSH authorized_keys for appuser (fake key) | SSH key reference (flagged, not copied) | standard |
| Create shared group `developers` (GID 1050) with appuser + dbuser as supplementary members | Shared group with supplementary membership | standard |
| Set up subuid/subgid ranges for appuser | Rootless container user mapping | kitchen-sink |

### Secret Handling

These are *fake* secrets that are designed to trigger yoinkc's redaction patterns. They should look realistic enough to validate the pattern matching but be obviously synthetic on inspection.

| What driftify plants | Where | Pattern triggered | Profile |
|---|---|---|---|
| `AKIAIOSFODNN7EXAMPLE` | `/etc/myapp/app.conf` | AWS access key | minimal |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | `/etc/myapp/app.conf` | AWS secret key | minimal |
| `password = SuperSecret123!` | `/etc/myapp/database.yml` | Password field pattern | minimal |
| `-----BEGIN RSA PRIVATE KEY-----\nMIIE...FAKE...` | `/etc/myapp/server.key` | PEM private key block | minimal |
| `ghp_xxxxxxxxxxDRIFTIFYFAKExxxxxxxxxx` | `/etc/myapp/app.conf` | GitHub personal access token | standard |
| `postgresql://dbuser:s3cret@db.internal:5432/myapp` | `/etc/myapp/database.yml` | Connection string with credentials | standard |
| `REDIS_URL=redis://:p4ssw0rd@redis.internal:6379` | `/etc/profile.d/custom-env.sh` | Redis connection string | standard |
| `mongodb://admin:m0ng0pass@mongo.internal:27017/admin` | `/etc/myapp/database.yml` | MongoDB connection string | kitchen-sink |
| Fake API token in a `.env` file | `/opt/myapp/.env` | Generic API_KEY/TOKEN pattern | kitchen-sink |

All fake secrets contain the string `EXAMPLE`, `FAKE`, `DRIFTIFY`, or use the well-known AWS example key prefix, so there's no ambiguity that these are synthetic.

## Script Structure

```
driftify.py          — Main script (single file, stdlib-only Python)
driftify.conf        — Optional config overrides (not required)
assets/              — Pre-built binaries, SELinux policy sources, etc.
                       (only needed for kitchen-sink; standard/minimal
                        download or generate what they need)
```

The main script is organized as a class with methods per inspector coverage area:

```python
class Driftify:
    def __init__(self, profile, dry_run, skip_sections):
        self.profile = profile
        self.dry_run = dry_run
        self.skip = skip_sections
        self.stamp = StampFile()
        self.os_id, self.os_major = detect_os()

    def run(self):
        self.stamp.start()

        self.drift_rpm()          # Packages and repos
        self.drift_services()     # Service state changes
        self.drift_config()       # Config file modifications
        self.drift_network()      # Firewall, NM, hosts, proxy
        self.drift_storage()      # Fstab entries, /var directories
        self.drift_scheduled()    # Cron, timers, at jobs
        self.drift_containers()   # Quadlet units, compose files
        self.drift_nonrpm()       # pip, npm, gems, binaries
        self.drift_kernel()       # Sysctl, modules, dracut
        self.drift_selinux()      # Booleans, audit rules, policy modules
        self.drift_users()        # Users, groups, sudoers, SSH keys
        self.drift_secrets()      # Fake credentials in config files

        self.stamp.finish()
        self.print_summary()
```

Each `drift_*` method:
1. Checks if its section is in the skip list (returns early if so).
2. Checks profile level (`self.needs_profile("minimal"|"standard"|"kitchen-sink")`).
3. Performs the modifications via `self.run_cmd()` (which respects `--dry-run`).
4. Logs progress with section headers.

### Stamp File

`/etc/driftify.stamp` is a JSON file written at the start of a run and updated at the end. It records run metadata only:

```json
{
  "started": "2025-01-15T10:30:00+00:00",
  "finished": "2025-01-15T10:32:47+00:00",
  "profile": "standard",
  "os_id": "centos",
  "os_major": 9
}
```

The stamp is used to record when driftify ran, which profile was applied, and which OS version was detected. It is not used for per-item tracking (files created, services changed, etc.) — the completion summary derives those counts from the profile definition, not the stamp.

## CLI Interface

```
Usage: sudo ./driftify.py [OPTIONS]

Options:
  --profile PROFILE    minimal, standard (default), or kitchen-sink
  --skip-SECTION       Skip a section (e.g., --skip-nonrpm, --skip-selinux)
  --dry-run            Print what would be done without doing it
  -y, --yes            Skip interactive confirmation prompt
  -q, --quiet          Show only section banners, warnings, and errors.
                       Does not suppress yoinkc output when --run-yoinkc is used.
  --verbose            Reserved for future use (no effect today)
  --run-yoinkc         After applying drift, download and run run-yoinkc.sh
  --yoinkc-output DIR  Output directory for yoinkc artifacts (default: ./yoinkc-output)
  --help               Show this help

Examples:
  sudo ./driftify.py                          # Standard profile
  sudo ./driftify.py --profile minimal        # CI-friendly, fast
  sudo ./driftify.py --profile kitchen-sink   # Everything
  sudo ./driftify.py --skip-nonrpm            # Standard, but skip non-RPM software
  sudo ./driftify.py --run-yoinkc             # Apply drift then hand off to yoinkc
```

## Fleet Testing

`run-fleet-test.sh` automates the full fleet test loop on a single VM. It is fully self-contained — it curls `driftify.py`, `run-yoinkc.sh`, and `run-yoinkc-fleet.sh` from GitHub so no local checkout is required.

**What it does:**

1. Runs driftify with all three profiles in sequence (minimal, standard, kitchen-sink).
2. After each profile, runs yoinkc with a unique `YOINKC_HOSTNAME` (web-01, web-02, web-03) so each tarball appears to come from a different host.
3. Aggregates the three host tarballs into a fleet tarball using `run-yoinkc-fleet.sh` with `-p 67` (67% prevalence threshold).

**Usage:**

```bash
curl -fsSL https://raw.githubusercontent.com/marrusl/driftify/main/run-fleet-test.sh -o run-fleet-test.sh
sudo bash run-fleet-test.sh
```

**What it produces:**

- 3 host tarballs (one per profile/hostname), each containing a Containerfile, HTML report, and snapshot.
- 1 fleet tarball with a merged snapshot, fleet HTML report (with prevalence badges), and Containerfile.

Since profiles are cumulative (minimal < standard < kitchen-sink), each successive tarball captures more drift. The fleet aggregation with `-p 67` naturally stratifies: minimal items appear on 3/3 hosts, standard-only on 2/3, kitchen-sink-only on 1/3.

## Coverage Verification

After driftify completes, it prints a summary showing what was created for each inspector:

```
=== driftify complete (standard profile, 2m 34s) ===

RPM Inspector:        14 packages installed, 1 repo added, 1 ghost package
Service Inspector:    2 enabled, 1 disabled, 1 masked
Config Inspector:     4 RPM configs modified, 6 unowned files placed, 1 orphan
Network Inspector:    3 firewall rules, 1 custom zone, 2 hosts entries, 1 proxy
Storage Inspector:    2 fstab entries, 3 /var directories
Scheduled Tasks:      2 cron jobs, 1 timer, 1 at job, 1 per-user crontab
Container Inspector:  2 quadlet units, 1 compose file
Non-RPM Software:     1 pip venv (3 packages), 1 npm project, 1 Go binary, 1 mystery binary
Kernel/Boot:          6 sysctl overrides, 1 module, 1 dracut config
SELinux/Security:     2 booleans, 1 audit rule file
Users/Groups:         2 users, 1 group, 1 sudoers rule, 1 SSH key
Secrets:              6 fake credentials planted

Stamp file: /etc/driftify.stamp
Run yoinkc: sudo ./driftify.py --run-yoinkc
```

This summary directly maps to what yoinkc should find. During development, you can compare driftify's summary against yoinkc's audit report to verify full coverage.

## Non-Goals

**driftify does not test yoinkc's rendering.** It tests detection. Whether the Containerfile or HTML report renders correctly is a separate concern — driftify just ensures there's something to detect and render.

**driftify does not create a "realistic production system."** It creates a system with realistic *types* of drift, but the specific combination (httpd AND nginx AND a Flask app AND Go binaries) is unlikely on any single real server. That's fine — the goal is coverage, not realism.

**driftify does not test yoinkc's baseline generation.** Baseline generation requires pulling a bootc base image via podman, which is infrastructure-dependent. driftify focuses on what's on the host filesystem. Baseline testing belongs in yoinkc's own test suite.

**driftify does not test version-specific edge cases exhaustively.** It works on both RHEL/CentOS 9 and 10 by adapting to the detected version, but it doesn't maintain separate coverage maps per version. If a yoinkc detection path is version-specific, that should be tested in yoinkc's own test suite with version-pinned fixtures.

**driftify is a single-host tool.** It applies drift to one system at a time. However, `run-fleet-test.sh` orchestrates multi-host fleet testing by running driftify with all three profiles on the same VM, capturing each run under a unique hostname, and aggregating the results with `yoinkc-fleet`. See the Fleet Testing section below.

## Dependencies

driftify requires:
- Python 3 (present on minimal RHEL/CentOS Stream 9 and 10 installs, and Fedora)
- Root access
- Network access for:
  - `dnf install` (requires configured repos)
  - EPEL repo setup on EL, or RPM Fusion Free on Fedora (version-appropriate URL selected automatically)
  - pip package installation
  - npm package installation (requires nodejs, installed via dnf)
  - Binary downloads from GitHub (for Go binary in standard/minimal profiles)

For fully air-gapped environments, a `--local-assets DIR` flag can point to a directory containing pre-downloaded RPMs, pip wheels, npm tarballs, and binaries. This is a stretch goal — network access is the expected case.

## File Inventory

Everything driftify creates, so you can audit it at a glance:

### Files created

```
/etc/driftify.stamp                              # Stamp file (all profiles)
/etc/yum.repos.d/epel*.repo                      # EPEL repo on EL (via dnf install)
/etc/yum.repos.d/rpmfusion-free*.repo            # RPM Fusion Free on Fedora (via dnf install)
/etc/myapp/                                       # Application config dir
/etc/myapp/app.conf                              # App config with fake secrets
/etc/myapp/database.yml                          # DB config with fake creds
/etc/myapp/server.key                            # Fake PEM private key
/etc/profile.d/custom-env.sh                     # Custom environment variables
/etc/profile.d/proxy.sh                          # Proxy configuration
/etc/logrotate.d/myapp                           # Logrotate config
/etc/sudoers.d/appusers                          # Sudoers rules
/etc/sysctl.d/99-driftify.conf                   # Sysctl overrides
/etc/modules-load.d/driftify.conf                # Module loading
/etc/dracut.conf.d/driftify.conf                 # Dracut config
/etc/audit/rules.d/driftify.rules                # Audit rules
/etc/cron.d/backup-daily                         # Cron job
/etc/cron.daily/cleanup.sh                       # Cron daily script
/etc/systemd/system/httpd.service.d/override.conf # httpd drop-in (standard+)
/etc/systemd/system/nginx.service.d/override.conf # nginx drop-in (kitchen-sink)
/etc/systemd/system/myapp-report.timer           # Custom systemd timer
/etc/systemd/system/myapp-report.service         # Timer's service unit
/etc/containers/systemd/webapp.container         # Quadlet: webapp (Image, Ports, Env, Volumes, Network)
/etc/containers/systemd/redis.container          # Quadlet: redis (standard+) (Image, Ports, Volume, Health)
/etc/containers/systemd/myapp.network            # Quadlet: network definition (standard+)
/etc/NetworkManager/system-connections/mgmt.nmconnection  # Static NM profile
/etc/firewalld/zones/myapp.xml                   # Custom firewall zone
/etc/hosts                                        # Modified (entries added)
/opt/myapp/                                       # Application directory
/opt/myapp/venv/                                  # Python venv
/opt/myapp/docker-compose.yml                    # Compose file (standard+)
/opt/myapp/.env                                   # Env file with fake secrets
/opt/webapp/                                      # npm project (standard+)
/opt/tools/some-tool/                             # Git-cloned dir (standard+)
/usr/local/bin/driftify-probe                    # Go binary
/usr/local/bin/mystery-tool                      # Unknown-provenance binary
/usr/local/bin/deploy.sh                         # Shell script (standard+)
/var/lib/myapp/                                   # App state directory
/var/lib/myapp/data/                              # App data directory
/var/log/myapp/                                   # App log directory
/home/appuser/                                    # User home dir
/home/appuser/.ssh/authorized_keys               # Fake SSH key (standard+)
```

### Files modified (RPM-owned)

```
/etc/httpd/conf/httpd.conf                       # Apache config tuning
/etc/nginx/nginx.conf                            # Nginx config tuning
/etc/ssh/sshd_config                             # SSH hardening (standard+)
/etc/chrony.conf                                  # NTP servers (standard+)
/etc/security/limits.conf                        # Resource limits (kitchen-sink)
/etc/audit/auditd.conf                           # Audit config (kitchen-sink)
/etc/default/grub                                 # Kernel args (kitchen-sink)
```

### System state changes

```
Services enabled: httpd, nginx
Services disabled: kdump (if present)
Services masked: bluetooth (standard+, if present)
Drop-in overrides: httpd (standard+), nginx (kitchen-sink)
SELinux booleans: httpd_can_network_connect=on, httpd_can_network_relay=on (standard+)
SELinux modules: myapp (kitchen-sink)
Users: appuser (1001), dbuser (1002, standard+)
Groups: appgroup (1001), developers (1050, standard+)
Firewall: http, https, 8080/tcp added to default zone
Sysctls: 6 values applied
Modules: br_netfilter loaded (standard+)
```

## Implementation Order

1. **Script skeleton** — argument parsing, profile logic, helpers, stamp file.
2. **RPM + Services** — the simplest sections, validate the framework works.
3. **Config + Secrets** — file creation, RPM config modification, fake secret planting.
4. **Users + SELinux** — user creation, boolean changes, audit rules.
5. **Kernel** — sysctl, modules, dracut.
6. **Network + Storage** — firewall, NM profiles, fstab entries.
7. **Scheduled Tasks** — cron jobs, timers, at jobs.
8. **Containers** — quadlet and compose files.
9. **Non-RPM Software** — pip venvs, npm, binaries (most complex section).
10. **Summary + verification** — final output showing what was done.

## Future Work

**CI integration.** A GitHub Actions workflow that provisions CentOS Stream 9, CentOS Stream 10, and Fedora VMs, runs driftify, runs yoinkc, and validates the output contains expected findings. This is the regression test harness. Matrix testing across OS versions ensures neither tool silently breaks on a version it claims to support.

**Parameterized scenarios.** Config file support for defining specific drift scenarios: "I want a system that looks like a web server" vs. "I want a system that looks like a database server" vs. "I want a system that looks like a Kubernetes node." Each scenario would select different packages, configs, and services.

**Drift variations.** For fleet analysis testing: a mode that applies slight variations across runs (different package versions, slightly different configs) to simulate host drift within a role. *Partially addressed:* `run-fleet-test.sh` provides cross-profile variation (minimal vs. standard vs. kitchen-sink), but true within-profile variation (e.g., same profile with randomized package subsets) is still future work.
