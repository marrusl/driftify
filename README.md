# driftify

Apply synthetic drift to a fresh RHEL or CentOS Stream 9/10 system so that [yoinkc](https://github.com/marrusl/yoinkc) has something to detect.

driftify is the fixture half of the yoinkc development workflow: run driftify on a clean host, then run yoinkc, and every inspector lights up with real findings — packages, configs, services, containers, secrets, the works.

## Quick start

```bash
curl -LO https://raw.githubusercontent.com/marrusl/driftify/main/driftify.py
chmod +x driftify.py
sudo ./driftify.py                    # standard profile
sudo ./driftify.py --undo             # reverse everything
```

No dependencies beyond Python 3 (ships on every RHEL/CentOS Stream minimal install).

## Usage

```
sudo ./driftify.py                          # standard profile
sudo ./driftify.py --profile minimal        # CI-friendly, fast
sudo ./driftify.py --profile kitchen-sink   # everything
sudo ./driftify.py --skip-nonrpm            # standard minus non-RPM software
sudo ./driftify.py --undo                   # reverse previous run
sudo ./driftify.py --dry-run                # preview without changes
```

## CLI reference

| Flag | Description |
|------|-------------|
| `--profile PROFILE` | `minimal`, `standard` (default), or `kitchen-sink` |
| `--skip-SECTION` | Skip a section (e.g. `--skip-rpm`, `--skip-services`, `--skip-nonrpm`) |
| `--undo` | Reverse all modifications from the previous run (requires stamp file) |
| `--dry-run` | Print commands without executing them |
| `--help` | Show help |

### Sections

Each `--skip-SECTION` flag controls one drift category:

`rpm` `services` `config` `network` `storage` `scheduled` `containers` `nonrpm` `kernel` `selinux` `users` `secrets`

## Profiles

| Profile | What it does | Time |
|---------|-------------|------|
| **minimal** | Just enough to light up every yoinkc inspector with at least one finding. No heavy downloads. Good for CI. | ~1–2 min |
| **standard** | A realistic "moderately customized app server." Multiple findings per inspector, enough for a compelling demo. | ~2–4 min |
| **kitchen-sink** | Everything — dev tools, compiled binaries, complex configs, edge cases. Exercises yoinkc's deep-scan paths. | ~5–10 min |

Profiles are cumulative: `standard` includes everything in `minimal`, and `kitchen-sink` includes everything in `standard`.

## Coverage map

Each section maps to a yoinkc inspector:

| Section | What driftify creates | yoinkc inspector exercised |
|---------|----------------------|---------------------------|
|  **rpm** | EPEL repo, base + EPEL packages, ghost package (install-then-remove) | RPM / Packages |
|  **services** | Enable httpd/nginx, disable kdump, mask bluetooth | Services |
|  **config** | Modified RPM-owned configs, unowned app configs, orphaned configs | Configuration Files |
|  **network** | Firewalld rules, custom zones, /etc/hosts entries, NM profiles, proxy | Network |
|  **storage** | NFS/CIFS fstab entries, app data dirs under /var | Storage |
|  **scheduled** | Cron jobs, systemd timers, at jobs, per-user crontabs | Scheduled Tasks |
|  **containers** | Quadlet .container/.network units, docker-compose.yml | Containers |
|  **nonrpm** | pip venvs, npm projects, Go binaries, mystery binaries, git repos | Non-RPM Software |
|  **kernel** | Sysctl overrides, modules-load.d, dracut config, GRUB args | Kernel / Boot |
|  **selinux** | SELinux booleans, audit rules, custom policy modules | SELinux / Security |
|  **users** | App users/groups, sudoers rules, SSH keys, subuid/subgid | Users / Groups |
|  **secrets** | Fake AWS keys, PEM keys, DB connection strings, API tokens | Secrets (redaction) |

## Features

-  **Single file, stdlib-only Python 3** — `curl` it onto a VM and run it. No pip, no venv, no bootstrapping.
-  **Profiles** — minimal for CI, standard for demos, kitchen-sink for stress testing.
-  **Per-section skip flags** — `--skip-SECTION` to leave individual categories untouched.
-  **Dry-run mode** — `--dry-run` prints every command without executing anything.
-  **Undo support** — `--undo` reverses all modifications using a JSON stamp file at `/etc/driftify.stamp`. Stamp tracks dnf transaction IDs, created files, enabled services, SELinux booleans, and more.
-  **OS auto-detection** — reads `/etc/os-release` to select the correct EPEL URL and adapt package names for EL9 vs EL10.
-  **Idempotent** — safe to run twice without breaking the system.
-  **Fake secrets** — plants realistic-looking but obviously synthetic credentials (AWS keys, PEM blocks, DB connection strings) to exercise yoinkc's redaction.
-  **Human-readable output** — colored section banners with Nerd Font icons and step counters. Degrades gracefully to plain text when stdout is not a TTY.

## Implementation status

Sections are being implemented iteratively:

- [x]  RPM / Packages
- [x]  Services
- [ ]  Config Files
- [ ]  Network
- [ ]  Storage
- [ ]  Scheduled Tasks
- [ ]  Containers
- [ ]  Non-RPM Software
- [ ]  Kernel / Boot
- [ ]  SELinux / Security
- [ ]  Users / Groups
- [ ]  Secrets

## Requirements

- Python 3.6+ (present on RHEL/CentOS Stream 9 and 10 minimal installs)
- Root access
- Network access (for dnf repos, EPEL, pip packages, binary downloads)
