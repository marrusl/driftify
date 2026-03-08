# driftify

Apply synthetic drift to a fresh RHEL, CentOS Stream, or Fedora system so that [yoinkc](https://github.com/marrusl/yoinkc) has something to detect.

driftify is the fixture half of the yoinkc development workflow: run driftify on a clean host, then run yoinkc, and every inspector lights up with real findings — packages, configs, services, containers, secrets, the works.

> **Intended use:** driftify is designed to run on throwaway VMs that exist solely to exercise yoinkc. It makes significant system-wide changes and provides no cleanup mechanism. Use VM snapshots to restore prior state.

## Quick start

```bash
curl -LO https://raw.githubusercontent.com/marrusl/driftify/main/driftify.py
chmod +x driftify.py
sudo ./driftify.py                    # standard profile
```

No dependencies beyond Python 3 (ships on every RHEL, CentOS Stream, and Fedora minimal install).

## Usage

```
sudo ./driftify.py                          # standard profile (interactive confirm)
sudo ./driftify.py -y                       # skip confirmation prompt
sudo ./driftify.py -q                       # quiet output
sudo ./driftify.py --profile minimal        # CI-friendly, fast
sudo ./driftify.py --profile kitchen-sink   # everything
sudo ./driftify.py --skip-nonrpm            # standard minus non-RPM software
sudo ./driftify.py --dry-run                # preview without changes
sudo ./driftify.py --run-yoinkc             # apply drift then run yoinkc
```

## CLI reference

| Flag | Description |
|------|-------------|
| `--profile PROFILE` | `minimal`, `standard` (default), or `kitchen-sink` |
| `--skip-SECTION` | Skip a section (e.g. `--skip-rpm`, `--skip-services`, `--skip-nonrpm`) |
| `--dry-run` | Print commands without executing them |
| `-y`, `--yes` | Skip interactive confirmation prompt |
| `-q`, `--quiet` | Show only section banners, warnings, and errors. Does not suppress yoinkc output when using `--run-yoinkc`. |
| `--verbose` | Reserved for future use |
| `--run-yoinkc` | After applying drift, download and run `run-yoinkc.sh` |
| `--yoinkc-output DIR` | Output directory for yoinkc artifacts (default: `./yoinkc-output`) |
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

- 📦 **rpm** → EPEL repo, base + EPEL packages, ghost package (install-then-remove)
- ⚙️ **services** → Enable httpd/nginx, disable kdump, mask bluetooth
- 🔧 **config** → Modified RPM-owned configs, unowned app configs, orphaned configs
- 🌐 **network** → Firewalld rules, custom zones, /etc/hosts entries, NM profiles, proxy
- 💾 **storage** → NFS/CIFS fstab entries, app data dirs under /var
- ⏰ **scheduled** → Cron jobs, systemd timers, at jobs, per-user crontabs
- 🦭 **containers** → Quadlet .container/.network units, docker-compose.yml
- 🧩 **nonrpm** → pip venvs, npm projects, Go binaries, mystery binaries, git repos
- 🐧 **kernel** → Sysctl overrides, modules-load.d, dracut config, GRUB args
- 🛡️ **selinux** → SELinux booleans, audit rules, custom policy modules
- 👥 **users** → App users/groups, sudoers rules, SSH keys, subuid/subgid
- 🔑 **secrets** → Fake AWS keys, PEM keys, DB connection strings, API tokens

## Features

- **Single file, stdlib-only Python 3** → `curl` it onto a VM and run it. No pip, no venv, no bootstrapping.
- **Profiles** → minimal for CI, standard for demos, kitchen-sink for stress testing.
- **Per-section skip flags** → `--skip-SECTION` to leave individual categories untouched.
- **Dry-run mode** → `--dry-run` prints every command without executing anything.
- **Run record** → writes `/etc/driftify.stamp` on completion with profile, OS, and timestamps.
- **OS auto-detection** → reads `/etc/os-release` to select the correct EPEL URL and adapt package names for EL9, EL10, and Fedora (EPEL skipped on Fedora; packages are in the default repos).
- **Idempotent** → safe to run twice without breaking the system.
- **Fake secrets** → plants realistic-looking but obviously synthetic credentials (AWS keys, PEM blocks, DB connection strings) to exercise yoinkc's redaction.
- **Human-readable output** → colored section banners with Nerd Font icons and step counters. Degrades gracefully to plain text when stdout is not a TTY.
- **Interactive confirmation** → prints a plain-English summary of what will happen and asks `[y/N]` before touching anything. Use `-y` / `--yes` to bypass. Skipped automatically in `--dry-run` mode.
- **yoinkc handoff** → `--run-yoinkc` downloads and runs `run-yoinkc.sh` immediately after drift is applied, writing artifacts to `--yoinkc-output`.

## Running tests

```bash
make test
```

Equivalent direct command:

```bash
python3 -m unittest discover -s tests -v
```

## Requirements

- Python 3.6+ (present on all supported platforms)
- Root access
- Network access (for dnf repos, EPEL, pip packages, binary downloads)

### Supported platforms

| Platform | Status |
|---|---|
| CentOS Stream 9 | ✅ Tested |
| CentOS Stream 10 | ✅ Tested |
| RHEL 9.6+ | ✅ Tested |
| RHEL 10 | ✅ Tested |
| Fedora | ✅ Tested |
