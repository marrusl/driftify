# driftify

Apply synthetic drift to a fresh RHEL, CentOS Stream, or Fedora system so that [yoinkc](https://github.com/marrusl/yoinkc) has something to detect.

## Why?

driftify creates controlled, reproducible drift for testing yoinkc inspectors without needing access to production infrastructure. It validates the full migration workflow end-to-end: inspect, refine, architect. It also lets you reproduce specific edge cases (SELinux modules, compiled binaries, stacked containers) by toggling profiles and skip flags.

> **Intended use:** driftify is designed to run on throwaway VMs. It makes significant system-wide changes and provides no cleanup mechanism. Use VM snapshots to restore prior state.

## Quick start

```bash
curl -LO https://raw.githubusercontent.com/marrusl/driftify/main/driftify.py
chmod +x driftify.py
sudo ./driftify.py          # standard profile (interactive confirm)
```

No dependencies beyond Python 3 (ships on every RHEL, CentOS Stream, and Fedora minimal install).

## Complete workflow

driftify is the fixture half of the yoinkc development workflow. Apply drift, then run yoinkc to inspect what changed:

```bash
# 1. Apply synthetic drift
sudo ./driftify.py --profile standard -y

# 2. Run yoinkc to inspect the drifted system
curl -fsSL https://raw.githubusercontent.com/marrusl/yoinkc/main/run-yoinkc.sh | sudo bash

# Or use driftify's built-in handoff:
sudo ./driftify.py --profile standard -y --run-yoinkc
```

The `--run-yoinkc` flag downloads and runs `run-yoinkc.sh` immediately after drift is applied, writing artifacts to `--yoinkc-output` (default: `./yoinkc-output`). The output includes an inspection snapshot, HTML report, and Containerfile ready for `yoinkc refine` and `yoinkc architect`.

## Usage

```bash
sudo ./driftify.py                          # standard profile (interactive confirm)
sudo ./driftify.py -y                       # skip confirmation prompt
sudo ./driftify.py -q                       # quiet output
sudo ./driftify.py --profile minimal        # CI-friendly, fast
sudo ./driftify.py --profile kitchen-sink   # everything
sudo ./driftify.py --skip-nonrpm            # standard minus non-RPM software
sudo ./driftify.py --dry-run                # preview without changes
sudo ./driftify.py --run-yoinkc             # apply drift then run yoinkc
sudo ./driftify.py --undo                   # reverse a previous driftify run
sudo ./driftify.py --undo-first             # reverse previous run, then apply drift
```

## CLI reference

### Main subcommand (default)

| Flag | Description |
|------|-------------|
| `--profile PROFILE` | `minimal`, `standard` (default), or `kitchen-sink` |
| `--skip-SECTION` | Skip a section (e.g. `--skip-rpm`, `--skip-services`, `--skip-nonrpm`) |
| `--dry-run` | Print commands without executing them |
| `--undo` | Reverse a previous driftify run and exit |
| `--undo-first` | Reverse previous run, then apply drift normally |
| `-y`, `--yes` | Skip interactive confirmation prompt |
| `-q`, `--quiet` | Show only section banners, warnings, and errors |
| `--verbose` | Reserved for future use |
| `--run-yoinkc` | After applying drift, download and run `run-yoinkc.sh` |
| `--yoinkc-output DIR` | Output directory for yoinkc artifacts (default: `./yoinkc-output`) |

#### Sections

Each `--skip-SECTION` flag controls one drift category:

`rpm` `services` `config` `network` `storage` `scheduled` `containers` `nonrpm` `kernel` `selinux` `users` `secrets`

### `topology` subcommand

Generate fleet topology fixture directories for testing `yoinkc architect`.

```bash
./driftify.py topology --list                              # list available topologies
./driftify.py topology three-role-overlap /tmp/fixtures/    # generate fixture directory
./driftify.py topology hardware-split /tmp/hw-fixtures/     # another topology
```

| Argument / Flag | Description |
|-----------------|-------------|
| `topology_name` | Name of the topology (e.g., `three-role-overlap`, `hardware-split`) |
| `output_dir` | Directory to write fleet fixture subdirectories into |
| `--list` | List available topologies and exit |

## Profiles

| Profile | What it does | Time |
|---------|-------------|------|
| **minimal** | Just enough to light up every yoinkc inspector with at least one finding. No heavy downloads. Good for CI. | ~1-2 min |
| **standard** | A realistic "moderately customized app server." Multiple findings per inspector, enough for a compelling demo. | ~2-4 min |
| **kitchen-sink** | Everything: dev tools, compiled binaries, complex configs, edge cases. Exercises yoinkc's deep-scan paths. | ~5-10 min |

Profiles are cumulative: `standard` includes everything in `minimal`, and `kitchen-sink` includes everything in `standard`.

## Coverage map

| Section | yoinkc inspector | What driftify plants |
|---------|-----------------|---------------------|
| rpm | Package inspector | Repo setup, base + extra-repo packages, ghost packages |
| services | Service inspector | Enabled/disabled/masked services, drop-in overrides |
| config | Config inspector | Modified RPM-owned configs, unowned app configs, orphaned configs |
| network | Network inspector | Firewalld rules, custom zones, /etc/hosts, NM profiles |
| storage | Storage inspector | NFS/CIFS fstab entries, app data dirs |
| scheduled | Scheduled inspector | Cron jobs, systemd timers, at jobs |
| containers | Container inspector | Quadlet units, docker-compose.yml |
| nonrpm | Non-RPM inspector | pip venvs, npm projects, Go binaries, git repos |
| kernel | Kernel inspector | Sysctl overrides, modules-load.d, dracut, GRUB args |
| selinux | SELinux inspector | Booleans, audit rules, custom policy modules |
| users | User inspector | App users/groups, sudoers, SSH keys |
| secrets | Secrets inspector | Fake AWS keys, PEM blocks, DB strings, API tokens |

For per-profile breakdowns of each section, see [docs/coverage-detail.md](docs/coverage-detail.md).

## Features

- **Single file, stdlib-only Python 3** -- `curl` it onto a VM and run it. No pip, no venv, no bootstrapping.
- **Profiles** -- minimal for CI, standard for demos, kitchen-sink for stress testing.
- **Per-section skip flags** -- `--skip-SECTION` to leave individual categories untouched.
- **Dry-run mode** -- `--dry-run` prints every command without executing anything.
- **Undo support** -- `--undo` reverses a previous run; `--undo-first` reverses then reapplies.
- **Run record** -- writes `/etc/driftify.stamp` on completion with profile, OS, and timestamps.
- **OS auto-detection** -- reads `/etc/os-release` to adapt for EL9, EL10, and Fedora.
- **Idempotent** -- safe to run twice without breaking the system.
- **Fake secrets** -- plants realistic-looking but obviously synthetic credentials to exercise yoinkc's redaction.
- **Human-readable output** -- colored section banners with step counters. Degrades to plain text when stdout is not a TTY.
- **yoinkc handoff** -- `--run-yoinkc` downloads and runs `run-yoinkc.sh` immediately after drift is applied.

## Fleet testing

`run-fleet-test.sh` automates the full fleet test loop: applies all three driftify profiles in sequence, runs yoinkc after each with a unique hostname, then aggregates the results into a fleet tarball.

```bash
curl -fsSL https://raw.githubusercontent.com/marrusl/driftify/main/run-fleet-test.sh -o run-fleet-test.sh
sudo bash run-fleet-test.sh
```

Since profiles are cumulative (minimal < standard < kitchen-sink), each successive tarball captures more drift. The fleet aggregation with `-p 67` naturally stratifies: minimal items appear on 3/3 hosts, standard-only on 2/3, kitchen-sink-only on 1/3.

The output is a fleet tarball with Containerfile, HTML report (with prevalence badges), and merged snapshot -- ready to open in a browser or pass to `yoinkc refine`.

Use driftify's multi-fleet topology fixtures to test `yoinkc architect` layer decomposition:

```bash
./driftify.py topology three-role-overlap /tmp/fixtures/
```

Each topology generates fleet-ready tarballs containing merged inspection snapshots with controlled inter-fleet variance, designed to exercise `yoinkc architect`'s base/derived layer decomposition.

## Requirements

- Python 3.6+ (present on all supported platforms)
- Root access
- Network access (for dnf repos, EPEL, pip packages, binary downloads)

### Supported platforms

| Platform | Status |
|---|---|
| CentOS Stream 9 | Tested |
| CentOS Stream 10 | Tested |
| RHEL 9.6+ | Tested |
| RHEL 10 | Tested |
| Fedora | Tested (RPM Fusion Free instead of EPEL) |

## Running tests

```bash
make test
```

## See also

- [yoinkc](https://github.com/marrusl/yoinkc) -- the inspection, refinement, and architect tool that driftify is built to exercise
- [yoinkc container image](https://github.com/marrusl/yoinkc/pkgs/container/yoinkc) -- pre-built container for running yoinkc without local setup
