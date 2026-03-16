# Driftify Undo Design

**Date:** 2026-03-16
**Status:** Proposed

## Problem

Driftify makes significant system-wide changes and provides no cleanup
mechanism. Testing fleet workflows requires re-running driftify on the
same VM, but without undo the only option is restoring a VM snapshot.
This slows down the test-iterate cycle significantly.

## Goal

Add `--undo` and `--undo-first` flags for good-enough reversal of
driftify changes — enough that re-running produces meaningful, testable
results. Not pixel-perfect restoration; some residual state is
acceptable on a throwaway test VM.

## Scope

**Files:**
- Modify: `driftify.py` — add undo methods, CLI flags, managed block
  removal helper
- Modify: `run-fleet-test.sh` — pass `--undo-first` on every invocation

## CLI Flags

**`--undo`** — standalone flag. Reverses previous driftify run and
exits. No drift is applied.

**`--undo-first`** — prefix flag. Runs undo, then proceeds with normal
drift using the remaining arguments. Example:
```bash
./driftify.py --undo-first --profile standard -y
```

**Guard:** both flags check for `/etc/driftify.stamp`. No stamp = fresh
system = skip undo silently. After successful undo, stamp file is
removed.

## run-fleet-test.sh

Pass `--undo-first` on every driftify invocation. On first run (no
stamp), undo is skipped automatically. On subsequent runs, undo cleans
up before re-applying drift.

## Undo Operations

Top-level `undo()` method calls individual `undo_*` methods in reverse
order of drift. Each `undo_*` method is best-effort — catches
exceptions and continues so one failure doesn't abort the rest.

Undo always reverses everything from the previous run, regardless of
what `--skip-*` flags were used originally. No interaction between
`--skip-*` and undo.

### undo_secrets

- Remove managed blocks from config files that `drift_secrets` appended
  to (app.conf, env files, etc.)
- Unset environment variables if stored in profile files

### undo_users

- Remove created users (`userdel -r`): appuser, svcaccount, developers
  group members
- Remove created groups (`groupdel`): developers, etc.
- Remove sudoers files from `/etc/sudoers.d/`
- Remove planted SSH authorized_keys entries

### undo_selinux

- Restore SELinux booleans to defaults (`setsebool`)
- Remove custom policy modules (`semodule -r`)
- Remove audit rules

### undo_kernel

- Remove sysctl managed block, reload sysctl
- Unload added kernel modules (`modprobe -r`)
- Note: grub/dracut changes may persist — acceptable residual

### undo_nonrpm

- Remove Python venvs (`/opt/myapp-venv/`, etc.)
- Remove npm projects (`/opt/dashboard/`)
- Remove git repos (`/opt/internal-tools/`)
- Remove Go binaries (`/usr/local/bin/` installed binaries)

### undo_containers

- Remove quadlet files from `/etc/containers/systemd/`
- Remove docker-compose files
- `systemctl daemon-reload`

### undo_scheduled

- Remove cron managed block from `/etc/crontab`
- Remove at jobs
- Stop and remove systemd timer units
- `systemctl daemon-reload`

### undo_storage

- Remove fstab managed block
- Remove autofs config entries
- Unmount added mount points

### undo_network

- Remove firewall rules (`firewall-cmd --permanent --remove-*`)
- `firewall-cmd --reload`
- Remove `/etc/hosts` managed block
- Delete NetworkManager connection profiles

### undo_config

- Remove managed blocks from modified files (chrony.conf, httpd.conf,
  etc.) using `_remove_managed_block()`
- Delete created files and directories:
  - `/etc/myapp/` (entire directory)
  - `/etc/myapp/database.conf`
  - Any other files created by `_write_managed_text()`
- Restore directive-edited files: for files modified via
  `_apply_directives()` (e.g., sshd_config), reversal is imperfect —
  we can remove the added keys but can't restore original values of
  overwritten keys. Acceptable residual.

### undo_services

- Stop and disable services started by driftify (httpd, nginx)
- Unmask services that were masked (bluetooth)
- Remove drop-in files (`/etc/systemd/system/*.service.d/`)
- `systemctl daemon-reload`

### undo_rpm

- `dnf remove -y` the known package lists (base packages, EPEL
  packages, RPM Fusion packages)
- Remove EPEL/RPM Fusion repos if installed by driftify
- No tracking of "was it already installed" — just remove the known
  lists. Throwaway VM, acceptable.

## New Helper: `_remove_managed_block(path, marker)`

Counterpart to `_append_managed_block()`. Reads the file, finds the
marker-delimited block (`# BEGIN driftify managed block: {marker}` /
`# END driftify managed block: {marker}`), strips it, writes back.
Returns quietly if file doesn't exist or marker not found.

## Stamp File

- `/etc/driftify.stamp` — already exists, records profile/OS/status
- Undo checks for its existence before running
- Stamp is removed after successful undo
- A new stamp is written after a successful drift run (existing
  behavior)

## Testing

- `./driftify.py --undo` on a drifted VM — verify files/packages/
  services cleaned up, stamp removed
- `./driftify.py --undo` on a fresh VM — verify no-op (no stamp)
- `./driftify.py --undo-first --profile standard -y` — verify undo
  runs then drift re-applies
- `run-fleet-test.sh` twice on same VM — verify second run produces
  clean results
- Spot check: after undo + re-drift, run yoinkc and verify report
  looks consistent (no duplicate entries or residual ghost items)
