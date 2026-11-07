# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **requirements.txt beside the pip venvs** — `/opt/myapp/requirements.txt` (minimal) and `/opt/legacy-app/requirements.txt` (standard) are generated from `pip freeze --local`, with a static pinned fallback. inspectah rates a venv high confidence only when a manifest sits beside it, so without these files no fixture ever produced a high-confidence venv.
- **Legacy-app venv at `/opt/legacy-app/venv`** (standard) — `--system-site-packages` paired with a requirements.txt and pure-Python packages, covering the system-site-packages flag at high confidence and with no C extensions. The kitchen-sink `/opt/shared-venv` continues to cover the same flag at medium confidence.
- **Venv at `/apps/reporting/venv`** (minimal) — sits outside every default scan root, so it is only detected when the scan is run with `--scan-path /apps/reporting`.
- **nginx on port 8081 with an `http_port_t` label** (standard): the managed nginx server block listens on 8081 instead of 8080, `semanage port -a -t http_port_t -p tcp 8081` labels the port, and firewalld opens 8081/tcp; undo removes all three. This replaces the custom SELinux port label the removed sshd port move used to provide, on a package the profile already configures, so inspectah still has a port label to detect and render as a `semanage port` line.
- **`StateDirectory=myapp` in `/usr/lib/systemd/system/myapp.service`** (standard) — gives `/var/lib/myapp` a declarative backing, exercising the StateDirectory class of inspectah's /var backing classification.

### Changed

- **`run-fleet-test.sh` scans beyond the default roots** — each scan now passes `--scan-path /apps/reporting` and `--scan-home appuser`, without which the new `/apps` venv and the existing appuser home environments never reach the fleet tarballs.

### Removed

- **sshd port move** (standard, kitchen-sink): driftify no longer sets `Port 2222` or `Port 2200` in `/etc/ssh/sshd_config`, opens those ports in firewalld, or adds an `ssh_port_t` SELinux label for them. The port move gave inspectah nothing to detect that the other sshd_config directives do not, and on a host that was not reverted it left sshd off port 22, so every ssh connection was refused. `PermitRootLogin no` (standard) and the cipher, MAC, and kex overrides (kitchen-sink) remain.

### Fixed

- **nginx server block lands outside `http {}`**: driftify now inserts its managed `server` block into `/etc/nginx/nginx.conf` just before the `http` block's closing brace, and skips it with a warning if it cannot find that brace. It used to append the block after the `http` block, where `nginx -t` rejects it with `"server" directive is not allowed here`, so a drifted host had nginx enabled but unable to start. The minimal profile's block also moves from port 8080, which httpd's drifted `Listen 8080` already claims, to port 81, which is in the stock `http_port_t` set and so still needs no SELinux label.
- **Undo leaves stale ssh port openings and labels**: undo again removes the 2222/tcp and 2200/tcp firewalld openings and their `ssh_port_t` SELinux labels. driftify no longer creates them, but a host drifted by an older driftify still carries them, and undo had stopped cleaning them up.
