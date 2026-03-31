# Coverage Detail

Detailed breakdown of what each driftify section installs, configures, or modifies, organized by profile tier.

## rpm

Repo setup (EPEL on EL, RPM Fusion Free on Fedora), base + extra-repo packages, RPM Fusion packages (x264/x265 at minimal, chromaprint-tools/unrar at standard, ffmpeg at kitchen-sink), ghost package (install-then-remove).

## services

Enable httpd/nginx, disable kdump, mask bluetooth, drop-in overrides (httpd at standard, nginx at kitchen-sink).

## config

Modified RPM-owned configs, unowned app configs, orphaned configs.

## network

Firewalld rules, custom zones, /etc/hosts entries, NetworkManager profiles, proxy environment.

## storage

NFS/CIFS fstab entries, app data dirs under /var.

## scheduled

Cron jobs, systemd timers, at jobs, per-user crontabs.

## containers

Quadlet .container/.network units, docker-compose.yml.

## nonrpm

pip venvs, npm projects, Go binaries, mystery binaries, git repos.

## kernel

Sysctl overrides, modules-load.d, dracut config, GRUB args.

## selinux

SELinux booleans, audit rules, custom policy modules.

## users

App users/groups, sudoers rules, SSH keys, subuid/subgid.

## secrets

Fake AWS keys, PEM keys, DB connection strings, API tokens.
