# Coverage Detail

Detailed breakdown of what each driftify section installs, configures, or modifies, organized by profile tier.

## rpm

Repo setup (EPEL on EL, RPM Fusion Free on Fedora), base + extra-repo packages, RPM Fusion packages (x264/x265 at minimal, chromaprint-tools/unrar at standard, ffmpeg at kitchen-sink), ghost package (install-then-remove), node_exporter package (logging/monitoring standard+), AIDE package (logging/monitoring kitchen-sink).

## services

Enable httpd/nginx, disable kdump, mask bluetooth, drop-in overrides (httpd at standard, nginx at kitchen-sink), node_exporter service (logging/monitoring standard+), legacy SysVinit script (legacy compat standard+), xinetd service (legacy compat kitchen-sink), systemd unit shadow for sshd (unit shadows standard+).

## config

Modified RPM-owned configs, unowned app configs, orphaned configs, IPA client certs (auth/identity standard+), keytab files (auth/identity standard+), SSSD config/cache (auth/identity standard+), PAM faillock config (auth/identity standard+), custom PAM drop-in (auth/identity standard+), authselect profile (auth/identity standard+), AD/winbind smb.conf (auth/identity kitchen-sink), LDAP cert (auth/identity kitchen-sink), tmpfiles.d entries for appone/cleanup (tmpfiles.d standard+), tmpfiles.d age-based cleanup (tmpfiles.d kitchen-sink), custom tuned profile dir (performance tuning standard+), rsyslog forwarding config (logging/monitoring standard+), journald config (logging/monitoring standard+), AIDE config (logging/monitoring kitchen-sink), logrotate config (logging/monitoring kitchen-sink), auditd rules (logging/monitoring kitchen-sink), cross-tree symlinks /etc→/var, /opt→/usr (cross-tree symlinks standard+), nested symlink chains (cross-tree symlinks kitchen-sink), xinetd config (legacy compat kitchen-sink), anacrontab entries (legacy compat kitchen-sink), cron.allow (legacy compat kitchen-sink).

## network

Firewalld rules, custom zones, /etc/hosts entries, NetworkManager profiles, proxy environment, ifcfg network config (legacy compat standard+).

## storage

NFS/CIFS fstab entries, app data dirs under /var, unbacked /var dirs (pgsql, myapp, cache) (tmpfiles.d standard+), mixed-backing /var tree (tmpfiles.d kitchen-sink).

## scheduled

Cron jobs, systemd timers, at jobs, per-user crontabs.

## containers

Quadlet .container/.network units, docker-compose.yml.

## nonrpm

pip venvs, npm projects, Go binaries, mystery binaries, git repos, /usr/bin/custom-tool (files in /usr standard+), /usr/lib/systemd/system/myapp.service (files in /usr standard+), /usr/share/myapp/ (files in /usr standard+), /usr/sbin/custom-daemon (files in /usr kitchen-sink), /usr/lib64/libcustom.so (files in /usr kitchen-sink), /usr/libexec/myapp-helper (files in /usr kitchen-sink).

## kernel

Sysctl overrides, modules-load.d, dracut config, GRUB args, hugepages sysctl (performance tuning standard+), THP disable (live+GRUB+sysctl) (performance tuning standard+), CPU isolation GRUB args (performance tuning kitchen-sink), IRQ affinity (performance tuning kitchen-sink), NUMA sysctl (performance tuning kitchen-sink).

## platform

EL8 detection (el8 support standard+), _try_install wrapper (el8 support standard+), _el8_safe_tmpfiles wrapper (el8 support standard+).

## selinux

SELinux booleans, audit rules, custom policy modules.

## users

App users/groups, sudoers rules, SSH keys, subuid/subgid.

## secrets

Fake AWS keys, PEM keys, DB connection strings, API tokens.
