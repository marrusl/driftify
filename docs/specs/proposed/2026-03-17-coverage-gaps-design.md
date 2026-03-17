# Driftify Coverage Gaps

**Date:** 2026-03-17
**Status:** Proposed

## Problem

yoinkc has added several inspection categories that driftify doesn't create examples for. Operators testing with driftify profiles won't see these categories populated in reports, so they can't verify the rendering or triage workflow for those items.

## Gaps (10 items)

| # | Category | What to add | Profile |
|---|----------|-------------|---------|
| 1 | Crypto policy | `update-crypto-policies --set FUTURE` | minimal |
| 2 | Locale/timezone | `localectl set-locale LANG=en_GB.UTF-8` + `timedatectl set-timezone America/Chicago` | minimal |
| 3 | Tuned profile | `tuned-adm profile throughput-performance` | standard |
| 4 | nsswitch.conf | Modify `/etc/nsswitch.conf` — add `sss` to passwd/group/shadow lines | standard |
| 5 | SSSD + Kerberos | `dnf install -y sssd sssd-krb5` + write `/etc/sssd/sssd.conf` (LDAP+Kerberos domain) + write `/etc/krb5.conf` (example realm) + `systemctl enable sssd` | standard |
| 6 | Alternatives | `alternatives --set python3 /usr/bin/python3.11` (or whatever python3 version is available) | standard |
| 7 | SELinux file contexts | `semanage fcontext -a -t httpd_sys_content_t '/srv/www(/.*)?'` + `restorecon -Rv /srv/www` (create /srv/www first) | standard |
| 8 | Mixed 32/64-bit | `dnf install -y glibc.i686` | kitchen-sink |
| 9 | Duplicate packages | Force-install an older version of a small package alongside the current one (e.g., `rpm --force -i <older-rpm-url>`) — or use `dnf install --allowerasing` if feasible. This is inherently hacky; if it's too fragile, skip and document why. | kitchen-sink |
| 10 | Ruby gems | `dnf install -y ruby` + `gem install bundler sinatra --no-document` | kitchen-sink |

## Profile Distribution Rationale

- **Minimal** (1-2): crypto policy and locale/timezone are universal — every host has them, and changing them is a common first step in hardening or localization.
- **Standard** (3-7): tuned, nsswitch, SSSD/Kerberos, alternatives, and SELinux file contexts are standard enterprise configuration. SSSD+nsswitch go together (identity stack). Alternatives is common after multi-version Python installs. SELinux file contexts pair with the existing port labels already in standard.
- **Kitchen-sink** (8-10): mixed arch, duplicate packages, and Ruby gems are edge cases or legacy scenarios. Duplicates especially — they're rare in clean environments and the installation mechanism is fragile.

## Implementation Notes

### Item 5 (SSSD + Kerberos)

Example `/etc/sssd/sssd.conf`:
```ini
[sssd]
domains = example.com
services = nss, pam

[domain/example.com]
id_provider = ldap
auth_provider = krb5
ldap_uri = ldap://ldap.example.com
krb5_server = kerberos.example.com
krb5_realm = EXAMPLE.COM
```

Example `/etc/krb5.conf`:
```ini
[libdefaults]
default_realm = EXAMPLE.COM
dns_lookup_realm = false
dns_lookup_kdc = true

[realms]
EXAMPLE.COM = {
    kdc = kerberos.example.com
    admin_server = kerberos.example.com
}

[domain_realm]
.example.com = EXAMPLE.COM
example.com = EXAMPLE.COM
```

Permissions: `sssd.conf` must be `0600` owned by root or sssd won't start. The driftify method should `chmod 0600` after writing.

### Item 4 (nsswitch.conf)

Use sed to append `sss` to the passwd, group, and shadow lines:
```bash
sed -i 's/^passwd:.*/& sss/' /etc/nsswitch.conf
sed -i 's/^group:.*/& sss/' /etc/nsswitch.conf
sed -i 's/^shadow:.*/& sss/' /etc/nsswitch.conf
```

This pairs with SSSD — the nsswitch change tells the system to look up users/groups via SSSD.

### Item 6 (Alternatives)

The available python3 version depends on the base image. Use a detection approach:
```python
# Find what python3 alternatives exist
result = subprocess.run(['alternatives', '--display', 'python3'], capture_output=True, text=True)
# Parse available options and pick one that isn't the current default
```

If only one python3 version exists, skip gracefully with a log message.

### Item 9 (Duplicate packages)

This is the most fragile item. Options:
- Download an older version of a small package (e.g., `zlib`) from the vault and `rpm --force --nodeps -i` it
- Accept that this may not work on all base images
- If it fails, the method should log a warning and continue (not abort the profile)

### Item 7 (SELinux file contexts)

Create the target directory first:
```bash
mkdir -p /srv/www
semanage fcontext -a -t httpd_sys_content_t '/srv/www(/.*)?'
restorecon -Rv /srv/www
```

### Undo support

Each new method needs a corresponding undo entry in the `_undo_*` methods:
- Crypto policy: `update-crypto-policies --set DEFAULT`
- Locale: `localectl set-locale LANG=en_US.UTF-8`
- Timezone: `timedatectl set-timezone UTC` (or America/New_York — whatever the base default is)
- Tuned: `tuned-adm profile virtual-guest` (common default)
- nsswitch: sed to remove `sss` from passwd/group/shadow lines
- SSSD: `systemctl disable sssd` + `dnf remove -y sssd sssd-krb5` + rm config files
- Alternatives: `alternatives --auto python3`
- SELinux fcontext: `semanage fcontext -d '/srv/www(/.*)?'` + `rm -rf /srv/www`
- Mixed arch: `dnf remove -y glibc.i686`
- Duplicates: best-effort `rpm -e --nodeps <older-package>` or skip
- Ruby: `gem uninstall bundler sinatra -x` + `dnf remove -y ruby`

## Cross-Profile Variant Opportunities

Item 4 (nsswitch.conf) is a good candidate for cross-profile variants for fleet testing — minimal could leave it unchanged, standard adds `sss`, kitchen-sink could add `sss winbind`. This creates content variants that exercise the fleet comparison UI.

## Out of Scope

- PAM custom modules (deferred in yoinkc gap audit)
- NIC naming risk detection (deferred — P1)
- sshd_config parse (deferred — P1)
- New yoinkc inspectors — this spec only adds driftify fixtures for existing inspectors

## Testing

- Run each profile individually and verify yoinkc reports show the new categories populated
- Run fleet test (`run-fleet-test.sh`) and verify aggregation handles the new items
- Verify undo reverses each change cleanly
