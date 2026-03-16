# Config Collision Variants Design

**Date:** 2026-03-16
**Status:** Proposed

## Problem

Driftify profiles create unique config files — no two profiles modify
the same file path with different content. This means fleet aggregation
(running all 3 profiles with unique hostnames) never produces
multi-variant config files. There's no way to test or demo yoinkc's
variant grouping, comparison, and selection features without manually
creating collisions.

## Scope

Changes to `driftify.py` only — add `kitchen-sink` profile overrides
for 5 files that `standard` already creates/modifies. No new methods,
CLI flags, or architectural changes.

## Design

Five files get cross-profile variants. The `standard` profile
creates/modifies each file. The `kitchen-sink` profile overwrites the
same file with different content. Since profiles are cumulative
(kitchen-sink includes standard), the kitchen-sink block runs after
the standard block and replaces the file.

Fleet test produces three runs:
- Run 1 (minimal): files untouched (original system defaults)
- Run 2 (standard): standard version of each file
- Run 3 (kitchen-sink): kitchen-sink version of each file

Fleet aggregation sees 2-3 variants per file depending on whether the
system default differs from both profile versions.

### 1. `/etc/ssh/sshd_config`

**Standard** (existing — `drift_config`, `needs_profile("standard")`):
Uses `_apply_directives()` for in-place key replacement:
- `Port 2222`
- `PermitRootLogin no`

**Kitchen-sink** (new — `drift_config`, `needs_profile("kitchen-sink")`):
Uses `_apply_directives()` to override/add keys:
- `Port 2200` (overrides standard's 2222)
- `Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com`
- `MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com`
- `KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org`

`PermitRootLogin no` is already set by standard and persists.

### 2. `/etc/chrony.conf`

**Standard** (existing — `drift_config`,
`needs_profile("standard")`):
Uses `_append_managed_block("chrony-servers", ...)` to add NTP servers.

**Kitchen-sink** (new — `drift_config`,
`needs_profile("kitchen-sink")`):
Uses `_append_managed_block("chrony-servers-ks", ...)` with a
**different marker** to add additional/different servers:
  `server time1.internal.corp iburst`
  `server time2.internal.corp iburst`

The standard block (`chrony-servers`) stays. The kitchen-sink block
(`chrony-servers-ks`) coexists with different content. The resulting
file differs from the standard-only version because it has both
blocks — producing a content-hash variant for fleet aggregation.

### 3. `/etc/httpd/conf/httpd.conf`

**Standard** (existing — `drift_config`,
`needs_profile("standard")`):
- Already modifies httpd.conf (existing drift directives)

**Kitchen-sink** (new — `drift_config`,
`needs_profile("kitchen-sink")`):
- Append additional directives:
  `MaxRequestWorkers 512`
  `ExtendedStatus On`

Since both append to the same file, the kitchen-sink version has all
standard directives PLUS the additional ones — making the content
different from the standard-only version.

### 4. `/etc/myapp/database.conf`

A new config file (not app.conf, which is created at minimal level
and also modified by `drift_secrets`).

**Standard** (new — `drift_config`,
`needs_profile("standard")`):
Create `/etc/myapp/database.conf` with:
```ini
[database]
host = localhost
port = 5432
max_connections = 50
log_level = info
pool_size = 10
```

**Kitchen-sink** (new — `drift_config`,
`needs_profile("kitchen-sink")`):
Overwrite with production-tuned values:
```ini
[database]
host = db.internal.corp
port = 5432
max_connections = 200
log_level = debug
pool_size = 50
connection_timeout = 30
```

### 5. `/etc/systemd/system/httpd.service.d/limits.conf`

**Standard** (new — `drift_services`,
`needs_profile("standard")`):
- Create drop-in: `[Service]\nLimitNOFILE=8192`

**Kitchen-sink** (new — `drift_services`,
`needs_profile("kitchen-sink")`):
- Overwrite drop-in: `[Service]\nLimitNOFILE=65535\nLimitNPROC=4096`

Note: if this drop-in already exists in `drift_services`, the
kitchen-sink block just overwrites it. If not, both blocks create it.

## Implementation Notes

- **sshd_config**: use `_apply_directives()` (in-place key replacement)
- **chrony.conf**: use `_append_managed_block()` with a different marker
- **httpd.conf**: use `_append_managed_block()` with a different marker
- **database.conf**: use `_write_managed_text()` (full file write)
- **limits.conf**: use `_write_file()` or equivalent (full file write)

Update `_run_description()` to reflect the new kitchen-sink operations
for each affected drift method.

## Testing

- Run `./driftify.py --profile standard --dry-run` — verify standard
  config file operations listed
- Run `./driftify.py --profile kitchen-sink --dry-run` — verify
  kitchen-sink overwrite operations listed after standard ones
- Run fleet test (`run-fleet-test.sh`) — verify yoinkc-fleet aggregate
  produces multi-variant entries for all 5 files
- Open the fleet HTML report — verify variant grouping shows 2+
  variants for sshd_config, chrony.conf, httpd.conf, database.conf,
  limits.conf
