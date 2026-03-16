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
- `Port 2222`
- `PermitRootLogin no`

**Kitchen-sink** (new — `drift_config`, `needs_profile("kitchen-sink")`):
Overwrite sshd_config with standard hardening PLUS:
- `Port 2200`
- `PermitRootLogin no`
- `Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com`
- `MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com`
- `KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org`

### 2. `/etc/chrony.conf`

**Standard** (existing or new — `drift_config`,
`needs_profile("standard")`):
- Append `server time1.example.com iburst`

**Kitchen-sink** (new — `drift_config`,
`needs_profile("kitchen-sink")`):
- Overwrite the appended server line(s) with:
  `server time1.internal.corp iburst`
  `server time2.internal.corp iburst`

Implementation: simplest approach is to re-read the file, replace the
standard server line, and write back. Or append the kitchen-sink lines
and remove the standard one via `sed`-style logic.

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

### 4. `/etc/myapp/app.conf`

**Standard** (existing — `drift_config`,
`needs_profile("standard")`):
- Creates the app.conf with standard settings

**Kitchen-sink** (new — `drift_config`,
`needs_profile("kitchen-sink")`):
- Overwrite with different values:
  Higher `max_connections`, different `log_level` (e.g., `debug` vs
  `info`), different `cache_size`, etc.

### 5. `/etc/systemd/system/httpd.service.d/limits.conf`

**Standard** (new — `drift_services`,
`needs_profile("standard")`):
- Create drop-in: `[Service]\nLimitNOFILE=8192`

**Kitchen-sink** (new — `drift_services`,
`needs_profile("kitchen-sink")`):
- Overwrite drop-in: `[Service]\nLimitNOFILE=65535\nLimitNPROC=4096`

Note: if this drop-in already exists in `drift_services`, the
kitchen-sink block just overwrites it. If not, both blocks create it.

## Implementation Pattern

For each file, the pattern is:

```python
if self.needs_profile("standard"):
    # existing or new standard-profile code
    self._write_file("/etc/path/file.conf", standard_content)

if self.needs_profile("kitchen-sink"):
    # overwrite with kitchen-sink variant
    self._write_file("/etc/path/file.conf", kitchen_sink_content)
```

For files that append (httpd.conf, chrony.conf), the kitchen-sink
block should append additional directives rather than overwrite, so the
content naturally differs from the standard-only version.

## Testing

- Run `./driftify.py --profile standard --dry-run` — verify standard
  config file operations listed
- Run `./driftify.py --profile kitchen-sink --dry-run` — verify
  kitchen-sink overwrite operations listed after standard ones
- Run fleet test (`run-fleet-test.sh`) — verify yoinkc-fleet aggregate
  produces multi-variant entries for all 5 files
- Open the fleet HTML report — verify variant grouping shows 2+
  variants for sshd_config, chrony.conf, httpd.conf, app.conf,
  limits.conf
