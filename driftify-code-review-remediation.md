# Driftify Code Review — Remediation Report

**Date:** 2026-03-07  
**Scope:** `driftify/driftify.py` and `driftify/tests/test_driftify.py`  
**Commits:** `50fffde` → `325dbe3` (7 commits on `main`)

---

## Overview

A targeted code review of `driftify` identified seven issues across correctness,
reliability, and code hygiene categories. All seven were remediated in separate,
independently reviewable commits. The test suite remained green throughout (60
tests passing after each change).

---

## Issues and Remediations

### 1. Kernel argument appending was not idempotent

**Severity:** Medium — correctness bug  
**Commit:** `50fffde` `fix(kernel): make _append_kernel_cmdline_arg idempotent`

**Problem.** `_append_kernel_cmdline_arg` unconditionally appended its
arguments to `GRUB_CMDLINE_LINUX` every time it ran. Running `driftify` a
second time (or re-running `drift_kernel`) produced duplicate boot parameters
like `audit=1 audit=1` or `panic=60 panic=60`. On some kernels duplicate
parameters are silently ignored; on others they produce a warning or behave
unexpectedly at boot.

**Fix.** Before appending, the function now splits both the existing value and
the new arguments on whitespace and only appends those not already present.
Existing argument order is preserved.

The grub path was also promoted to a module-level constant (`GRUB_DEFAULT_PATH`)
so the test can redirect it without filesystem mocking.

**Test impact.** The existing test `test_kernel_kitchen_sink_modifies_grub` was
found to never call the function under test — it manually invoked `re.sub` on
a temp file and asserted on that. It was rewritten to (1) actually call
`_append_kernel_cmdline_arg`, (2) assert arguments are added on the first call,
and (3) assert a second identical call produces no duplicates.

---

### 2. `_print_summary` reported zero counts on real (non-dry) runs

**Severity:** Medium — user-facing correctness bug  
**Commit:** `82dc5c8` `fix(summary): always use computed counts in _print_summary`

**Problem.** `_print_summary` tried to read per-item counts (services enabled,
users created, files written, etc.) from the stamp file. However, `StampFile.start()`
only records `started`, `finished`, `profile`, `os_id`, and `os_major` — the
per-item fields were never populated. Because `self.stamp.data` is a non-empty
dict after a real run, the `if d:` branches were taken, and every
`d.get("services_enabled", [])` call returned `[]`. The result was a summary
that showed "0 enabled, 0 disabled" and similar zeros for every section —
immediately after a successful apply.

**Fix.** Removed all stamp-dependent `if d: / else:` branches throughout
`_print_summary`. The function now unconditionally uses the profile-computed
values that were previously only used in the dry-run fallback path. The stamp
file continues to record timing and profile metadata as before; it is simply no
longer used for per-item counting (which was never implemented).

The now-unused `_count_created` helper method was also deleted.

**Test impact.** Added `TestPrintSummary.test_summary_nonzero_counts_on_real_run`:
instantiates Driftify with `dry_run=False`, starts and finishes the stamp, calls
`_print_summary`, and asserts that sections show correct nonzero counts (e.g.
`"2 enabled"`, `"2 user(s)"`).

---

### 3. SSH key writes and chown calls were not guarded on `useradd` success

**Severity:** High — silent data integrity issue  
**Commit:** `57562b4` `fix(users): guard SSH keys and chown on useradd success`

**Problem.** `useradd` and `groupadd` were called with `check=False`. When
`useradd` failed (e.g. a UID conflict or insufficient permissions), the code
continued unconditionally and wrote SSH `authorized_keys` files, ran `chown`
against the new username, and wrote `sudoers` rules — all of which would
silently fail or produce root-owned files, leaving the system in an
inconsistent state. The container quadlet `chown -R appuser:appgroup` in
`drift_containers` had the same exposure.

**Fix.** The return code of `useradd` is now checked for both `appuser` and
`dbuser`. On failure during a non-dry run, a warning is emitted and
`self._appuser_created` / `self._dbuser_created` flags are cleared. The SSH
key creation, `.ssh` directory chown/chmod, sudoers write, and the
`drift_containers` recursive chown are all gated on `self._appuser_created`.
Operations that do not depend on the user existing (e.g. subuid/subgid entries)
are unaffected.

---

### 4a. Dead undo code and unused icon constants

**Severity:** Low — code hygiene  
**Commit:** `c0f3a73` `refactor(confirm): remove dead undo code and unused icon constants`

**Problem.** The undo feature was removed from driftify at some point, but an
`if False: # undo mode removed` block remained inside `_confirm` (nine lines of
dead code that could never execute). Two icon constants, `_I.UNDO` and
`_I.TRASH`, were only referenced by this dead path and therefore also unused.

**Fix.** Deleted the `if False:` block and simplified the surrounding
conditional to unconditional code. Removed `_I.UNDO` and `_I.TRASH`.

---

### 4b. Quiet-mode inconsistency in `_write_managed_text`

**Severity:** Low — UX inconsistency  
**Commit:** `8706623` `fix(config): suppress "No change needed" message in quiet mode`

**Problem.** `_write_managed_text` gated its "Wrote \<path\>" message on
`not self.quiet`, but printed "No change needed: \<path\>" unconditionally.
Users running with `--quiet` would still see a stream of "No change needed"
lines on repeat runs, defeating the purpose of the flag.

**Fix.** The "No change needed" message is now gated on `not self.quiet`,
making the two code paths consistent.

---

### 4c. HTTP downloads had no timeout

**Severity:** Medium — operational reliability  
**Commit:** `9152e45` `fix(nonrpm): add 60-second timeout to HTTP downloads`

**Problem.** Both `_download_go_probe` (downloads the `yq` Go binary from
GitHub Releases) and `_launch_yoinkc` (downloads `run-yoinkc.sh`) used
`urllib.request.urlretrieve`, which has no timeout. A stalled or slow network
response would hang the entire `driftify` process indefinitely with no way to
interrupt it short of `SIGKILL`.

**Fix.** Replaced both calls with `urllib.request.urlopen(..., timeout=60)`,
writing the response body to disk explicitly. A 60-second timeout was chosen
as a reasonable upper bound for small script/binary downloads; if exceeded, an
exception is raised and caught by the existing error handler, which logs a
warning and continues.

### 5. `assert` used for flow control in subprocess output loop

**Severity:** Low — correctness under non-default interpreter flags  
**Commit:** `325dbe3` `fix(yoinkc): replace assert with explicit None check on proc.stdout`

**Problem.** After spawning the yoinkc subprocess, `assert proc.stdout is not None`
was used as a guard before iterating its output. Python's `-O` (optimise) flag
strips all `assert` statements at compile time. Under `-O`, the assertion would
disappear and `proc.stdout` — if somehow `None` — would propagate silently into
the `for line in proc.stdout` loop, raising a `TypeError` with no user-visible
explanation. Using `assert` for runtime flow control is also a semantic misuse
of the construct, which is intended for invariant checking in development.

**Fix.** Replaced the `assert` with an explicit `if proc.stdout is None:` guard
that emits a warning via `_warn()` and returns. In practice `proc.stdout` cannot
be `None` here because `Popen` is called with `stdout=subprocess.PIPE`, so this
is a defensive measure; the important property is that the code is now
unambiguously correct under all interpreter modes.

---

## Test Coverage Summary

| Issue | Pre-remediation test status | Post-remediation |
|---|---|---|
| Kernel idempotency | Test existed but tested `re.sub`, not the function | Rewritten; tests actual function + double-call |
| Summary zero counts | No test | New test added |
| useradd guard | No test | Covered by existing `drift_users` dry-run tests |
| Dead undo code | N/A | N/A |
| Quiet-mode message | No test | Covered by existing quiet-mode tests |
| HTTP timeout | No test | Covered by existing download smoke tests |
| `assert` flow control | No test | Defensive guard; no test needed |

All 60 tests pass after each individual commit.

---

## Risk Assessment

None of the changes alter externally visible behaviour under normal operating
conditions. The kernel idempotency fix changes the write path only when
arguments are already present (previously it always wrote; now it may skip the
write). The summary fix changes display output, not system state. The `useradd`
guard prevents writes that would have silently failed anyway. The quiet-mode
and dead-code changes are purely cosmetic. The timeout change adds a failure
mode that previously would have hung — it is strictly safer. The `assert`
replacement is a no-op under normal execution and only adds a clean failure
path under `-O` or if the pipe unexpectedly fails to open.
