#!/usr/bin/python3
"""driftify — apply synthetic drift to a fresh RHEL/CentOS Stream 9 or 10 system.

Companion tool to yoinkc.  Runs on a clean host and applies curated system
modifications so that every yoinkc inspector has something to detect.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

STAMP_PATH = Path("/etc/driftify.stamp")

PROFILES = ("minimal", "standard", "kitchen-sink")
PROFILE_RANK = {p: i for i, p in enumerate(PROFILES)}

SECTIONS = [
    "rpm", "services", "config", "network", "storage",
    "scheduled", "containers", "nonrpm", "kernel", "selinux",
    "users", "secrets",
]

EPEL_URLS = {
    9: "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm",
    10: "https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm",
}

BASE_PACKAGES = {
    "minimal": [
        "httpd", "nginx", "vim-enhanced", "tmux", "jq",
        "python3-pip", "git", "wget", "curl", "bind-utils",
    ],
    "standard": [
        "rsync", "lsof", "strace", "tcpdump", "nmap-ncat",
        "bash-completion", "man-pages", "info", "tree", "unzip",
    ],
    "kitchen-sink": [
        "gcc", "make", "kernel-devel", "gdb", "valgrind",
        "cmake", "autoconf", "automake", "libtool", "pkgconfig",
    ],
}

EPEL_PACKAGES = {
    "minimal": ["htop", "bat"],
    "standard": ["the_silver_searcher", "fd-find"],
    "kitchen-sink": ["fzf", "ripgrep", "hyperfine"],
}

GHOST_PACKAGE = "words"


# ── Nerd Font icons ──────────────────────────────────────────────────────────

class _I:
    ROCKET   = "\uf135"
    CHECK    = "\uf058"   # check-circle
    OK       = "\uf00c"   # check
    WARN     = "\uf071"   # exclamation-triangle
    ERROR    = "\uf057"   # times-circle
    EYE      = "\uf06e"   # eye (dry-run)
    SKIP     = "\uf04e"   # forward
    UNDO     = "\uf0e2"   # rotate-left
    PACKAGE  = "\uf187"   # archive
    COGS     = "\uf085"   # cogs
    WRENCH   = "\uf0ad"   # wrench
    GLOBE    = "\uf0ac"   # globe
    DATABASE = "\uf1c0"   # database
    CLOCK    = "\uf017"   # clock
    CUBES    = "\uf1b3"   # cubes (containers)
    PUZZLE   = "\uf12e"   # puzzle-piece
    LINUX    = "\uf17c"   # tux
    SHIELD   = "\uf132"   # shield
    USERS    = "\uf0c0"   # users
    KEY      = "\uf084"   # key
    DOWNLOAD = "\uf019"   # download
    TOGGLE   = "\uf205"   # toggle-on
    BAN      = "\uf05e"   # ban (disable)
    MASK     = "\uf070"   # eye-slash
    RECYCLE  = "\uf1b8"   # recycle (ghost)
    STAMP    = "\uf249"   # id-badge
    TRASH    = "\uf1f8"   # trash

SECTION_ICONS = {
    "rpm":        _I.PACKAGE,
    "services":   _I.COGS,
    "config":     _I.WRENCH,
    "network":    _I.GLOBE,
    "storage":    _I.DATABASE,
    "scheduled":  _I.CLOCK,
    "containers": _I.CUBES,
    "nonrpm":     _I.PUZZLE,
    "kernel":     _I.LINUX,
    "selinux":    _I.SHIELD,
    "users":      _I.USERS,
    "secrets":    _I.KEY,
}

SECTION_LABELS = {
    "rpm":        "RPM / Packages",
    "services":   "Services",
    "config":     "Config Files",
    "network":    "Network",
    "storage":    "Storage",
    "scheduled":  "Scheduled Tasks",
    "containers": "Containers",
    "nonrpm":     "Non-RPM Software",
    "kernel":     "Kernel / Boot",
    "selinux":    "SELinux / Security",
    "users":      "Users / Groups",
    "secrets":    "Secrets",
}


# ── ANSI helpers ─────────────────────────────────────────────────────────────

class _C:
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    RED    = "\033[31m"
    CYAN   = "\033[36m"
    RESET  = "\033[0m"

if not sys.stdout.isatty():
    _C.BOLD = _C.DIM = _C.GREEN = _C.YELLOW = _C.RED = ""
    _C.CYAN = _C.RESET = ""


def _banner(title: str) -> None:
    print(f"\n{_C.BOLD}{_C.CYAN}{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}{_C.RESET}")


def _section(icon: str, title: str, step: int, total: int) -> None:
    tag = f"{_C.DIM}[{step}/{total}]{_C.RESET}"
    print(f"\n{_C.BOLD}{_C.CYAN}{'─' * 60}")
    print(f"  {icon}  {title}  {tag}")
    print(f"{'─' * 60}{_C.RESET}")


def _info(msg: str) -> None:
    print(f"  {_C.GREEN}{_I.OK}{_C.RESET}  {msg}")


def _warn(msg: str) -> None:
    print(f"  {_C.YELLOW}{_I.WARN}{_C.RESET}  {msg}")


def _error(msg: str) -> None:
    print(f"  {_C.RED}{_I.ERROR}{_C.RESET}  {msg}", file=sys.stderr)


def _skip(msg: str) -> None:
    print(f"  {_C.DIM}{_I.SKIP}  {msg}{_C.RESET}")


def _dry(msg: str) -> None:
    print(f"  {_C.YELLOW}{_I.EYE}  [DRY RUN]{_C.RESET} {msg}")


# ── OS detection ─────────────────────────────────────────────────────────────

def detect_os() -> tuple:
    """Parse /etc/os-release → (os_id, os_major)."""
    info = {}
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                line = line.strip()
                if "=" in line:
                    key, _, val = line.partition("=")
                    info[key] = val.strip('"')
    except FileNotFoundError:
        _error("/etc/os-release not found — cannot detect OS")
        sys.exit(1)

    os_id = info.get("ID", "unknown")
    version_id = info.get("VERSION_ID", "0")

    try:
        os_major = int(version_id.split(".")[0])
    except (ValueError, IndexError):
        _error(f"Cannot parse VERSION_ID '{version_id}' from /etc/os-release")
        sys.exit(1)

    if os_id not in ("rhel", "centos") or os_major not in (9, 10):
        _warn(f"Detected {os_id} {version_id} — driftify targets RHEL/CentOS Stream 9 or 10")

    return os_id, os_major


# ── StampFile ────────────────────────────────────────────────────────────────

class StampFile:
    """JSON-backed ledger of everything driftify did, consumed by --undo."""

    def __init__(self, path=None):
        self.path = path or STAMP_PATH
        self.data: dict = {}

    def load(self) -> dict:
        if self.path.exists():
            with open(self.path) as fh:
                self.data = json.load(fh)
        return self.data

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            json.dump(self.data, fh, indent=2)
            fh.write("\n")
        tmp.rename(self.path)

    def start(self, profile: str, os_id: str, os_major: int) -> None:
        self.data = {
            "started": datetime.now(timezone.utc).isoformat(),
            "finished": None,
            "profile": profile,
            "os_id": os_id,
            "os_major": os_major,
            "dnf_transaction_start": None,
            "dnf_transaction_end": None,
            "ghost_package": None,
            "services_enabled": [],
            "services_disabled": [],
            "services_masked": [],
            "files_created": [],
            "dirs_created": [],
            "file_backups": {},
            "users_created": [],
            "groups_created": [],
            "firewall_services": [],
            "firewall_ports": [],
            "selinux_booleans": [],
            "selinux_modules": [],
        }
        self.save()

    def finish(self) -> None:
        self.data["finished"] = datetime.now(timezone.utc).isoformat()
        self.save()

    def record(self, key: str, value) -> None:
        """Append *value* to a list key, or set a scalar key.

        Mutates in-memory only.  Call ``save()`` at section boundaries.
        """
        if isinstance(self.data.get(key), list):
            if value not in self.data[key]:
                self.data[key].append(value)
        else:
            self.data[key] = value


# ── Driftify ─────────────────────────────────────────────────────────────────

class Driftify:

    _IMPLEMENTED = {"rpm", "services", "config", "network", "storage", "secrets"}

    def __init__(self, profile: str, dry_run: bool, skip_sections: list,
                 undo: bool = False):
        self.profile = profile
        self.dry_run = dry_run
        self.skip = set(skip_sections)
        self.undo_mode = undo
        self.stamp = StampFile()
        self.os_id, self.os_major = detect_os()
        self._t0 = None
        self._step = 0
        self._total = sum(
            1 for s in SECTIONS
            if s not in self.skip and s in self._IMPLEMENTED
        )

    # ── helpers ───────────────────────────────────────────────────────────

    def needs_profile(self, level: str) -> bool:
        """True when the active profile includes *level*."""
        return PROFILE_RANK[self.profile] >= PROFILE_RANK[level]

    def run_cmd(self, cmd, check=True, capture=False):
        """Execute *cmd*, or print it if --dry-run."""
        pretty = " ".join(str(c) for c in cmd)
        if self.dry_run:
            _dry(pretty)
            return None
        _info(f"Running: {pretty}")
        result = subprocess.run(
            cmd, check=check,
            capture_output=capture, text=capture,
        )
        if not check and result.returncode != 0:
            _warn(f"  ↳ exited {result.returncode}: {pretty}")
        return result

    def _dnf_last_tid(self):
        """Return the most recent dnf transaction ID, or None."""
        r = subprocess.run(
            ["dnf", "history", "list"],
            capture_output=True, text=True,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if parts and parts[0].isdigit():
                return int(parts[0])
        return None

    def _backup_file_once(self, path: Path) -> None:
        """Save original file content to stamp once."""
        if self.dry_run or not path.exists():
            return
        backups = self.stamp.data.setdefault("file_backups", {})
        key = str(path)
        if key in backups:
            return
        with open(path) as fh:
            backups[key] = fh.read()
        self.stamp.save()

    def _ensure_dir(self, path: Path) -> None:
        """Create directory (and track it) when needed."""
        if path.exists():
            return
        if self.dry_run:
            _dry(f"mkdir -p {path}")
            return
        path.mkdir(parents=True, exist_ok=True)
        self.stamp.record("dirs_created", str(path))
        _info(f"Created dir {path}")

    def _write_managed_text(self, path_str: str, content: str, mode: int = 0o644) -> None:
        """Write file with stamp tracking for created/modified files."""
        path = Path(path_str)
        exists = path.exists()

        if exists:
            with open(path) as fh:
                old = fh.read()
            if old == content:
                _info(f"No change needed: {path}")
                return
        else:
            old = None

        if self.dry_run:
            action = "update" if exists else "create"
            _dry(f"{action} file {path}")
            return

        self._ensure_dir(path.parent)
        if exists:
            self._backup_file_once(path)
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, mode)
        if not exists:
            self.stamp.record("files_created", str(path))
        _info(f"Wrote {path}")

    def _set_or_append_directive(self, path_str: str, key: str, line: str) -> None:
        """Set a config directive by key or append when missing (single directive)."""
        self._apply_directives(path_str, {key: line})

    def _apply_directives(self, path_str: str,
                          directives: dict) -> None:
        """Apply multiple key→line directive replacements to a file in one pass.

        Each key is matched against commented or uncommented lines; the first
        match is replaced with the supplied line.  Unmatched keys are appended.
        """
        path = Path(path_str)
        if not path.exists():
            for key in directives:
                _warn(f"{path} not found — skipping directive '{key}'")
            return

        with open(path) as fh:
            text = fh.read()
        lines = text.splitlines()
        remaining = dict(directives)

        for idx, existing in enumerate(lines):
            for key, line in list(remaining.items()):
                key_re = re.compile(
                    r"^\s*(#\s*)?" + re.escape(key) + r"(\s|=)"
                )
                if key_re.match(existing):
                    lines[idx] = line
                    del remaining[key]
                    break

        for line in remaining.values():
            lines.append(line)

        out = "\n".join(lines) + "\n"
        self._write_managed_text(path_str, out)

    def _append_managed_block(self, path_str: str, marker: str, block: str,
                              mode: int = 0o644, create_if_missing: bool = True) -> None:
        """Append an idempotent driftify-managed block to a file."""
        path = Path(path_str)
        begin = f"# BEGIN DRIFTIFY {marker}"
        end = f"# END DRIFTIFY {marker}"
        wrapped = f"{begin}\n{block.rstrip()}\n{end}\n"

        if path.exists():
            with open(path) as fh:
                current = fh.read()
        else:
            if not create_if_missing:
                _warn(f"{path} not found — skipping block '{marker}'")
                return
            current = ""

        if begin in current:
            _info(f"Block already present in {path}: {marker}")
            return

        prefix = current
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        if prefix and not prefix.endswith("\n\n"):
            prefix += "\n"

        self._write_managed_text(path_str, prefix + wrapped, mode=mode)

    # ── apply entry point ─────────────────────────────────────────────────

    def _next_step(self, section_name: str) -> None:
        """Print a section banner with icon and step counter."""
        self._step += 1
        _section(
            SECTION_ICONS[section_name],
            SECTION_LABELS[section_name],
            self._step, self._total,
        )

    def run(self) -> None:
        self._t0 = time.monotonic()

        _banner(f"{_I.ROCKET}  driftify — {self.profile} profile on "
                f"{self.os_id} {self.os_major}")

        if STAMP_PATH.exists():
            _warn(f"Existing stamp file at {STAMP_PATH} will be overwritten")
            _warn("(Run --undo first if you need to reverse the previous run)")

        if not self.dry_run:
            self.stamp.start(self.profile, self.os_id, self.os_major)

        self.drift_rpm()
        self.drift_services()
        self.drift_config()
        self.drift_network()
        self.drift_storage()
        # Future sections — will be added iteratively:
        # self.drift_scheduled()
        # self.drift_containers()
        # self.drift_nonrpm()
        # self.drift_kernel()
        # self.drift_selinux()
        # self.drift_users()
        self.drift_secrets()   # Must run after users (needs user homes for kitchen-sink secrets)

        if not self.dry_run:
            self.stamp.finish()

        self._print_summary()

    # ── undo entry point ──────────────────────────────────────────────────

    def run_undo(self) -> None:
        self._t0 = time.monotonic()
        _banner(f"{_I.UNDO}  driftify --undo")

        self.stamp.load()
        if not self.stamp.data:
            _error(f"No stamp file at {STAMP_PATH} — nothing to undo")
            sys.exit(1)

        _info(f"Stamp from {self.stamp.data.get('started', '?')}, "
              f"profile={self.stamp.data.get('profile', '?')}")

        self._undo_filesystem()
        self._undo_network()
        self._undo_services()
        self._undo_rpm()

        if not self.dry_run:
            self.stamp.path.unlink(missing_ok=True)
            _info(f"{_I.TRASH}  Stamp file removed")

        elapsed = time.monotonic() - self._t0
        _banner(f"{_I.CHECK}  Undo complete ({int(elapsed)}s)")

    # ── RPM / Packages ────────────────────────────────────────────────────

    def drift_rpm(self) -> None:
        if "rpm" in self.skip:
            _skip("Skipping RPM section (--skip-rpm)")
            return

        self._next_step("rpm")

        # Snapshot dnf history before we touch anything
        if not self.dry_run:
            tid = self._dnf_last_tid()
            self.stamp.record("dnf_transaction_start", tid)

        # EPEL repo — all profiles
        epel_url = EPEL_URLS.get(self.os_major)
        if epel_url:
            _info(f"{_I.GLOBE}  Enabling EPEL for EL{self.os_major}")
            self.run_cmd(["dnf", "install", "-y", epel_url], check=False)
        else:
            _warn(f"No EPEL URL for EL{self.os_major} — skipping EPEL")

        # Base-repo packages, cumulative across profile levels
        for level in PROFILES:
            if not self.needs_profile(level):
                break
            pkgs = BASE_PACKAGES.get(level, [])
            if pkgs:
                _info(f"{_I.DOWNLOAD}  Installing base packages ({level}): "
                      f"{', '.join(pkgs)}")
                self.run_cmd(
                    ["dnf", "install", "-y", "--setopt=strict=0"] + pkgs,
                    check=False,
                )

        # EPEL packages, cumulative
        for level in PROFILES:
            if not self.needs_profile(level):
                break
            pkgs = EPEL_PACKAGES.get(level, [])
            if pkgs:
                _info(f"{_I.DOWNLOAD}  Installing EPEL packages ({level}): "
                      f"{', '.join(pkgs)}")
                self.run_cmd(
                    ["dnf", "install", "-y", "--setopt=strict=0"] + pkgs,
                    check=False,
                )

        # Ghost package: install, drop orphaned config, remove (standard+)
        # This creates a dnf history entry AND an unowned /etc config file,
        # both of which yoinkc's RPM inspector is expected to detect.
        if self.needs_profile("standard"):
            _info(f"{_I.RECYCLE}  Ghost package: install + orphaned config "
                  f"+ remove '{GHOST_PACKAGE}'")
            self.run_cmd(["dnf", "install", "-y", GHOST_PACKAGE], check=False)
            self._write_managed_text(
                "/etc/words.conf",
                "# Simulated orphaned config — driftify synthetic fixture\n"
                "# This file is left behind after 'words' is removed,\n"
                "# exercising yoinkc unowned-file and dnf-ghost detection.\n"
                "dictionary = /usr/share/dict/words\n"
                "max_suggestions = 10\n",
            )
            self.run_cmd(["dnf", "remove", "-y", GHOST_PACKAGE], check=False)
            if not self.dry_run:
                self.stamp.record("ghost_package", GHOST_PACKAGE)

        # Snapshot final transaction ID
        if not self.dry_run:
            tid = self._dnf_last_tid()
            self.stamp.record("dnf_transaction_end", tid)
            self.stamp.save()

    # ── Services ──────────────────────────────────────────────────────────

    def drift_services(self) -> None:
        if "services" in self.skip:
            _skip("Skipping Services section (--skip-services)")
            return

        self._next_step("services")

        # Enable non-default services (minimal)
        for svc in ("httpd", "nginx"):
            _info(f"{_I.TOGGLE}  Enabling {svc}")
            self.run_cmd(["systemctl", "enable", svc], check=False)
            if not self.dry_run:
                self.stamp.record("services_enabled", svc)

        # Disable a default service (minimal)
        _info(f"{_I.BAN}  Disabling kdump")
        self.run_cmd(["systemctl", "disable", "kdump"], check=False)
        if not self.dry_run:
            self.stamp.record("services_disabled", "kdump")

        # Mask bluetooth if it exists (standard+)
        if self.needs_profile("standard"):
            _BT_UNIT_PATHS = [
                Path("/usr/lib/systemd/system/bluetooth.service"),
                Path("/lib/systemd/system/bluetooth.service"),
            ]
            if self.dry_run:
                bt_exists = any(p.exists() for p in _BT_UNIT_PATHS)
            else:
                r = subprocess.run(
                    ["systemctl", "cat", "bluetooth"],
                    capture_output=True, text=True,
                )
                bt_exists = r.returncode == 0

            if bt_exists:
                _info(f"{_I.MASK}  Masking bluetooth")
                self.run_cmd(["systemctl", "mask", "bluetooth"], check=False)
                if not self.dry_run:
                    self.stamp.record("services_masked", "bluetooth")
            else:
                _warn("bluetooth unit not found — skipping mask")

        if not self.dry_run:
            self.stamp.save()

    # ── Config Files ───────────────────────────────────────────────────────

    def drift_config(self) -> None:
        if "config" in self.skip:
            _skip("Skipping Config section (--skip-config)")
            return

        self._next_step("config")

        # Minimal: modify RPM-owned configs (batch directives per file)
        self._apply_directives("/etc/httpd/conf/httpd.conf", {
            "Listen":            "Listen 8080",
            "ServerName":        "ServerName driftify.local",
            "MaxRequestWorkers": "MaxRequestWorkers 256",
        })

        self._apply_directives("/etc/nginx/nginx.conf", {
            "worker_processes": "worker_processes 2;",
        })
        self._append_managed_block(
            "/etc/nginx/nginx.conf",
            "nginx-server-block",
            """server {
    listen 8080 default_server;
    server_name _;
    location / {
        return 200 "driftify nginx config drift\\n";
    }
}""",
            create_if_missing=False,
        )

        # Minimal: unowned configs in /etc
        self._ensure_dir(Path("/etc/myapp"))
        self._write_managed_text(
            "/etc/myapp/app.conf",
            """[app]
name = driftify-demo
environment = production
log_level = info
""",
        )
        self._write_managed_text(
            "/etc/myapp/database.yml",
            """production:
  adapter: postgresql
  host: db.internal
  port: 5432
  database: myapp
  username: appuser
""",
        )

        if self.needs_profile("standard"):
            self._apply_directives("/etc/ssh/sshd_config", {
                "PermitRootLogin": "PermitRootLogin no",
                "Port":            "Port 2222",
            })
            self._append_managed_block(
                "/etc/chrony.conf",
                "chrony-servers",
                """server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst""",
                create_if_missing=False,
            )
            self._write_managed_text(
                "/etc/profile.d/custom-env.sh",
                """#!/bin/sh
export APP_ENV=production
export LOG_LEVEL=info
""",
                mode=0o644,
            )
            self._write_managed_text(
                "/etc/logrotate.d/myapp",
                """/var/log/myapp/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
""",
            )

        if self.needs_profile("kitchen-sink"):
            self._append_managed_block(
                "/etc/security/limits.conf",
                "limits-nofile",
                """* soft nofile 65535
* hard nofile 65535""",
                create_if_missing=False,
            )
            self._set_or_append_directive("/etc/audit/auditd.conf", "max_log_file", "max_log_file = 64")

        if not self.dry_run:
            self.stamp.save()

    # ── Secrets ────────────────────────────────────────────────────────────

    def drift_secrets(self) -> None:
        if "secrets" in self.skip:
            _skip("Skipping Secrets section (--skip-secrets)")
            return

        self._next_step("secrets")
        self._ensure_dir(Path("/etc/myapp"))

        self._append_managed_block(
            "/etc/myapp/app.conf",
            "fake-secrets-app",
            """aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""",
        )
        self._append_managed_block(
            "/etc/myapp/database.yml",
            "fake-secrets-db",
            """  password: SuperSecret123!
  url: postgresql://dbuser:s3cret@db.internal:5432/myapp""",
        )
        self._write_managed_text(
            "/etc/myapp/server.key",
            """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzDRIFTIFYFAKEKEYMATERIALONLY
THISISNOTAREALPRIVATEKEYDRIFTIFYEXAMPLEONLY
-----END RSA PRIVATE KEY-----
""",
            mode=0o600,
        )

        if self.needs_profile("standard"):
            self._append_managed_block(
                "/etc/myapp/app.conf",
                "fake-secrets-standard",
                """github_pat = ghp_xxxxxxxxxxDRIFTIFYFAKExxxxxxxxxx""",
            )
            self._append_managed_block(
                "/etc/profile.d/custom-env.sh",
                "fake-secrets-env",
                """export REDIS_URL=redis://:p4ssw0rd@redis.internal:6379""",
            )

        if self.needs_profile("kitchen-sink"):
            self._ensure_dir(Path("/opt/myapp"))
            self._write_managed_text(
                "/opt/myapp/.env",
                """API_TOKEN=DRIFTIFY_FAKE_TOKEN_12345
MONGODB_URL=mongodb://admin:m0ng0pass@mongo.internal:27017/admin
""",
                mode=0o600,
            )

        if not self.dry_run:
            self.stamp.save()

    # ── Network ────────────────────────────────────────────────────────────

    def drift_network(self) -> None:
        if "network" in self.skip:
            _skip("Skipping Network section (--skip-network)")
            return

        self._next_step("network")

        # Minimal: firewalld allowances
        fw_services = ["http", "https"]
        fw_ports = ["8080/tcp"]
        _info(f"{_I.GLOBE}  Adding firewalld rules "
              f"({', '.join(fw_services + fw_ports)})")
        for svc in fw_services:
            self.run_cmd(["firewall-cmd", "--permanent", f"--add-service={svc}"],
                         check=False)
            if not self.dry_run:
                self.stamp.record("firewall_services", svc)
        for port in fw_ports:
            self.run_cmd(["firewall-cmd", "--permanent", f"--add-port={port}"],
                         check=False)
            if not self.dry_run:
                self.stamp.record("firewall_ports", port)
        self.run_cmd(["firewall-cmd", "--reload"], check=False)

        # Minimal: /etc/hosts additions
        self._append_managed_block(
            "/etc/hosts",
            "hosts-entries",
            """10.10.10.10 app.internal app
10.10.10.11 db.internal db""",
            create_if_missing=False,
        )

        if self.needs_profile("standard"):
            # Standard: custom firewalld zone
            self._write_managed_text(
                "/etc/firewalld/zones/myapp.xml",
                """<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>myapp</short>
  <description>Driftify demo zone</description>
  <service name="http"/>
  <service name="https"/>
  <port port="8080" protocol="tcp"/>
</zone>
""",
            )

            # Standard: static NM profile
            self._write_managed_text(
                "/etc/NetworkManager/system-connections/mgmt.nmconnection",
                """[connection]
id=mgmt
type=ethernet
interface-name=eth0
autoconnect=true

[ipv4]
method=manual
addresses=192.168.122.50/24,192.168.122.1
dns=9.9.9.9;1.1.1.1;

[ipv6]
method=ignore
""",
                mode=0o600,
            )

            # Standard: proxy config
            self._write_managed_text(
                "/etc/profile.d/proxy.sh",
                """#!/bin/sh
export HTTP_PROXY=http://proxy.internal:3128
export HTTPS_PROXY=http://proxy.internal:3128
export NO_PROXY=localhost,127.0.0.1,.internal
""",
                mode=0o644,
            )

        if self.needs_profile("kitchen-sink"):
            # Kitchen-sink: static route + firewalld direct.xml
            self._write_managed_text(
                "/etc/sysconfig/network-scripts/route-eth0",
                """10.20.0.0/16 via 192.168.122.1 dev eth0
172.16.30.0/24 via 192.168.122.1 dev eth0
""",
            )
            self._write_managed_text(
                "/etc/firewalld/direct.xml",
                """<?xml version="1.0" encoding="utf-8"?>
<direct>
  <rule ipv="ipv4" table="filter" chain="INPUT" priority="0">-p tcp --dport 8443 -j ACCEPT</rule>
</direct>
""",
            )

        if not self.dry_run:
            self.stamp.save()

    # ── Storage ────────────────────────────────────────────────────────────

    def drift_storage(self) -> None:
        if "storage" in self.skip:
            _skip("Skipping Storage section (--skip-storage)")
            return

        self._next_step("storage")

        # Minimal: app state directories
        self._ensure_dir(Path("/var/lib/myapp"))
        self._ensure_dir(Path("/var/lib/myapp/data"))
        self._ensure_dir(Path("/var/log/myapp"))

        if self.needs_profile("standard"):
            # Standard: non-functional noauto fstab entries
            self._append_managed_block(
                "/etc/fstab",
                "nfs-entry",
                """nfs.internal:/exports/myapp /mnt/myapp-nfs nfs defaults,noauto,_netdev 0 0""",
                create_if_missing=False,
            )
            self._append_managed_block(
                "/etc/fstab",
                "cifs-entry",
                """//files.internal/myshare /mnt/myapp-cifs cifs credentials=/etc/myapp/cifs.creds,noauto,_netdev,vers=3.0 0 0""",
                create_if_missing=False,
            )
            self._write_managed_text(
                "/etc/myapp/cifs.creds",
                """username=myapp
password=DRIFTIFY_FAKE_CIFS_PASS
domain=INTERNAL
""",
                mode=0o600,
            )

        if self.needs_profile("kitchen-sink"):
            # Kitchen-sink: autofs map
            self._write_managed_text(
                "/etc/auto.master.d/app.autofs",
                """/- /etc/auto.app
""",
            )
            self._write_managed_text(
                "/etc/auto.app",
                """/mnt/auto-app -fstype=nfs4,rw,soft,intr nfs.internal:/exports/auto-app
""",
            )

        if not self.dry_run:
            self.stamp.save()

    # ── Undo: Services ────────────────────────────────────────────────────

    def _undo_services(self) -> None:
        d = self.stamp.data
        enabled = d.get("services_enabled", [])
        disabled = d.get("services_disabled", [])
        masked = d.get("services_masked", [])

        if not (enabled or disabled or masked):
            return

        _banner(f"{_I.UNDO}  Undo: Services")

        for svc in enabled:
            _info(f"{_I.BAN}  Disabling {svc}")
            self.run_cmd(["systemctl", "disable", svc], check=False)

        for svc in disabled:
            _info(f"{_I.TOGGLE}  Re-enabling {svc}")
            self.run_cmd(["systemctl", "enable", svc], check=False)

        for svc in masked:
            _info(f"{_I.MASK}  Unmasking {svc}")
            self.run_cmd(["systemctl", "unmask", svc], check=False)

    def _undo_network(self) -> None:
        """Remove firewalld services/ports that were added."""
        d = self.stamp.data
        fw_services = d.get("firewall_services", [])
        fw_ports = d.get("firewall_ports", [])

        if not (fw_services or fw_ports):
            return

        _banner(f"{_I.UNDO}  Undo: Network (firewalld)")

        for svc in fw_services:
            _info(f"{_I.GLOBE}  Removing firewalld service {svc}")
            self.run_cmd(["firewall-cmd", "--permanent", f"--remove-service={svc}"],
                         check=False)
        for port in fw_ports:
            _info(f"{_I.GLOBE}  Removing firewalld port {port}")
            self.run_cmd(["firewall-cmd", "--permanent", f"--remove-port={port}"],
                         check=False)

        self.run_cmd(["firewall-cmd", "--reload"], check=False)

    def _undo_filesystem(self) -> None:
        """Undo created files/dirs and restore original file contents."""
        d = self.stamp.data
        created_files = d.get("files_created", [])
        created_dirs = d.get("dirs_created", [])
        backups = d.get("file_backups", {})

        if not (created_files or created_dirs or backups):
            return

        _banner(f"{_I.UNDO}  Undo: Filesystem")

        for path_str in reversed(created_files):
            path = Path(path_str)
            if self.dry_run:
                _dry(f"rm -f {path}")
                continue
            if path.exists():
                path.unlink()
                _info(f"Removed created file {path}")

        for path_str, original in backups.items():
            path = Path(path_str)
            if self.dry_run:
                _dry(f"restore file {path}")
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as fh:
                fh.write(original)
            _info(f"Restored original file {path}")

        for path_str in sorted(created_dirs, key=len, reverse=True):
            path = Path(path_str)
            if self.dry_run:
                _dry(f"rmdir {path} (if empty)")
                continue
            if path.exists() and path.is_dir():
                try:
                    path.rmdir()
                    _info(f"Removed created dir {path}")
                except OSError:
                    _warn(f"Directory not empty, leaving {path}")

    # ── Undo: RPM ─────────────────────────────────────────────────────────

    def _undo_rpm(self) -> None:
        d = self.stamp.data
        start_tid = d.get("dnf_transaction_start")
        end_tid = d.get("dnf_transaction_end")

        if start_tid is None or end_tid is None:
            _warn("No dnf transaction range in stamp — skipping RPM undo")
            return

        if end_tid <= start_tid:
            _info("No dnf transactions to undo")
            return

        _banner(f"{_I.UNDO}  Undo: RPM / Packages")
        _info(f"{_I.PACKAGE}  Reverting dnf transactions "
              f"{start_tid + 1}..{end_tid}")

        for tid in range(end_tid, start_tid, -1):
            _info(f"{_I.RECYCLE}  Undoing dnf transaction {tid}")
            self.run_cmd(["dnf", "history", "undo", "-y", str(tid)], check=False)

    # ── Summary ───────────────────────────────────────────────────────────

    def _print_summary(self) -> None:
        elapsed = time.monotonic() - self._t0
        m, s = divmod(int(elapsed), 60)

        _banner(f"{_I.CHECK}  driftify complete "
                f"({self.profile} profile, {m}m {s:02d}s)")

        d = self.stamp.data  # {} when dry_run (stamp never started)

        # RPM stats
        pkg_count = sum(
            len(BASE_PACKAGES.get(lvl, []))
            for lvl in PROFILES if self.needs_profile(lvl)
        )
        epel_count = sum(
            len(EPEL_PACKAGES.get(lvl, []))
            for lvl in PROFILES if self.needs_profile(lvl)
        )
        if "rpm" not in self.skip:
            rpm_parts = [f"{pkg_count + epel_count} packages requested", "1 repo added"]
            if self.needs_profile("standard"):
                rpm_parts += ["1 ghost package", "1 orphaned config"]
            rpm_str = ", ".join(rpm_parts)
        else:
            rpm_str = "skipped"
        _info(f"{SECTION_ICONS['rpm']}  RPM:        {rpm_str}")

        # Service stats — use real stamp counts when available
        if "services" not in self.skip:
            if d:
                en  = len(d.get("services_enabled",  []))
                dis = len(d.get("services_disabled", []))
                mas = len(d.get("services_masked",   []))
            else:
                en, dis = 2, 1
                mas = 1 if self.needs_profile("standard") else 0
            parts = []
            if en:  parts.append(f"{en} enabled")
            if dis: parts.append(f"{dis} disabled")
            if mas: parts.append(f"{mas} masked")
            svc_str = ", ".join(parts) if parts else "none"
        else:
            svc_str = "skipped"
        _info(f"{SECTION_ICONS['services']}  Services:   {svc_str}")

        # Config stats
        cfg = "skipped" if "config" in self.skip else "RPM + unowned config drift applied"
        _info(f"{SECTION_ICONS['config']}  Config:     {cfg}")

        # Network stats — use real firewall counts when available
        if "network" not in self.skip:
            if d:
                fw_n = (len(d.get("firewall_services", [])) +
                        len(d.get("firewall_ports",    [])))
                net_parts = [f"{fw_n} firewall rules", "hosts entries"]
            else:
                net_parts = ["3 firewall rules", "hosts entries"]
            if self.needs_profile("standard"):
                net_parts += ["zone", "NM profile", "proxy"]
            net_str = ", ".join(net_parts)
        else:
            net_str = "skipped"
        _info(f"{SECTION_ICONS['network']}  Network:    {net_str}")

        # Storage stats
        sto = "skipped" if "storage" in self.skip else "fstab + /var storage drift applied"
        _info(f"{SECTION_ICONS['storage']}  Storage:    {sto}")

        # Secrets stats
        sec = "skipped" if "secrets" in self.skip else "fake secrets planted"
        _info(f"{SECTION_ICONS['secrets']}  Secrets:    {sec}")

        # Placeholder lines for future sections
        for section in SECTIONS:
            if section in self._IMPLEMENTED:
                continue
            icon = SECTION_ICONS[section]
            label = SECTION_LABELS[section]
            _skip(f"{icon}  {label}: not yet implemented")

        print()
        _info(f"{_I.STAMP}  Stamp file: {STAMP_PATH}")
        _info(f"{_I.UNDO}  To undo:    sudo ./driftify.py --undo")


# ── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="driftify",
        description="Apply synthetic drift to a RHEL/CentOS Stream 9 or 10 system.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  sudo ./driftify.py                          # standard profile
  sudo ./driftify.py --profile minimal        # CI-friendly, fast
  sudo ./driftify.py --profile kitchen-sink   # everything
  sudo ./driftify.py --skip-nonrpm            # standard minus non-RPM software
  sudo ./driftify.py --undo                   # reverse previous run
  sudo ./driftify.py --dry-run                # preview without changes
""",
    )
    p.add_argument(
        "--profile", choices=PROFILES, default="standard",
        help="drift profile: minimal, standard (default), kitchen-sink",
    )
    for section in SECTIONS:
        p.add_argument(
            f"--skip-{section}",
            dest=f"skip_{section.replace('-', '_')}",
            action="store_true",
            help=f"skip the {section} section",
        )
    p.add_argument(
        "--undo", action="store_true",
        help="reverse all modifications from the previous run (requires stamp file)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="print commands without executing them",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.dry_run:
        _error("driftify must run as root (try: sudo ./driftify.py)")
        sys.exit(1)

    skipped = [
        section for section in SECTIONS
        if getattr(args, f"skip_{section.replace('-', '_')}", False)
    ]

    drifter = Driftify(
        profile=args.profile,
        dry_run=args.dry_run,
        skip_sections=skipped,
        undo=args.undo,
    )

    if args.undo:
        drifter.run_undo()
    else:
        drifter.run()


if __name__ == "__main__":
    main()
