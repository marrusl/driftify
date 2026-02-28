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
        "bash-completion", "man-pages", "info", "tree", "unzip", "at",
        "nodejs",
    ],
    "kitchen-sink": [
        "gcc", "make", "kernel-devel", "gdb", "valgrind",
        "cmake", "autoconf", "automake", "libtool", "pkgconfig",
        "checkpolicy", "policycoreutils-python-utils",
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

# TTY check runs once at import time against the real stdout.
# Tests that redirect stdout via io.StringIO will still see ANSI codes
# in captured output — this is harmless since no test asserts on colors.
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
            "at_jobs": [],
            "recursive_dirs_created": [],
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

    _IMPLEMENTED = {
        "rpm", "services", "config", "network", "storage",
        "scheduled", "containers", "nonrpm", "kernel", "selinux",
        "users", "secrets",
    }

    def __init__(self, profile: str, dry_run: bool, skip_sections: list,
                 undo: bool = False, yes: bool = False,
                 quiet: bool = False, verbose: bool = False):
        self.profile = profile
        self.dry_run = dry_run
        self.skip = set(skip_sections)
        self.undo_mode = undo
        self.yes = yes
        self.quiet = quiet
        # verbose: reserved for future use when capture=True calls are added;
        # subprocess output currently passes through directly so --verbose
        # has no additional effect today.
        self.verbose = verbose
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
        """Execute *cmd*, or print it if --dry-run.

        With --quiet the "Running:" echo is suppressed; warnings and errors
        still print.  [DRY RUN] lines are never suppressed.
        """
        pretty = " ".join(str(c) for c in cmd)
        if self.dry_run:
            _dry(pretty)
            return None
        if not self.quiet:
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
        """Write file with stamp tracking for created/modified files.

        NOTE: reads existing content in text mode for change-detection and
        backup.  Only suitable for text files — calling this on a binary
        path would produce a corrupt backup and likely a UnicodeDecodeError.
        All files driftify currently manages are text; keep it that way.
        """
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
        if not self.quiet:
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

    # ── confirmation ──────────────────────────────────────────────────────

    def _run_description(self) -> list:
        """Return bullet-point lines describing what this run will do.

        NOTE: this method is a prose mirror of the drift_* methods.
        When adding or changing what a section does at a given profile
        level, update this method AND _print_summary() to match.
        """
        lines = []
        active = [s for s in SECTIONS
                  if s in self._IMPLEMENTED and s not in self.skip]

        if "rpm" in active:
            pkg_count = sum(
                len(BASE_PACKAGES.get(lvl, []))
                for lvl in PROFILES if self.needs_profile(lvl)
            )
            epel_count = sum(
                len(EPEL_PACKAGES.get(lvl, []))
                for lvl in PROFILES if self.needs_profile(lvl)
            )
            tiers = " + standard" if self.needs_profile("standard") else ""
            ghost = ", ghost entry" if self.needs_profile("standard") else ""
            lines.append(
                f"Install ~{pkg_count + epel_count} packages "
                f"(EPEL + base{tiers}{ghost})"
            )

        if "services" in active:
            svcs = "Enable httpd, nginx; disable kdump"
            if self.needs_profile("standard"):
                svcs += "; mask bluetooth (if present)"
            lines.append(svcs)

        if "config" in active:
            cfgs = "Modify RPM-owned configs (httpd, nginx"
            if self.needs_profile("standard"):
                cfgs += ", sshd, chrony"
            if self.needs_profile("kitchen-sink"):
                cfgs += ", limits, auditd"
            cfgs += ") + drop /etc/myapp/ configs"
            lines.append(cfgs)

        if "network" in active:
            net = "Add firewall rules (http, https, 8080/tcp), /etc/hosts entries"
            if self.needs_profile("standard"):
                net += ", NM profile, proxy"
            if self.needs_profile("kitchen-sink"):
                net += ", static route, direct.xml"
            lines.append(net)

        if "storage" in active:
            sto = "Create /var/lib/myapp/, /var/log/myapp/ dirs"
            if self.needs_profile("standard"):
                sto += "; add NFS/CIFS entries to /etc/fstab"
            lines.append(sto)

        if "scheduled" in active:
            sch = "Create cron jobs (/etc/cron.d, /etc/cron.daily)"
            if self.needs_profile("standard"):
                sch += ", systemd timer pair, at job, per-user crontab"
            lines.append(sch)

        if "nonrpm" in active:
            nrpm = "Create Python venv (/opt/myapp/venv) with flask/gunicorn/requests"
            nrpm += ", download yq Go binary (/usr/local/bin/driftify-probe)"
            if self.needs_profile("standard"):
                nrpm += ", npm project (/opt/webapp/), git repo (/opt/tools/some-tool/)"
                nrpm += ", deploy.sh script"
            if self.needs_profile("kitchen-sink"):
                nrpm += ", mystery binary (stripped)"
            lines.append(nrpm)

        if "containers" in active:
            ctr = "Drop webapp.container quadlet in /etc/containers/systemd/"
            if self.needs_profile("standard"):
                ctr += ", redis.container, myapp.network, docker-compose.yml"
            if self.needs_profile("kitchen-sink"):
                ctr += ", user-level quadlet (~appuser)"
            lines.append(ctr)

        if "kernel" in active:
            ker = "Apply 6 sysctl overrides (/etc/sysctl.d/99-driftify.conf)"
            if self.needs_profile("standard"):
                ker += ", load br_netfilter, dracut config"
            if self.needs_profile("kitchen-sink"):
                ker += ", add grub kernel args (panic=60 audit=1)"
            lines.append(ker)

        if "selinux" in active:
            sel = "Set httpd_can_network_connect=on"
            if self.needs_profile("standard"):
                sel += ", httpd_can_network_relay=on, custom audit rules"
            if self.needs_profile("kitchen-sink"):
                sel += ", install custom SELinux module"
            lines.append(sel)

        if "users" in active:
            usr = "Create appuser (UID 1001) + appgroup (GID 1001)"
            if self.needs_profile("standard"):
                usr += ", dbuser (UID 1002), sudoers rule, SSH key"
            if self.needs_profile("kitchen-sink"):
                usr += ", subuid/subgid maps"
            lines.append(usr)

        if "secrets" in active:
            sec = "Plant fake credentials in /etc/myapp/ (AWS, PEM"
            if self.needs_profile("standard"):
                sec += ", GitHub token, Redis URL"
            if self.needs_profile("kitchen-sink"):
                sec += ", MongoDB URL, .env"
            sec += ")"
            lines.append(sec)

        return lines

    def _confirm(self, undo_mode: bool = False) -> None:
        """Print a description of what will happen and ask for confirmation.

        Exits immediately if the user declines.  Skipped when --yes or
        --dry-run are active.
        """
        if self.yes or self.dry_run:
            return

        print()
        if undo_mode:
            started = self.stamp.data.get("started", "unknown time")
            profile = self.stamp.data.get("profile", "unknown")
            print(f"  {_C.BOLD}About to reverse the previous driftify run:{_C.RESET}")
            print(f"    • Restore all backed-up config files to their original state")
            print(f"    • Remove all files and dirs created by driftify")
            print(f"    • Remove firewall rules added by driftify")
            print(f"    • Disable/re-enable services changed by driftify")
            print(f"    • Reverse dnf transactions from that run")
            print()
            print(f"  {_C.DIM}Stamp: {profile} profile, started {started}{_C.RESET}")
        else:
            print(f"  {_C.BOLD}About to apply {self.profile} profile drift "
                  f"on {self.os_id} {self.os_major}:{_C.RESET}")
            for line in self._run_description():
                print(f"    • {line}")
            print()
            print(f"  {_C.DIM}Run --undo afterwards to reverse all changes.{_C.RESET}")

        print()
        try:
            answer = input("  Proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            _info("Aborted.")
            sys.exit(0)

        if answer != "y":
            _info("Aborted.")
            sys.exit(0)

        print()

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

        self._confirm(undo_mode=False)

        if not self.dry_run:
            self.stamp.start(self.profile, self.os_id, self.os_major)

        self.drift_rpm()
        self.drift_services()
        self.drift_config()
        self.drift_network()
        self.drift_storage()
        self.drift_scheduled()
        self.drift_containers()
        self.drift_kernel()
        self.drift_selinux()
        self.drift_nonrpm()
        self.drift_users()
        # WARNING: drift_secrets() must remain after drift_users().
        # Kitchen-sink secrets write to /home/appuser/ which only exists
        # once drift_users() has run useradd.  Reordering breaks silently.
        self.drift_secrets()

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

        self._confirm(undo_mode=True)

        self._undo_filesystem()

        # Reload systemd if any created unit files were removed
        unit_files = [f for f in self.stamp.data.get("files_created", [])
                      if "/systemd/system/" in f]
        if unit_files:
            _info(f"{_I.COGS}  Reloading systemd after unit file removal")
            self.run_cmd(["systemctl", "daemon-reload"], check=False)

        self._undo_scheduled()
        self._undo_selinux()
        self._undo_kernel()
        self._undo_users()
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

    # ── Scheduled Tasks ────────────────────────────────────────────────────

    def drift_scheduled(self) -> None:
        if "scheduled" in self.skip:
            _skip("Skipping Scheduled section (--skip-scheduled)")
            return

        self._next_step("scheduled")

        # Minimal: cron job in /etc/cron.d
        self._write_managed_text(
            "/etc/cron.d/backup-daily",
            "# Daily backup — driftify synthetic fixture\n"
            "# yoinkc should convert this to a systemd timer\n"
            "0 2 * * * root /usr/local/bin/backup.sh"
            " >> /var/log/myapp/backup.log 2>&1\n",
        )

        # Minimal: cron daily drop-in script
        self._write_managed_text(
            "/etc/cron.daily/cleanup.sh",
            "#!/bin/sh\n"
            "# Cleanup script — driftify synthetic fixture\n"
            "find /tmp -name 'myapp-*' -mtime +7 -delete\n",
            mode=0o755,
        )

        if self.needs_profile("standard"):
            # Per-user crontab written directly to spool dir
            # appuser is created later in drift_users; crond picks it up then
            self._write_managed_text(
                "/var/spool/cron/appuser",
                "# appuser crontab — driftify synthetic fixture\n"
                "*/15 * * * * /opt/myapp/scripts/health-check.sh"
                " >> /var/log/myapp/health.log 2>&1\n",
                mode=0o600,
            )

            # Systemd timer + service pair
            self._write_managed_text(
                "/etc/systemd/system/myapp-report.service",
                "[Unit]\n"
                "Description=MyApp Daily Report\n"
                "After=network.target\n\n"
                "[Service]\n"
                "Type=oneshot\n"
                "User=root\n"
                "ExecStart=/usr/local/bin/generate-report.sh\n"
                "StandardOutput=journal\n",
            )
            self._write_managed_text(
                "/etc/systemd/system/myapp-report.timer",
                "[Unit]\n"
                "Description=MyApp Daily Report Timer\n\n"
                "[Timer]\n"
                "OnCalendar=daily\n"
                "Persistent=true\n\n"
                "[Install]\n"
                "WantedBy=timers.target\n",
            )
            self.run_cmd(["systemctl", "daemon-reload"], check=False)
            _info(f"{_I.TOGGLE}  Enabling myapp-report.timer")
            self.run_cmd(["systemctl", "enable", "myapp-report.timer"],
                         check=False)
            if not self.dry_run:
                self.stamp.record("services_enabled", "myapp-report.timer")

            # Queue an at job
            _info(f"{_I.CLOCK}  Starting atd and queuing at job")
            self.run_cmd(["systemctl", "start", "atd"], check=False)
            self._queue_at_job()

        if self.needs_profile("kitchen-sink"):
            # Cron job with MAILTO and env vars — exercises edge-case parsing
            self._write_managed_text(
                "/etc/cron.d/complex-job",
                "# Complex cron with env deps — driftify kitchen-sink fixture\n"
                "MAILTO=ops@example.com\n"
                "APP_ENV=production\n"
                "30 6 * * 1-5 appuser /opt/myapp/scripts/weekday-report.sh\n",
            )

        if not self.dry_run:
            self.stamp.save()

    def _queue_at_job(self) -> None:
        """Queue an at job and store its ID in the stamp for undo."""
        if self.dry_run:
            _dry("echo 'touch /tmp/driftify-at-probe' | at now + 1 hour")
            return
        r = subprocess.run(
            ["at", "now", "+", "1", "hour"],
            input="touch /tmp/driftify-at-probe\n",
            capture_output=True, text=True, check=False,
        )
        if r.returncode != 0:
            _warn(f"at job failed: {r.stderr.strip()}")
            return
        match = re.search(r"job\s+(\d+)", r.stderr)
        if match:
            job_id = int(match.group(1))
            self.stamp.record("at_jobs", job_id)
            _info(f"{_I.CLOCK}  Queued at job {job_id}")
        else:
            _warn(f"Could not parse at job ID from: {r.stderr.strip()}")

    # ── Users / Groups ─────────────────────────────────────────────────────

    def drift_users(self) -> None:
        if "users" in self.skip:
            _skip("Skipping Users section (--skip-users)")
            return

        self._next_step("users")

        # Minimal: create appgroup then appuser with that primary group
        _info(f"{_I.USERS}  Creating group appgroup (GID 1001)")
        self.run_cmd(["groupadd", "-g", "1001", "appgroup"], check=False)
        if not self.dry_run:
            r = subprocess.run(["getent", "group", "appgroup"],
                               capture_output=True)
            if r.returncode == 0:
                self.stamp.record("groups_created", "appgroup")

        _info(f"{_I.USERS}  Creating user appuser (UID 1001, primary: appgroup)")
        self.run_cmd(
            ["useradd", "-u", "1001", "-g", "appgroup", "-m",
             "-c", "App User", "appuser"],
            check=False,
        )
        if not self.dry_run:
            r = subprocess.run(["id", "appuser"], capture_output=True)
            if r.returncode == 0:
                self.stamp.record("users_created", "appuser")

        if self.needs_profile("standard"):
            _info(f"{_I.USERS}  Creating user dbuser (UID 1002, nologin)")
            self.run_cmd(
                ["useradd", "-u", "1002", "-s", "/sbin/nologin", "-M",
                 "-c", "DB Service Account", "dbuser"],
                check=False,
            )
            if not self.dry_run:
                r = subprocess.run(["id", "dbuser"], capture_output=True)
                if r.returncode == 0:
                    self.stamp.record("users_created", "dbuser")

            # Sudoers rule
            self._write_managed_text(
                "/etc/sudoers.d/appusers",
                "# sudoers rules — driftify synthetic fixture\n"
                "appuser ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp\n"
                "appuser ALL=(ALL) NOPASSWD: /usr/bin/systemctl status myapp\n",
                mode=0o440,
            )

            # SSH authorized_keys for appuser
            ssh_dir = Path("/home/appuser/.ssh")
            self._ensure_dir(ssh_dir)
            if not self.dry_run:
                self.run_cmd(["chown", "appuser:appgroup", str(ssh_dir)],
                             check=False)
                self.run_cmd(["chmod", "0700", str(ssh_dir)], check=False)
            self._write_managed_text(
                "/home/appuser/.ssh/authorized_keys",
                "# Driftify synthetic SSH key — NOT a real key\n"
                "ssh-rsa AAAAB3NzaC1yc2EDRIFTIFYFAKEKEY0000EXAMPLEONLY"
                "0000000000 appuser@driftify-demo\n",
                mode=0o600,
            )
            if not self.dry_run:
                self.run_cmd(
                    ["chown", "appuser:appgroup",
                     "/home/appuser/.ssh/authorized_keys"],
                    check=False,
                )

        if self.needs_profile("kitchen-sink"):
            # Rootless container user mappings
            self._append_managed_block(
                "/etc/subuid",
                "appuser-subuid",
                "appuser:100000:65536",
                create_if_missing=False,
            )
            self._append_managed_block(
                "/etc/subgid",
                "appuser-subgid",
                "appuser:100000:65536",
                create_if_missing=False,
            )

        if not self.dry_run:
            self.stamp.save()

    # ── Undo: Scheduled Tasks ──────────────────────────────────────────────

    def _undo_scheduled(self) -> None:
        at_jobs = self.stamp.data.get("at_jobs", [])
        if not at_jobs:
            return
        _banner(f"{_I.UNDO}  Undo: Scheduled Tasks (at jobs)")
        for job_id in at_jobs:
            _info(f"{_I.CLOCK}  Removing at job {job_id}")
            self.run_cmd(["atrm", str(job_id)], check=False)

    # ── Containers ─────────────────────────────────────────────────────────

    def drift_containers(self) -> None:
        if "containers" in self.skip:
            _skip("Skipping Containers section (--skip-containers)")
            return

        self._next_step("containers")

        # Minimal: webapp quadlet — exercises Image, ports, env (with secret),
        # volumes with :Z, Network reference, AutoUpdate
        self._ensure_dir(Path("/etc/containers/systemd"))
        self._write_managed_text(
            "/etc/containers/systemd/webapp.container",
            "[Unit]\n"
            "Description=Web Application\n"
            "After=network-online.target\n"
            "\n"
            "[Container]\n"
            "Image=registry.example.com/myorg/webapp:v2.1.3\n"
            "PublishPort=8080:8080\n"
            "PublishPort=8443:8443\n"
            "Environment=APP_ENV=production\n"
            "Environment=LOG_LEVEL=info\n"
            "# This fake secret should trigger yoinkc's redaction\n"
            "Environment=DATABASE_URL=postgresql://dbuser:s3cret@db.internal:5432/myapp\n"
            "Volume=/var/lib/myapp/data:/app/data:Z\n"
            "Volume=/var/log/myapp:/app/logs:Z\n"
            "Network=myapp.network\n"
            "AutoUpdate=registry\n"
            "\n"
            "[Service]\n"
            "Restart=always\n"
            "TimeoutStartSec=300\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target default.target\n",
        )

        if self.needs_profile("standard"):
            # redis quadlet — exercises docker.io registry, localhost port
            # binding, named volume, healthcheck fields
            self._write_managed_text(
                "/etc/containers/systemd/redis.container",
                "[Unit]\n"
                "Description=Redis Cache\n"
                "Before=webapp.service\n"
                "\n"
                "[Container]\n"
                "Image=docker.io/library/redis:7-alpine\n"
                "PublishPort=127.0.0.1:6379:6379\n"
                "Volume=redis-data.volume:/data:Z\n"
                "Environment=REDIS_PASSWORD=DRIFTIFY_FAKE_r3d1s_p4ss\n"
                "# Exercises healthcheck detection\n"
                "HealthCmd=/usr/local/bin/redis-cli ping\n"
                "HealthInterval=10s\n"
                "\n"
                "[Service]\n"
                "Restart=always\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target default.target\n",
            )

            # network quadlet — exercises .network unit type, subnet config
            self._write_managed_text(
                "/etc/containers/systemd/myapp.network",
                "[Unit]\n"
                "Description=Application Network\n"
                "\n"
                "[Network]\n"
                "Subnet=10.89.1.0/24\n"
                "Gateway=10.89.1.1\n"
                "Label=app=myapp\n",
            )

            # docker-compose.yml — exercises compose detection in /opt,
            # multi-service image: extraction, secret in env
            self._ensure_dir(Path("/opt/myapp"))
            self._write_managed_text(
                "/opt/myapp/docker-compose.yml",
                "# Legacy compose file — should be converted to quadlets\n"
                "version: \"3.8\"\n"
                "services:\n"
                "  app:\n"
                "    image: registry.example.com/myorg/webapp:v2.1.3\n"
                "    ports:\n"
                "      - \"9090:8080\"\n"
                "    environment:\n"
                "      - APP_ENV=staging\n"
                "    volumes:\n"
                "      - ./data:/app/data\n"
                "    depends_on:\n"
                "      - db\n"
                "  db:\n"
                "    image: docker.io/library/postgres:16\n"
                "    environment:\n"
                "      POSTGRES_PASSWORD: DRIFTIFY_FAKE_pgpass123\n"
                "    volumes:\n"
                "      - pgdata:/var/lib/postgresql/data\n"
                "volumes:\n"
                "  pgdata:\n",
            )

        if self.needs_profile("kitchen-sink"):
            # User-level quadlet — exercises UID 1000-59999 path scan,
            # %h specifier, quay.io as third registry variant
            user_quadlet_dir = Path("/home/appuser/.config/containers/systemd")
            self._ensure_dir(user_quadlet_dir)
            self._write_managed_text(
                str(user_quadlet_dir / "dev-tools.container"),
                "[Unit]\n"
                "Description=Development tools (user-level)\n"
                "\n"
                "[Container]\n"
                "Image=quay.io/toolbox/toolbox:latest\n"
                "Volume=%h/projects:/projects:Z\n"
                "\n"
                "[Install]\n"
                "WantedBy=default.target\n",
            )
            if not self.dry_run:
                self.run_cmd(
                    ["chown", "-R", "appuser:appgroup",
                     str(user_quadlet_dir.parent.parent.parent)],
                    check=False,
                )

        if not self.dry_run:
            self.stamp.save()

    # ── Non-RPM Software ──────────────────────────────────────────────────────

    def drift_nonrpm(self) -> None:
        if "nonrpm" in self.skip:
            _skip("Skipping Non-RPM section (--skip-nonrpm)")
            return

        self._next_step("nonrpm")

        # Minimal: Python venv with flask, gunicorn, requests
        venv_path = "/opt/myapp/venv"
        _info(f"{_I.PUZZLE}  Creating Python venv at {venv_path}")
        self.run_cmd(["python3", "-m", "venv", venv_path], check=False)
        self.run_cmd(
            [f"{venv_path}/bin/pip", "install", "--quiet",
             "flask", "gunicorn", "requests"],
            check=False,
        )
        if not self.dry_run:
            self.stamp.record("recursive_dirs_created", venv_path)

        # Minimal: download yq as a real Go binary (gives yoinkc a
        # .note.go.buildid ELF section to detect)
        self._download_go_probe()

        if self.needs_profile("standard"):
            # npm project — nodejs installed via BASE_PACKAGES
            self._create_npm_project()

            # Git-initialised dir with a remote URL
            git_dir = "/opt/tools/some-tool"
            _info(f"{_I.PUZZLE}  Initialising git repo at {git_dir}")
            self._ensure_dir(Path(git_dir))
            self.run_cmd(["git", "-C", git_dir, "init", "--quiet"],
                         check=False)
            self.run_cmd(
                ["git", "-C", git_dir, "remote", "add", "origin",
                 "https://github.com/example/some-tool.git"],
                check=False,
            )
            if not self.dry_run:
                self.stamp.record("recursive_dirs_created", git_dir)

            # Shell script at /usr/local/bin — non-binary script detection
            self._write_managed_text(
                "/usr/local/bin/deploy.sh",
                "#!/bin/sh\n"
                "# Deploy script — driftify synthetic fixture\n"
                "# yoinkc should detect this as a non-RPM script\n"
                "APP_DIR=/opt/myapp\n"
                "VENV=${APP_DIR}/venv\n"
                'echo "[deploy] Stopping service..."\n'
                "systemctl stop myapp || true\n"
                'echo "[deploy] Pulling latest code..."\n'
                "git -C ${APP_DIR} pull\n"
                'echo "[deploy] Installing dependencies..."\n'
                "${VENV}/bin/pip install -r ${APP_DIR}/requirements.txt\n"
                'echo "[deploy] Starting service..."\n'
                "systemctl start myapp\n",
                mode=0o755,
            )

        if self.needs_profile("kitchen-sink"):
            # Mystery binary: stripped copy of /usr/bin/true — no metadata,
            # no build ID; yoinkc should flag this as unknown provenance
            mystery = "/usr/local/bin/mystery-tool"
            _info(f"{_I.PUZZLE}  Creating mystery binary at {mystery}")
            if not self.dry_run:
                import shutil as _shutil
                _shutil.copy2("/usr/bin/true", mystery)
                os.chmod(mystery, 0o755)
                self.run_cmd(["strip", mystery], check=False)
                self.stamp.record("files_created", mystery)
            else:
                _dry(f"cp /usr/bin/true {mystery} && strip {mystery}")

        if not self.dry_run:
            self.stamp.save()

    def _download_go_probe(self) -> None:
        """Download yq from GitHub releases as a real Go binary."""
        import platform
        import urllib.request

        dest = "/usr/local/bin/driftify-probe"
        arch_map = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
        arch = arch_map.get(platform.machine())

        if arch is None:
            _warn(f"Unsupported arch {platform.machine()} — skipping Go probe download")
            return

        url = (
            f"https://github.com/mikefarah/yq/releases/latest/download/"
            f"yq_linux_{arch}"
        )

        if self.dry_run:
            _dry(f"download {url} → {dest}")
            return

        _info(f"{_I.DOWNLOAD}  Downloading yq ({arch}) → {dest}")
        try:
            urllib.request.urlretrieve(url, dest)
            os.chmod(dest, 0o755)
            self.stamp.record("files_created", dest)
            _info(f"  Go binary written to {dest}")
        except Exception as exc:
            _warn(f"yq download failed: {exc}")

    def _create_npm_project(self) -> None:
        """Create a minimal npm project at /opt/webapp/."""
        npm_dir = "/opt/webapp"
        _info(f"{_I.PUZZLE}  Creating npm project at {npm_dir}")
        self._ensure_dir(Path(npm_dir))
        self._write_managed_text(
            f"{npm_dir}/package.json",
            '{\n'
            '  "name": "myapp-web",\n'
            '  "version": "1.0.0",\n'
            '  "description": "Driftify synthetic npm project",\n'
            '  "main": "index.js",\n'
            '  "scripts": {\n'
            '    "start": "node index.js"\n'
            '  },\n'
            '  "dependencies": {\n'
            '    "express": "^4.18.0",\n'
            '    "lodash": "^4.17.21"\n'
            '  }\n'
            '}\n',
        )
        self.run_cmd(
            ["npm", "install", "--prefix", npm_dir, "--quiet"],
            check=False,
        )
        if not self.dry_run:
            self.stamp.record("recursive_dirs_created", npm_dir)

    # ── Kernel / Boot ──────────────────────────────────────────────────────

    def drift_kernel(self) -> None:
        if "kernel" in self.skip:
            _skip("Skipping Kernel section (--skip-kernel)")
            return

        self._next_step("kernel")

        # Minimal: sysctl overrides
        self._write_managed_text(
            "/etc/sysctl.d/99-driftify.conf",
            "# Network performance tuning — driftify synthetic fixture\n"
            "# yoinkc should detect these as non-default sysctl values\n"
            "net.core.somaxconn = 4096\n"
            "net.ipv4.tcp_max_syn_backlog = 8192\n"
            "net.ipv4.ip_local_port_range = 1024 65535\n"
            "vm.swappiness = 10\n"
            "fs.file-max = 2097152\n"
            "net.ipv4.tcp_keepalive_time = 600\n",
        )
        _info(f"{_I.LINUX}  Applying sysctls live")
        self.run_cmd(["sysctl", "-p", "/etc/sysctl.d/99-driftify.conf"],
                     check=False)

        if self.needs_profile("standard"):
            # Module load config
            self._write_managed_text(
                "/etc/modules-load.d/driftify.conf",
                "# Kernel modules — driftify synthetic fixture\n"
                "# yoinkc should flag br_netfilter as explicitly configured\n"
                "br_netfilter\n",
            )
            _info(f"{_I.LINUX}  Loading br_netfilter")
            self.run_cmd(["modprobe", "br_netfilter"], check=False)

            # Dracut config
            self._write_managed_text(
                "/etc/dracut.conf.d/driftify.conf",
                "# Custom dracut config — driftify synthetic fixture\n"
                'add_drivers+=" overlay "\n'
                'compress="gzip"\n',
            )

        if self.needs_profile("kitchen-sink"):
            self._append_kernel_cmdline_arg("panic=60 audit=1")

        if not self.dry_run:
            self.stamp.save()

    def _append_kernel_cmdline_arg(self, args: str) -> None:
        """Append args to GRUB_CMDLINE_LINUX in /etc/default/grub."""
        grub_path = "/etc/default/grub"
        path = Path(grub_path)
        if not path.exists():
            _warn("/etc/default/grub not found — skipping grub modification")
            return
        with open(path) as fh:
            content = fh.read()

        def _append(m):
            existing = m.group(1).rstrip()
            sep = " " if existing else ""
            return f'GRUB_CMDLINE_LINUX="{existing}{sep}{args}"'

        new_content, n = re.subn(
            r'GRUB_CMDLINE_LINUX="([^"]*)"', _append, content
        )
        if n == 0:
            _warn("GRUB_CMDLINE_LINUX not found — skipping grub modification")
            return
        self._write_managed_text(grub_path, new_content)

    # ── SELinux / Security ─────────────────────────────────────────────────

    def drift_selinux(self) -> None:
        if "selinux" in self.skip:
            _skip("Skipping SELinux section (--skip-selinux)")
            return

        self._next_step("selinux")

        # Minimal: non-default SELinux boolean
        _info(f"{_I.SHIELD}  Setting httpd_can_network_connect on")
        self.run_cmd(
            ["setsebool", "-P", "httpd_can_network_connect", "on"],
            check=False,
        )
        if not self.dry_run:
            self.stamp.record("selinux_booleans", "httpd_can_network_connect")

        if self.needs_profile("standard"):
            _info(f"{_I.SHIELD}  Setting httpd_can_network_relay on")
            self.run_cmd(
                ["setsebool", "-P", "httpd_can_network_relay", "on"],
                check=False,
            )
            if not self.dry_run:
                self.stamp.record("selinux_booleans", "httpd_can_network_relay")

            # Custom audit rules
            self._ensure_dir(Path("/etc/audit/rules.d"))
            self._write_managed_text(
                "/etc/audit/rules.d/driftify.rules",
                "# Custom audit rules — driftify synthetic fixture\n"
                "-a always,exit -F arch=b64 -S open"
                " -F dir=/etc/myapp -F success=1 -k myapp-config\n"
                "-a always,exit -F arch=b64 -S execve"
                " -F uid=1001 -k appuser-exec\n",
            )

        if self.needs_profile("kitchen-sink"):
            self._install_selinux_module()

        if not self.dry_run:
            self.stamp.save()

    def _install_selinux_module(self) -> None:
        """Compile and install a minimal custom SELinux policy module."""
        import shutil
        import tempfile

        for tool in ("checkmodule", "semodule_package"):
            if not shutil.which(tool):
                _warn(f"{tool} not found — skipping SELinux module install")
                return

        te_src = (
            "module myapp 1.0;\n\n"
            "require {\n"
            "    type httpd_t;\n"
            "    type http_port_t;\n"
            "    class tcp_socket name_connect;\n"
            "}\n\n"
            "allow httpd_t http_port_t:tcp_socket name_connect;\n"
        )

        if self.dry_run:
            _dry("compile + semodule -i myapp.pp")
            return

        td = tempfile.mkdtemp(prefix="driftify-selinux-")
        try:
            te  = os.path.join(td, "myapp.te")
            mod = os.path.join(td, "myapp.mod")
            pp  = os.path.join(td, "myapp.pp")
            with open(te, "w") as fh:
                fh.write(te_src)
            r = subprocess.run(
                ["checkmodule", "-M", "-m", "-o", mod, te],
                check=False, capture_output=True, text=True,
            )
            if r.returncode != 0:
                _warn(f"checkmodule failed: {r.stderr.strip()}")
                return
            r = subprocess.run(
                ["semodule_package", "-o", pp, "-m", mod],
                check=False, capture_output=True, text=True,
            )
            if r.returncode != 0:
                _warn(f"semodule_package failed: {r.stderr.strip()}")
                return
            r = subprocess.run(
                ["semodule", "-i", pp],
                check=False, capture_output=True, text=True,
            )
            if r.returncode != 0:
                _warn(f"semodule -i failed: {r.stderr.strip()}")
                return
            _info(f"{_I.SHIELD}  Installed SELinux module: myapp")
            self.stamp.record("selinux_modules", "myapp")
        finally:
            import shutil as _shutil
            _shutil.rmtree(td, ignore_errors=True)

    # ── Undo: Kernel / Boot ────────────────────────────────────────────────

    def _undo_kernel(self) -> None:
        created = self.stamp.data.get("files_created", [])
        # The sysctl and modules files are already removed by _undo_filesystem.
        # Reapply remaining sysctl config so live values revert.
        sysctl_removed = any("/sysctl.d/" in f for f in created)
        modules_removed = any("/modules-load.d/" in f for f in created)
        grub_modified = "/etc/default/grub" in self.stamp.data.get(
            "file_backups", {}
        )

        if not (sysctl_removed or modules_removed or grub_modified):
            return

        _banner(f"{_I.UNDO}  Undo: Kernel / Boot")

        if sysctl_removed:
            _info(f"{_I.LINUX}  Reapplying remaining sysctls (reverting live values)")
            self.run_cmd(["sysctl", "--system"], check=False)

        if modules_removed:
            _info(f"{_I.LINUX}  Attempting to unload br_netfilter")
            self.run_cmd(["modprobe", "-r", "br_netfilter"], check=False)

        if grub_modified:
            _info(f"{_I.LINUX}  Regenerating grub.cfg after /etc/default/grub restore")
            _GRUB_CFG_PATHS = [
                "/boot/grub2/grub.cfg",
                "/boot/efi/EFI/centos/grub.cfg",
                "/boot/efi/EFI/redhat/grub.cfg",
            ]
            for cfg in _GRUB_CFG_PATHS:
                if Path(cfg).exists():
                    self.run_cmd(["grub2-mkconfig", "-o", cfg], check=False)
                    break
            else:
                _warn("Could not locate grub.cfg — run grub2-mkconfig manually")

    # ── Undo: SELinux / Security ───────────────────────────────────────────

    def _undo_selinux(self) -> None:
        d = self.stamp.data
        booleans = d.get("selinux_booleans", [])
        modules  = d.get("selinux_modules",  [])

        if not (booleans or modules):
            return

        _banner(f"{_I.UNDO}  Undo: SELinux / Security")

        for boolean in booleans:
            _info(f"{_I.SHIELD}  Resetting {boolean} to off")
            self.run_cmd(["setsebool", "-P", boolean, "off"], check=False)

        for module in modules:
            _info(f"{_I.SHIELD}  Removing SELinux module {module}")
            self.run_cmd(["semodule", "-r", module], check=False)

    # ── Undo: Users / Groups ───────────────────────────────────────────────

    def _undo_users(self) -> None:
        d = self.stamp.data
        users = d.get("users_created", [])
        groups = d.get("groups_created", [])

        if not (users or groups):
            return

        _banner(f"{_I.UNDO}  Undo: Users / Groups")

        # Delete users first (primary group can't be deleted while user exists)
        for user in reversed(users):
            _info(f"{_I.USERS}  Deleting user {user} (and home dir)")
            self.run_cmd(["userdel", "-r", user], check=False)

        for group in groups:
            _info(f"{_I.USERS}  Deleting group {group}")
            self.run_cmd(["groupdel", group], check=False)

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
        import shutil as _shutil
        d = self.stamp.data
        created_files = d.get("files_created", [])
        created_dirs = d.get("dirs_created", [])
        recursive_dirs = d.get("recursive_dirs_created", [])
        backups = d.get("file_backups", {})

        if not (created_files or created_dirs or recursive_dirs or backups):
            return

        _banner(f"{_I.UNDO}  Undo: Filesystem")

        # Files in both created_files and file_backups were created by
        # driftify and then modified by a later section.  The backup holds
        # an intermediate driftify state, not the original state.  Only
        # the delete is needed — skip the restore for these paths.
        created_files_set = set(created_files)

        for path_str in reversed(created_files):
            path = Path(path_str)
            if self.dry_run:
                _dry(f"rm -f {path}")
                continue
            if path.exists():
                path.unlink()
                _info(f"Removed created file {path}")

        for path_str, original in backups.items():
            if path_str in created_files_set:
                _info(f"Skipping restore of driftify-created file {path_str}")
                continue
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

        # Recursively remove trees explicitly created by driftify
        # (venvs, node_modules, git-init'd dirs, etc.)
        for path_str in sorted(recursive_dirs, key=len, reverse=True):
            path = Path(path_str)
            if self.dry_run:
                _dry(f"rm -rf {path}")
                continue
            if path.exists():
                _shutil.rmtree(path)
                _info(f"Removed created directory tree {path}")

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

    def _count_created(self, prefix: str) -> int:
        """Count files_created entries whose path starts with *prefix*."""
        return sum(
            1 for f in self.stamp.data.get("files_created", [])
            if f.startswith(prefix)
        )

    def _print_summary(self) -> None:
        elapsed = time.monotonic() - self._t0
        m, s = divmod(int(elapsed), 60)

        _banner(f"{_I.CHECK}  driftify complete "
                f"({self.profile} profile, {m}m {s:02d}s)")

        d = self.stamp.data  # {} when dry_run (stamp never started)

        # ── RPM ──────────────────────────────────────────────────────────────
        pkg_count = sum(
            len(BASE_PACKAGES.get(lvl, []))
            for lvl in PROFILES if self.needs_profile(lvl)
        )
        epel_count = sum(
            len(EPEL_PACKAGES.get(lvl, []))
            for lvl in PROFILES if self.needs_profile(lvl)
        )
        if "rpm" not in self.skip:
            ghost = d.get("ghost_package") if d else None
            rpm_parts = [f"{pkg_count + epel_count} packages requested", "1 repo added"]
            if ghost or self.needs_profile("standard"):
                rpm_parts += ["1 ghost package", "1 orphaned config"]
            rpm_str = ", ".join(rpm_parts)
        else:
            rpm_str = "skipped"
        _info(f"{SECTION_ICONS['rpm']}  RPM:        {rpm_str}")

        # ── Services ─────────────────────────────────────────────────────────
        if "services" not in self.skip:
            en  = len(d.get("services_enabled",  [])) if d else 2
            dis = len(d.get("services_disabled", [])) if d else 1
            mas = len(d.get("services_masked",   [])) if d else (
                1 if self.needs_profile("standard") else 0)
            parts = []
            if en:  parts.append(f"{en} enabled")
            if dis: parts.append(f"{dis} disabled")
            if mas: parts.append(f"{mas} masked")
            svc_str = ", ".join(parts) if parts else "none"
        else:
            svc_str = "skipped"
        _info(f"{SECTION_ICONS['services']}  Services:   {svc_str}")

        # ── Config ───────────────────────────────────────────────────────────
        if "config" not in self.skip:
            if d:
                cfg_files   = self._count_created("/etc/myapp/")
                cfg_backups = len([k for k in d.get("file_backups", {})
                                   if k.startswith("/etc/")])
                cfg_parts = []
                if cfg_backups: cfg_parts.append(f"{cfg_backups} RPM config(s) modified")
                if cfg_files:   cfg_parts.append(f"{cfg_files} unowned file(s) created")
                cfg_str = ", ".join(cfg_parts) if cfg_parts else "applied"
            else:
                cfg_str = "RPM + unowned config drift applied"
        else:
            cfg_str = "skipped"
        _info(f"{SECTION_ICONS['config']}  Config:     {cfg_str}")

        # ── Network ──────────────────────────────────────────────────────────
        if "network" not in self.skip:
            fw_n = (len(d.get("firewall_services", [])) +
                    len(d.get("firewall_ports",    []))) if d else 3
            net_parts = [f"{fw_n} firewall rules", "hosts entries"]
            if self.needs_profile("standard"):
                net_parts += ["zone", "NM profile", "proxy"]
            net_str = ", ".join(net_parts)
        else:
            net_str = "skipped"
        _info(f"{SECTION_ICONS['network']}  Network:    {net_str}")

        # ── Storage ──────────────────────────────────────────────────────────
        if "storage" not in self.skip:
            if d:
                var_dirs = len([p for p in d.get("dirs_created", [])
                                if p.startswith("/var/")])
                sto_parts = []
                if var_dirs: sto_parts.append(f"{var_dirs} /var dir(s)")
                if self.needs_profile("standard"):
                    sto_parts.append("fstab entries")
                sto_str = ", ".join(sto_parts) if sto_parts else "dirs created"
            else:
                sto_str = "fstab + /var storage drift applied"
        else:
            sto_str = "skipped"
        _info(f"{SECTION_ICONS['storage']}  Storage:    {sto_str}")

        # ── Scheduled ────────────────────────────────────────────────────────
        if "scheduled" not in self.skip:
            if d:
                at_n    = len(d.get("at_jobs", []))
                tmr_n   = len([sv for sv in d.get("services_enabled", [])
                                if sv.endswith(".timer")])
                cron_n  = (self._count_created("/etc/cron.d/") +
                           self._count_created("/etc/cron.daily/"))
                spool_n = self._count_created("/var/spool/cron/")
                sch_parts = []
                if cron_n:  sch_parts.append(f"{cron_n} cron file(s)")
                if tmr_n:   sch_parts.append(f"{tmr_n} timer(s)")
                if at_n:    sch_parts.append(f"{at_n} at job(s)")
                if spool_n: sch_parts.append(f"{spool_n} user crontab(s)")
                sch_str = ", ".join(sch_parts) if sch_parts else "applied"
            else:
                sch_parts = ["2 cron files"]
                if self.needs_profile("standard"):
                    sch_parts += ["1 timer", "1 at job", "1 per-user crontab"]
                sch_str = ", ".join(sch_parts)
        else:
            sch_str = "skipped"
        _info(f"{SECTION_ICONS['scheduled']}  Scheduled:  {sch_str}")

        # ── Containers ───────────────────────────────────────────────────────
        if "containers" not in self.skip:
            if d:
                quadlets = (self._count_created("/etc/containers/systemd/") +
                            self._count_created("/home/appuser/.config/"))
                compose  = self._count_created("/opt/myapp/docker-compose")
                ctr_parts = []
                if quadlets: ctr_parts.append(f"{quadlets} quadlet file(s)")
                if compose:  ctr_parts.append("docker-compose.yml")
                ctr_str = ", ".join(ctr_parts) if ctr_parts else "applied"
            else:
                ctr_parts = ["1 quadlet (.container)"]
                if self.needs_profile("standard"):
                    ctr_parts += ["redis.container", "myapp.network", "docker-compose.yml"]
                ctr_str = ", ".join(ctr_parts)
        else:
            ctr_str = "skipped"
        _info(f"{SECTION_ICONS['containers']}  Containers: {ctr_str}")

        # ── Non-RPM ──────────────────────────────────────────────────────────
        if "nonrpm" not in self.skip:
            if d:
                rdirs   = len(d.get("recursive_dirs_created", []))
                scripts = self._count_created("/usr/local/bin/")
                nrpm_parts = []
                if rdirs:   nrpm_parts.append(f"{rdirs} dir tree(s) (venv/npm/git)")
                if scripts: nrpm_parts.append(f"{scripts} /usr/local/bin file(s)")
                nrpm_str = ", ".join(nrpm_parts) if nrpm_parts else "applied"
            else:
                nrpm_parts = ["Python venv", "Go binary (yq)"]
                if self.needs_profile("standard"):
                    nrpm_parts += ["npm project", "git repo", "deploy.sh"]
                nrpm_str = ", ".join(nrpm_parts)
        else:
            nrpm_str = "skipped"
        _info(f"{SECTION_ICONS['nonrpm']}  Non-RPM:    {nrpm_str}")

        # ── Kernel ───────────────────────────────────────────────────────────
        if "kernel" not in self.skip:
            if d:
                ker_files = (self._count_created("/etc/sysctl.d/") +
                             self._count_created("/etc/modules-load.d/") +
                             self._count_created("/etc/dracut.conf.d/"))
                grub_mod  = "/etc/default/grub" in d.get("file_backups", {})
                ker_parts = ["sysctl applied live"]
                if ker_files: ker_parts.insert(0, f"{ker_files} kernel config file(s)")
                if grub_mod:  ker_parts.append("grub args modified")
                ker_str = ", ".join(ker_parts)
            else:
                ker_parts = ["6 sysctl values applied"]
                if self.needs_profile("standard"):
                    ker_parts += ["br_netfilter loaded", "dracut config"]
                if self.needs_profile("kitchen-sink"):
                    ker_parts.append("grub args")
                ker_str = ", ".join(ker_parts)
        else:
            ker_str = "skipped"
        _info(f"{SECTION_ICONS['kernel']}  Kernel:     {ker_str}")

        # ── SELinux ──────────────────────────────────────────────────────────
        if "selinux" not in self.skip:
            nb = len(d.get("selinux_booleans", [])) if d else (
                1 + (1 if self.needs_profile("standard") else 0))
            nm = len(d.get("selinux_modules",  [])) if d else (
                1 if self.needs_profile("kitchen-sink") else 0)
            audit_n = self._count_created("/etc/audit/rules.d/") if d else (
                1 if self.needs_profile("standard") else 0)
            sel_parts = []
            if nb:      sel_parts.append(f"{nb} boolean(s) set")
            if audit_n: sel_parts.append(f"{audit_n} audit rule file(s)")
            if nm:      sel_parts.append(f"{nm} policy module(s)")
            sel_str = ", ".join(sel_parts) if sel_parts else "none"
        else:
            sel_str = "skipped"
        _info(f"{SECTION_ICONS['selinux']}  SELinux:    {sel_str}")

        # ── Users ────────────────────────────────────────────────────────────
        if "users" not in self.skip:
            usr_n  = len(d.get("users_created",  [])) if d else (
                1 + (1 if self.needs_profile("standard") else 0))
            grp_n  = len(d.get("groups_created", [])) if d else 1
            sudo_n = self._count_created("/etc/sudoers.d/") if d else (
                1 if self.needs_profile("standard") else 0)
            ssh_n  = self._count_created("/home/appuser/.ssh/") if d else (
                1 if self.needs_profile("standard") else 0)
            usr_parts = []
            if usr_n:  usr_parts.append(f"{usr_n} user(s)")
            if grp_n:  usr_parts.append(f"{grp_n} group(s)")
            if sudo_n: usr_parts.append(f"{sudo_n} sudoers rule(s)")
            if ssh_n:  usr_parts.append(f"{ssh_n} SSH key(s)")
            usr_str = ", ".join(usr_parts) if usr_parts else "none"
        else:
            usr_str = "skipped"
        _info(f"{SECTION_ICONS['users']}  Users:      {usr_str}")

        # ── Secrets ──────────────────────────────────────────────────────────
        if "secrets" not in self.skip:
            if d:
                sec_files = (self._count_created("/etc/myapp/server.key") +
                             self._count_created("/opt/myapp/.env"))
                sec_str = (f"{sec_files} secret file(s) + credential blocks "
                           "in app configs") if sec_files else "credential blocks appended"
            else:
                sec_str = "fake secrets planted"
        else:
            sec_str = "skipped"
        _info(f"{SECTION_ICONS['secrets']}  Secrets:    {sec_str}")

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
  sudo ./driftify.py                          # standard profile (interactive confirm)
  sudo ./driftify.py -y                       # skip confirmation prompt
  sudo ./driftify.py -q                       # quiet — section banners + errors only
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
    p.add_argument(
        "-y", "--yes", action="store_true",
        help="skip interactive confirmation prompt",
    )
    p.add_argument(
        "-q", "--quiet", action="store_true",
        help="suppress per-command and per-file output; show only section "
             "banners, warnings, and errors",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="reserved for future use (no effect today; subprocess output "
             "already passes through directly)",
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
        yes=args.yes,
        quiet=args.quiet,
        verbose=args.verbose,
    )

    if args.undo:
        drifter.run_undo()
    else:
        drifter.run()


if __name__ == "__main__":
    main()
