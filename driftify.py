#!/usr/bin/python3
"""driftify — apply synthetic drift to a fresh RHEL/CentOS Stream 9 or 10 system.

Companion tool to yoinkc.  Runs on a clean host and applies curated system
modifications so that every yoinkc inspector has something to detect.
"""

import argparse
import json
import os
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
    BLUE   = "\033[34m"
    RESET  = "\033[0m"

if not sys.stdout.isatty():
    _C.BOLD = _C.DIM = _C.GREEN = _C.YELLOW = _C.RED = ""
    _C.CYAN = _C.BLUE = _C.RESET = ""


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
            "users_created": [],
            "groups_created": [],
            "selinux_booleans": [],
            "selinux_modules": [],
        }
        self.save()

    def finish(self) -> None:
        self.data["finished"] = datetime.now(timezone.utc).isoformat()
        self.save()

    def record(self, key: str, value) -> None:
        """Append *value* to a list key, or set a scalar key."""
        if isinstance(self.data.get(key), list):
            if value not in self.data[key]:
                self.data[key].append(value)
        else:
            self.data[key] = value
        self.save()


# ── Driftify ─────────────────────────────────────────────────────────────────

class Driftify:

    _IMPLEMENTED = {"rpm", "services"}

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
        return subprocess.run(
            cmd, check=check,
            capture_output=capture, text=capture,
        )

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
        # Future sections — will be added iteratively:
        # self.drift_config()
        # self.drift_network()
        # self.drift_storage()
        # self.drift_scheduled()
        # self.drift_containers()
        # self.drift_nonrpm()
        # self.drift_kernel()
        # self.drift_selinux()
        # self.drift_users()
        # self.drift_secrets()

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

        # Ghost package: install then immediately remove (standard+)
        if self.needs_profile("standard"):
            _info(f"{_I.RECYCLE}  Ghost package: install + remove "
                  f"'{GHOST_PACKAGE}'")
            self.run_cmd(["dnf", "install", "-y", GHOST_PACKAGE], check=False)
            self.run_cmd(["dnf", "remove", "-y", GHOST_PACKAGE], check=False)
            if not self.dry_run:
                self.stamp.record("ghost_package", GHOST_PACKAGE)

        # Snapshot final transaction ID
        if not self.dry_run:
            tid = self._dnf_last_tid()
            self.stamp.record("dnf_transaction_end", tid)

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
            bt_exists = True
            if not self.dry_run:
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

        # RPM stats
        pkg_count = sum(
            len(BASE_PACKAGES.get(lvl, []))
            for lvl in PROFILES if self.needs_profile(lvl)
        )
        epel_count = sum(
            len(EPEL_PACKAGES.get(lvl, []))
            for lvl in PROFILES if self.needs_profile(lvl)
        )
        rpm_parts = []
        if "rpm" not in self.skip:
            rpm_parts.append(f"{pkg_count + epel_count} packages requested")
            rpm_parts.append("1 repo added")
            if self.needs_profile("standard"):
                rpm_parts.append("1 ghost package")

        icon = SECTION_ICONS["rpm"]
        _info(f"{icon}  RPM:        "
              f"{', '.join(rpm_parts) if rpm_parts else 'skipped'}")

        # Service stats
        svc_parts = []
        if "services" not in self.skip:
            svc_parts.append("2 enabled")
            svc_parts.append("1 disabled")
            if self.needs_profile("standard"):
                svc_parts.append("1 masked")

        icon = SECTION_ICONS["services"]
        _info(f"{icon}  Services:   "
              f"{', '.join(svc_parts) if svc_parts else 'skipped'}")

        # Placeholder lines for future sections
        for section in SECTIONS[2:]:
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
