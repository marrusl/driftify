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
        "podman",
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

GRUB_DEFAULT_PATH = "/etc/default/grub"


# ── Nerd Font icons ──────────────────────────────────────────────────────────

class _I:
    ROCKET   = "\uf135"
    CHECK    = "\uf058"   # check-circle
    OK       = "\uf00c"   # check
    WARN     = "\uf071"   # exclamation-triangle
    ERROR    = "\uf057"   # times-circle
    EYE      = "\uf06e"   # eye (dry-run)
    SKIP     = "\uf04e"   # forward
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
    """Run record written to /etc/driftify.stamp after a successful apply."""

    def __init__(self, path=None):
        self.path = path or STAMP_PATH
        self.data: dict = {}

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
        }
        self.save()

    def finish(self) -> None:
        self.data["finished"] = datetime.now(timezone.utc).isoformat()
        self.save()



# ── Driftify ─────────────────────────────────────────────────────────────────

class Driftify:

    _IMPLEMENTED = {
        "rpm", "services", "config", "network", "storage",
        "scheduled", "containers", "nonrpm", "kernel", "selinux",
        "users", "secrets",
    }

    _YOINKC_SCRIPT_URL = (
        "https://raw.githubusercontent.com/marrusl/yoinkc/main/run-yoinkc.sh"
    )

    def __init__(self, profile: str, dry_run: bool, skip_sections: list,
                 yes: bool = False,
                 quiet: bool = False, verbose: bool = False,
                 run_yoinkc: bool = False, yoinkc_output: str = "./yoinkc-output"):
        self.profile = profile
        self.dry_run = dry_run
        self.skip = set(skip_sections)
        self.yes = yes
        self.quiet = quiet
        # verbose: reserved for future use when capture=True calls are added;
        # subprocess output currently passes through directly so --verbose
        # has no additional effect today.
        self.verbose = verbose
        self.run_yoinkc = run_yoinkc
        self.yoinkc_output = yoinkc_output
        self.stamp = StampFile()
        self.os_id, self.os_major = detect_os()
        self._t0 = None
        self._step = 0
        self._total = sum(
            1 for s in SECTIONS
            if s not in self.skip and s in self._IMPLEMENTED
        )
        self._appuser_created = True  # cleared if useradd appuser fails at runtime
        self._dbuser_created  = True  # cleared if useradd dbuser fails at runtime

    # ── helpers ───────────────────────────────────────────────────────────

    def needs_profile(self, level: str) -> bool:
        """True when the active profile includes *level*."""
        return PROFILE_RANK[self.profile] >= PROFILE_RANK[level]

    def run_cmd(self, cmd, check=True, capture=False):
        """Execute *cmd*, or print it if --dry-run.

        With --quiet the "Running:" echo is suppressed and all subprocess
        output is captured and discarded so it doesn't reach the terminal.
        The caller can re-run without --quiet to see diagnostic detail.
        Warnings on non-zero exit and [DRY RUN] lines are never suppressed.
        """
        pretty = " ".join(str(c) for c in cmd)
        if self.dry_run:
            _dry(pretty)
            return None
        if not self.quiet:
            _info(f"Running: {pretty}")
        # capture=True means the caller needs stdout; quiet=True means we
        # want to suppress terminal noise — both cases use capture_output=True.
        capture_out = capture or self.quiet
        result = subprocess.run(
            cmd, check=check,
            capture_output=capture_out, text=capture_out,
        )
        if not check and result.returncode != 0:
            _warn(f"  ↳ exited {result.returncode}: {pretty}")
        return result

    def _ensure_dir(self, path: Path) -> None:
        """Create directory when needed."""
        if path.exists():
            return
        if self.dry_run:
            _dry(f"mkdir -p {path}")
            return
        path.mkdir(parents=True, exist_ok=True)
        _info(f"Created dir {path}")

    def _write_managed_text(self, path_str: str, content: str, mode: int = 0o644) -> None:
        """Write a text file idempotently.

        NOTE: reads existing content in text mode for change-detection.
        Only suitable for text files — binary paths would raise
        UnicodeDecodeError.  All files driftify manages are text.
        """
        path = Path(path_str)
        if path.exists():
            with open(path) as fh:
                if fh.read() == content:
                    if not self.quiet:
                        _info(f"No change needed: {path}")
                    return
        if self.dry_run:
            action = "update" if path.exists() else "create"
            _dry(f"{action} file {path}")
            return
        self._ensure_dir(path.parent)
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, mode)
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
            if self.needs_profile("standard"):
                lines.append(
                    f"{_I.WARN}  sshd_config will be modified: Port \u2192 2222, "
                    "PermitRootLogin \u2192 no "
                    "\u2014 firewall and SELinux label updated; "
                    "takes effect on next sshd restart or reboot"
                )

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
                sch += ", /etc/crontab entry, systemd timer pair, at job, per-user crontab"
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
                ker += ", load br_netfilter, modprobe.d options, dracut config, grub audit=1"
            if self.needs_profile("kitchen-sink"):
                ker += " + panic=60"
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

    def _confirm(self) -> None:
        """Print a description of what will happen and ask for confirmation.

        Exits immediately if the user declines.  Skipped when --yes or
        --dry-run are active.
        """
        if self.yes or self.dry_run:
            return

        print()
        print(f"  {_C.BOLD}About to apply {self.profile} profile drift "
              f"on {self.os_id} {self.os_major}:{_C.RESET}")
        for line in self._run_description():
            print(f"    • {line}")
        print()

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

        self._confirm()

        if not self.dry_run:
            self.stamp.start(self.profile, self.os_id, self.os_major)

        self.drift_rpm()
        self.drift_services()
        self.drift_config()
        self.drift_network()
        self.drift_storage()
        self.drift_users()
        # WARNING: drift_scheduled(), drift_containers(), and drift_secrets()
        # must all run after drift_users().  drift_scheduled() writes crontabs
        # owned by appuser; drift_containers() chowns files under /home/appuser/;
        # drift_secrets() writes into /home/appuser/.  Reordering breaks silently.
        self.drift_scheduled()
        self.drift_containers()
        self.drift_kernel()
        self.drift_selinux()
        self.drift_nonrpm()
        self.drift_secrets()

        if not self.dry_run:
            self.stamp.finish()

        self._print_summary()

        if self.run_yoinkc:
            self._launch_yoinkc()

    # ── RPM / Packages ────────────────────────────────────────────────────

    def drift_rpm(self) -> None:
        if "rpm" in self.skip:
            _skip("Skipping RPM section (--skip-rpm)")
            return

        self._next_step("rpm")

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

        # Disable kdump if it exists (not present on Fedora or minimal installs)
        _KDUMP_UNIT_PATHS = [
            Path("/usr/lib/systemd/system/kdump.service"),
            Path("/lib/systemd/system/kdump.service"),
        ]
        if self.dry_run:
            kdump_exists = any(p.exists() for p in _KDUMP_UNIT_PATHS)
        else:
            r = subprocess.run(
                ["systemctl", "cat", "kdump"],
                capture_output=True, text=True,
            )
            kdump_exists = r.returncode == 0

        if kdump_exists:
            _info(f"{_I.BAN}  Disabling kdump")
            self.run_cmd(["systemctl", "disable", "kdump"], check=False)
        else:
            _warn("kdump unit not found — skipping disable")

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
            else:
                _warn("bluetooth unit not found — skipping mask")

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
            # Open port 2222 in firewalld so SSH is reachable after sshd restarts.
            # drift_network opens 8080/tcp but not the new SSH port, so we handle
            # it here alongside the config change that requires it.
            _info(f"{_I.GLOBE}  Opening 2222/tcp in firewalld for SSH")
            self.run_cmd(
                ["firewall-cmd", "--permanent", "--add-port=2222/tcp"],
                check=False,
            )
            self.run_cmd(["firewall-cmd", "--reload"], check=False)
            # Add the SELinux port label so sshd can bind to 2222.  semanage may
            # not be present on every minimal install; skip gracefully if absent.
            import shutil as _shutil_semanage
            if _shutil_semanage.which("semanage"):
                _info(f"{_I.SHIELD}  Adding ssh_port_t SELinux label for port 2222")
                self.run_cmd(
                    ["semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", "2222"],
                    check=False,
                )
            else:
                _warn("semanage not found — skipping ssh_port_t label for 2222"
                      " (install policycoreutils-python-utils if needed)")
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
        for port in fw_ports:
            self.run_cmd(["firewall-cmd", "--permanent", f"--add-port={port}"],
                         check=False)
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
export NO_PROXY=localhost,127.0.0.1,.internal,github.com,githubusercontent.com,ghcr.io,quay.io,registry.redhat.io
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
            # System crontab entry — exercises yoinkc's /etc/crontab parsing
            # path (distinct from /etc/cron.d/ which is covered at minimal)
            self._append_managed_block(
                "/etc/crontab",
                "logrotate",
                "30 2 * * * root /usr/bin/logrotate /etc/logrotate.conf",
                create_if_missing=False,
            )

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
        _info(f"{_I.USERS}  Creating user appuser (UID 1001, primary: appgroup)")
        result = self.run_cmd(
            ["useradd", "-u", "1001", "-g", "appgroup", "-m",
             "-c", "App User", "appuser"],
            check=False,
        )
        if not self.dry_run and result is not None and result.returncode != 0:
            _warn("useradd appuser failed — skipping SSH keys, chown, and sudoers")
            self._appuser_created = False

        if self.needs_profile("standard"):
            _info(f"{_I.USERS}  Creating user dbuser (UID 1002, nologin)")
            result = self.run_cmd(
                ["useradd", "-u", "1002", "-s", "/sbin/nologin", "-M",
                 "-c", "DB Service Account", "dbuser"],
                check=False,
            )
            if not self.dry_run and result is not None and result.returncode != 0:
                _warn("useradd dbuser failed")
                self._dbuser_created = False

            if self._appuser_created:
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
            if not self.dry_run and self._appuser_created:
                self.run_cmd(
                    ["chown", "-R", "appuser:appgroup",
                     str(user_quadlet_dir.parent.parent.parent)],
                    check=False,
                )

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
            else:
                _dry(f"cp /usr/bin/true {mystery} && strip {mystery}")

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
            with urllib.request.urlopen(url, timeout=60) as resp:
                with open(dest, "wb") as fh:
                    fh.write(resp.read())
            os.chmod(dest, 0o755)
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

            # modprobe.d options — persistent per-module parameter;
            # exercises yoinkc's modprobe.d config capture path
            self._write_managed_text(
                "/etc/modprobe.d/driftify.conf",
                "# Module parameters — driftify synthetic fixture\n"
                "# yoinkc should detect this as a persistent modprobe.d config\n"
                "options br_netfilter nf_conntrack_max=131072\n",
            )

            # Dracut config
            self._write_managed_text(
                "/etc/dracut.conf.d/driftify.conf",
                "# Custom dracut config — driftify synthetic fixture\n"
                'add_drivers+=" overlay "\n'
                'compress="gzip"\n',
            )

            # GRUB hardening — add audit=1 at standard profile so yoinkc's
            # GRUB defaults detection fires without requiring kitchen-sink
            if not self.needs_profile("kitchen-sink"):
                self._append_kernel_cmdline_arg("audit=1")

        if self.needs_profile("kitchen-sink"):
            self._append_kernel_cmdline_arg("panic=60 audit=1")

    def _append_kernel_cmdline_arg(self, args: str) -> None:
        """Append args to GRUB_CMDLINE_LINUX in /etc/default/grub (idempotent)."""
        grub_path = GRUB_DEFAULT_PATH
        path = Path(grub_path)
        if not path.exists():
            _warn(f"{grub_path} not found — skipping grub modification")
            return
        with open(path) as fh:
            content = fh.read()

        def _append(m):
            existing = m.group(1).rstrip()
            existing_args = existing.split() if existing else []
            new_args = [a for a in args.split() if a not in existing_args]
            if not new_args:
                return m.group(0)
            sep = " " if existing else ""
            return f'GRUB_CMDLINE_LINUX="{existing}{sep}{" ".join(new_args)}"'

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

        if self.needs_profile("standard"):
            _info(f"{_I.SHIELD}  Setting httpd_can_network_relay on")
            self.run_cmd(
                ["setsebool", "-P", "httpd_can_network_relay", "on"],
                check=False,
            )

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
        finally:
            import shutil as _shutil
            _shutil.rmtree(td, ignore_errors=True)

    def _launch_yoinkc(self) -> None:
        """Download run-yoinkc.sh from the yoinkc repo and execute it."""
        import urllib.request
        import tempfile
        import stat

        _banner(f"{_I.ROCKET}  Launching yoinkc")
        _info(f"{_I.DOWNLOAD}  Script: {self._YOINKC_SCRIPT_URL}")
        _info(f"{_I.DATABASE}  Output: {self.yoinkc_output}")

        if self.dry_run:
            _dry(f"curl {self._YOINKC_SCRIPT_URL} | sh -s -- {self.yoinkc_output}")
            return

        script_path = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".sh", delete=False, mode="w"
            ) as tf:
                script_path = tf.name
            with urllib.request.urlopen(self._YOINKC_SCRIPT_URL, timeout=60) as resp:
                with open(script_path, "w") as fh:
                    fh.write(resp.read().decode())
            os.chmod(script_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
            # Stream stdout+stderr live so the user sees container progress,
            # but accumulate the output so we can check it on failure.
            if not self.quiet:
                _info(f"Running: sh {script_path} {self.yoinkc_output}")
            proc = subprocess.Popen(
                ["sh", script_path, self.yoinkc_output],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            captured_lines: list[str] = []
            if proc.stdout is None:
                _warn("yoinkc subprocess produced no output")
                return
            for line in proc.stdout:
                if not self.quiet:
                    print(line, end="", flush=True)
                captured_lines.append(line)
            proc.wait()
            captured = "".join(captured_lines)

            if proc.returncode != 0:
                # In quiet mode the output was suppressed above — replay it now
                # so the user can see what went wrong.
                if self.quiet and captured:
                    print(captured, end="")
                _warn(f"yoinkc failed with exit code {proc.returncode}")
                _AUTH_PATTERNS = (
                    "unauthorized",
                    "authentication required",
                    "login",
                    "registry.redhat.io",
                )
                if any(p in captured.lower() for p in _AUTH_PATTERNS):
                    _warn(
                        "Hint: run 'sudo podman login registry.redhat.io'"
                        " before using --run-yoinkc on RHEL hosts."
                    )
            else:
                output_path = Path(self.yoinkc_output).resolve()
                parent_path = output_path.parent
                tarballs = list(parent_path.glob("*.tar.gz"))
                if tarballs:
                    self._print_next_steps()
                else:
                    _warn(f"yoinkc completed but no tarball found in {parent_path}")
        except Exception as exc:
            _warn(f"Could not launch yoinkc: {exc}")
        finally:
            if script_path:
                try:
                    os.unlink(script_path)
                except OSError:
                    pass

    def _print_next_steps(self) -> None:
        """Print a 'Next steps' block after a successful yoinkc run."""
        import socket as _socket
        hostname = _socket.gethostname()
        output_path = Path(self.yoinkc_output).resolve()
        parent_path = output_path.parent
        tarballs = sorted(parent_path.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime)
        tarball_name = tarballs[-1].name if tarballs else f"yoinkc-output-{hostname}-*.tar.gz"
        print()
        _banner(f"{_I.DOWNLOAD}  Next steps")
        _info(f"{_I.ROCKET}  Copy the tarball to your workstation and review:")
        _info(f"             scp {hostname}:{parent_path / tarball_name} .")
        _info(f"             yoinkc-refine {tarball_name}")

    def _print_summary(self) -> None:
        elapsed = time.monotonic() - self._t0
        m, s = divmod(int(elapsed), 60)

        _banner(f"{_I.CHECK}  driftify complete "
                f"({self.profile} profile, {m}m {s:02d}s)")

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
            rpm_parts = [f"{pkg_count + epel_count} packages requested", "1 repo added"]
            if self.needs_profile("standard"):
                rpm_parts += ["1 ghost package", "1 orphaned config"]
            rpm_str = ", ".join(rpm_parts)
        else:
            rpm_str = "skipped"
        _info(f"{SECTION_ICONS['rpm']}  RPM:        {rpm_str}")

        # ── Services ─────────────────────────────────────────────────────────
        if "services" not in self.skip:
            en  = 2
            dis = 1
            mas = 1 if self.needs_profile("standard") else 0
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
            cfg_str = "RPM + unowned config drift applied"
        else:
            cfg_str = "skipped"
        _info(f"{SECTION_ICONS['config']}  Config:     {cfg_str}")

        # ── Network ──────────────────────────────────────────────────────────
        if "network" not in self.skip:
            net_parts = ["3 firewall rules", "hosts entries"]
            if self.needs_profile("standard"):
                net_parts += ["zone", "NM profile", "proxy"]
            net_str = ", ".join(net_parts)
        else:
            net_str = "skipped"
        _info(f"{SECTION_ICONS['network']}  Network:    {net_str}")

        # ── Storage ──────────────────────────────────────────────────────────
        if "storage" not in self.skip:
            sto_str = "fstab + /var storage drift applied"
        else:
            sto_str = "skipped"
        _info(f"{SECTION_ICONS['storage']}  Storage:    {sto_str}")

        # ── Scheduled ────────────────────────────────────────────────────────
        if "scheduled" not in self.skip:
            sch_parts = ["2 cron files"]
            if self.needs_profile("standard"):
                sch_parts += ["1 crontab entry", "1 timer", "1 at job", "1 per-user crontab"]
            sch_str = ", ".join(sch_parts)
        else:
            sch_str = "skipped"
        _info(f"{SECTION_ICONS['scheduled']}  Scheduled:  {sch_str}")

        # ── Containers ───────────────────────────────────────────────────────
        if "containers" not in self.skip:
            ctr_parts = ["1 quadlet (.container)"]
            if self.needs_profile("standard"):
                ctr_parts += ["redis.container", "myapp.network", "docker-compose.yml"]
            ctr_str = ", ".join(ctr_parts)
        else:
            ctr_str = "skipped"
        _info(f"{SECTION_ICONS['containers']}  Containers: {ctr_str}")

        # ── Non-RPM ──────────────────────────────────────────────────────────
        if "nonrpm" not in self.skip:
            nrpm_parts = ["Python venv", "Go binary (yq)"]
            if self.needs_profile("standard"):
                nrpm_parts += ["npm project", "git repo", "deploy.sh"]
            nrpm_str = ", ".join(nrpm_parts)
        else:
            nrpm_str = "skipped"
        _info(f"{SECTION_ICONS['nonrpm']}  Non-RPM:    {nrpm_str}")

        # ── Kernel ───────────────────────────────────────────────────────────
        if "kernel" not in self.skip:
            ker_parts = ["6 sysctl values applied"]
            if self.needs_profile("standard"):
                ker_parts += ["br_netfilter loaded", "modprobe.d config",
                              "dracut config", "grub audit=1"]
            ker_str = ", ".join(ker_parts)
        else:
            ker_str = "skipped"
        _info(f"{SECTION_ICONS['kernel']}  Kernel:     {ker_str}")

        # ── SELinux ──────────────────────────────────────────────────────────
        if "selinux" not in self.skip:
            nb      = 1 + (1 if self.needs_profile("standard") else 0)
            nm      = 1 if self.needs_profile("kitchen-sink") else 0
            audit_n = 1 if self.needs_profile("standard") else 0
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
            usr_n  = 1 + (1 if self.needs_profile("standard") else 0)
            grp_n  = 1
            sudo_n = 1 if self.needs_profile("standard") else 0
            ssh_n  = 1 if self.needs_profile("standard") else 0
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

        if "config" not in self.skip and self.needs_profile("standard"):
            print()
            _warn("WARNING: sshd_config was modified \u2014 "
                  "Port changed to 2222, PermitRootLogin set to no.")
            _warn("         firewall-cmd and semanage updated for port 2222.")
            _warn("         Changes take effect on next sshd restart or reboot.")

        print()
        _info(f"{_I.STAMP}  Stamp file: {STAMP_PATH}")
        if not self.run_yoinkc:
            _info(f"{_I.ROCKET}  Run yoinkc: sudo ./driftify.py --run-yoinkc")
            _info(f"             or: curl -fsSL "
                  f"https://raw.githubusercontent.com/marrusl/yoinkc/main/"
                  f"run-yoinkc.sh | sh")


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
    p.add_argument(
        "--run-yoinkc", action="store_true",
        help="after applying drift, download and run run-yoinkc.sh",
    )
    p.add_argument(
        "--yoinkc-output", default="./yoinkc-output", metavar="DIR",
        help="output directory for yoinkc artifacts (default: ./yoinkc-output)",
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
        yes=args.yes,
        quiet=args.quiet,
        verbose=args.verbose,
        run_yoinkc=args.run_yoinkc,
        yoinkc_output=args.yoinkc_output,
    )

    drifter.run()


if __name__ == "__main__":
    main()
