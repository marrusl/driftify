import io
import json
import os
import subprocess
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path

import driftify


class DriftifyTestCase(unittest.TestCase):
    """Base class that patches detect_os and suppresses log output."""

    def setUp(self):
        self.original_stamp_path = driftify.STAMP_PATH
        self.original_detect_os = driftify.detect_os
        driftify.detect_os = lambda: ("centos", 9)
        self._devnull = io.StringIO()
        self._suppress = redirect_stdout(self._devnull)
        self._suppress.__enter__()

    def tearDown(self):
        self._suppress.__exit__(None, None, None)
        self._devnull.close()
        driftify.STAMP_PATH = self.original_stamp_path
        driftify.detect_os = self.original_detect_os


class RedirectedFixtureTestCase(DriftifyTestCase):
    """Base class for fixture tests that redirect absolute paths into a temp tree."""

    def _build_redirected_drifter(self, td, profile):
        driftify.STAMP_PATH = Path(td) / "stamp.json"
        d = driftify.Driftify(profile, dry_run=False, skip_sections=[])
        d.stamp.start(d.profile, d.os_id, d.os_major)

        root = Path(td)

        def map_path(path_str):
            path = Path(path_str)
            if str(path).startswith(str(root)):
                return path
            rel = str(path).lstrip("/")
            return root / rel

        original_write = d._write_managed_text
        original_append = d._append_managed_block
        original_remove_path = d._remove_path
        original_remove_block = d._remove_managed_block
        original_ensure_dir = d._ensure_dir

        d._write_managed_text = (
            lambda path_str, content, mode=0o644:
            original_write(str(map_path(path_str)), content, mode)
        )
        d._append_managed_block = (
            lambda path_str, marker, block, mode=0o644, create_if_missing=True:
            original_append(
                str(map_path(path_str)),
                marker,
                block,
                mode=mode,
                create_if_missing=create_if_missing,
            )
        )
        d._remove_path = lambda path_str: original_remove_path(str(map_path(path_str)))
        d._remove_managed_block = (
            lambda path_str, marker:
            original_remove_block(str(map_path(path_str)), marker)
        )
        d._ensure_dir = lambda path: original_ensure_dir(map_path(path))

        return d, map_path


class TestProfileAndSkipLogic(DriftifyTestCase):
    def test_needs_profile_ranking(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self.assertTrue(d.needs_profile("minimal"))
        self.assertFalse(d.needs_profile("standard"))

        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self.assertTrue(d.needs_profile("minimal"))
        self.assertTrue(d.needs_profile("standard"))
        self.assertFalse(d.needs_profile("kitchen-sink"))

        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        self.assertTrue(d.needs_profile("kitchen-sink"))

    def test_total_steps_respect_skip_flags(self):
        # all 12 implemented sections
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self.assertEqual(d._total, 12)

        d = driftify.Driftify("standard", dry_run=True, skip_sections=["network", "storage"])
        self.assertEqual(d._total, 10)

        d = driftify.Driftify(
            "standard",
            dry_run=True,
            skip_sections=["rpm", "services", "config", "network",
                           "storage", "scheduled", "containers", "nonrpm",
                           "kernel", "selinux", "users", "secrets"],
        )
        self.assertEqual(d._total, 0)


class TestStampFile(DriftifyTestCase):
    def test_stamp_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            stamp_path = Path(td) / "driftify.stamp"
            sf = driftify.StampFile(stamp_path)
            sf.start("standard", "centos", 9)
            sf.finish()
            with open(stamp_path) as fh:
                loaded = json.load(fh)
            self.assertEqual(loaded["profile"], "standard")
            self.assertEqual(loaded["os_major"], 9)
            self.assertIsNotNone(loaded["finished"])
            self.assertNotIn("services_enabled", loaded)



class TestHelpersAndDryRun(DriftifyTestCase):
    def _build_non_dry_with_temp_stamp(self, td):
        driftify.STAMP_PATH = Path(td) / "stamp.json"
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
        d.stamp.start(d.profile, d.os_id, d.os_major)
        return d

    def test_write_managed_text_creates_and_updates(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            file_path = Path(td) / "cfg.txt"

            d._write_managed_text(str(file_path), "one\n")
            self.assertTrue(file_path.exists())
            self.assertEqual(file_path.read_text(), "one\n")

            d._write_managed_text(str(file_path), "two\n")
            self.assertEqual(file_path.read_text(), "two\n")

    def test_append_managed_block_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            p = Path(td) / "app.conf"
            p.write_text("base=true\n")

            d._append_managed_block(str(p), "marker", "x=1")
            first = p.read_text()
            d._append_managed_block(str(p), "marker", "x=1")
            second = p.read_text()

            self.assertEqual(first, second)
            self.assertIn("BEGIN DRIFTIFY marker", second)

    def test_run_cmd_dry_run_does_not_execute(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        out = d.run_cmd(["echo", "hello"])
        self.assertIsNone(out)

    def test_run_cmd_warns_on_nonzero_exit(self):
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
        mock_result = unittest.mock.MagicMock()
        mock_result.returncode = 127
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with unittest.mock.patch("subprocess.run", return_value=mock_result):
                d.run_cmd(["no-such-cmd"], check=False)
        self._suppress.__enter__()
        self.assertIn("exited 127", buf.getvalue())

    def test_run_cmd_no_warning_on_success(self):
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
        mock_result = unittest.mock.MagicMock()
        mock_result.returncode = 0
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with unittest.mock.patch("subprocess.run", return_value=mock_result):
                d.run_cmd(["true"], check=False)
        self._suppress.__enter__()
        self.assertNotIn("exited", buf.getvalue())

    def test_dry_run_output_mentions_new_sections(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=["rpm", "services"])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.run()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("Config Files", output)
        self.assertIn("Network", output)
        self.assertIn("Storage", output)
        self.assertIn("Secrets", output)
        self.assertIn("/etc/myapp/app.conf", output)
        self.assertIn("/etc/hosts", output)

    def test_ghost_package_dry_run_shows_orphaned_config(self):
        d = driftify.Driftify("standard", dry_run=True,
                              skip_sections=["services", "config", "network",
                                             "storage", "secrets"])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.run()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("/etc/words.conf", output)
        self.assertIn(driftify.GHOST_PACKAGE, output)

    def test_kdump_dry_run_skips_when_unit_absent(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=["rpm"])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with unittest.mock.patch.object(driftify.Path, "exists",
                                            return_value=False):
                d.drift_services()
        self._suppress.__enter__()
        self.assertNotIn("systemctl disable kdump", buf.getvalue())
        self.assertIn("kdump unit not found", buf.getvalue())

    def test_kdump_dry_run_disables_when_present(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=["rpm"])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with unittest.mock.patch.object(driftify.Path, "exists",
                                            return_value=True):
                d.drift_services()
        self._suppress.__enter__()
        self.assertIn("systemctl disable kdump", buf.getvalue())

    def test_bluetooth_dry_run_respects_unit_absence(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=["rpm"])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with unittest.mock.patch.object(driftify.Path, "exists",
                                            return_value=False):
                d.drift_services()
        self._suppress.__enter__()
        # When unit absent, mask command should NOT be in dry-run output
        self.assertNotIn("systemctl mask bluetooth", buf.getvalue())

    def test_bluetooth_dry_run_shows_mask_when_unit_present(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=["rpm"])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        # Return True only for bluetooth unit paths so _write_managed_text
        # (called by the new drop-in code) doesn't attempt to open missing files.
        def _bt_exists(self_path):
            return "bluetooth.service" in str(self_path)
        with redirect_stdout(buf):
            with unittest.mock.patch.object(driftify.Path, "exists", _bt_exists):
                d.drift_services()
        self._suppress.__enter__()
        self.assertIn("systemctl mask bluetooth", buf.getvalue())

    def test_set_or_append_directive(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            p = Path(td) / "test.conf"
            p.write_text("Listen 80\nServerName localhost\n")

            d._set_or_append_directive(str(p), "Listen", "Listen 8080")
            self.assertIn("Listen 8080", p.read_text())
            self.assertNotIn("Listen 80\n", p.read_text())

            d._set_or_append_directive(str(p), "NewKey", "NewKey value")
            self.assertIn("NewKey value", p.read_text())

    def test_apply_directives_batches_into_single_write(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            p = Path(td) / "httpd.conf"
            p.write_text("Listen 80\n#ServerName example.com\nMaxRequestWorkers 150\n")

            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                d._apply_directives(str(p), {
                    "Listen":            "Listen 8080",
                    "ServerName":        "ServerName driftify.local",
                    "MaxRequestWorkers": "MaxRequestWorkers 256",
                })
            self._suppress.__enter__()

            content = p.read_text()
            self.assertIn("Listen 8080", content)
            self.assertIn("ServerName driftify.local", content)
            self.assertIn("MaxRequestWorkers 256", content)
            self.assertNotIn("Listen 80\n", content)
            # Only one "Wrote" line — single write for all three directives
            self.assertEqual(buf.getvalue().count("Wrote"), 1)

    def test_ensure_dir_logs_creation(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            new_dir = Path(td) / "myapp"

            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                d._ensure_dir(new_dir)
            self._suppress.__enter__()

            self.assertTrue(new_dir.exists())
            self.assertIn(str(new_dir), buf.getvalue())

    def test_ensure_dir_silent_when_already_exists(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                d._ensure_dir(Path(td))  # already exists
            self._suppress.__enter__()
            self.assertEqual(buf.getvalue(), "")


class TestRunCmdDnfQuietMode(DriftifyTestCase):
    """Tests for the Popen-based dnf repo-metadata surfacing in quiet mode."""

    _METADATA_LINES = [
        "CentOS Stream 9 - BaseOS    3.2 MB/s |  8.1 MB  00:02",
        "CentOS Stream 9 - AppStream 2.1 MB/s | 12.4 MB  00:05",
        "Extra Packages for Enterprise Linux 9    1.4 MB/s |  6.3 MB  00:04",
    ]
    _NOISE_LINES = [
        "Last metadata expiration check: 0:01:23 ago.",
        "Dependencies resolved.",
        "================================================================================",
        " Package           Arch      Version          Repository       Size",
        "Installing:",
        " httpd             x86_64    2.4.51-7.el9     appstream        1.5 M",
        "Transaction Summary",
        "Total download size: 1.5 M",
        "Downloading Packages:",
        "Running transaction check",
        "Complete!",
    ]

    def _mock_popen(self, stdout_lines, returncode=0):
        proc = unittest.mock.MagicMock()
        proc.stdout = [line + "\n" for line in stdout_lines]
        proc.returncode = returncode
        proc.wait = unittest.mock.Mock()
        return proc

    def _capture_quiet_dnf(self, stdout_lines, returncode=0, check=True):
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[], quiet=True)
        proc = self._mock_popen(stdout_lines, returncode)
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                with unittest.mock.patch("subprocess.Popen", return_value=proc):
                    d.run_cmd(["dnf", "install", "-y", "httpd"], check=check)
        finally:
            self._suppress.__enter__()
        return buf.getvalue()

    def test_metadata_lines_produce_sub_output(self):
        output = self._capture_quiet_dnf(self._METADATA_LINES)
        self.assertIn("fetching CentOS Stream 9 - BaseOS", output)
        self.assertIn("fetching CentOS Stream 9 - AppStream", output)
        self.assertIn("fetching Extra Packages for Enterprise Linux 9", output)

    def test_non_metadata_output_suppressed(self):
        output = self._capture_quiet_dnf(self._NOISE_LINES)
        self.assertNotIn("Last metadata", output)
        self.assertNotIn("Dependencies resolved", output)
        self.assertNotIn("Complete!", output)
        # Ensure no content from the noise lines leaked through
        self.assertNotIn("Transaction Summary", output)

    def test_mixed_lines_only_metadata_surfaces(self):
        all_lines = self._METADATA_LINES + self._NOISE_LINES
        output = self._capture_quiet_dnf(all_lines)
        self.assertIn("fetching CentOS Stream 9 - BaseOS", output)
        self.assertNotIn("Complete!", output)

    def test_lowercase_repo_and_iec_units_surface(self):
        output = self._capture_quiet_dnf(
            ["copr:someone/project    1.4 MiB/s |  6.3 MiB  00:04"]
        )
        self.assertIn("fetching copr:someone/project", output)

    def test_non_dnf_quiet_uses_subprocess_run_not_popen(self):
        """Non-dnf commands in quiet mode must not go through the Popen path."""
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[], quiet=True)
        mock_result = unittest.mock.MagicMock()
        mock_result.returncode = 0
        with unittest.mock.patch("subprocess.run", return_value=mock_result) as mock_run, \
             unittest.mock.patch("subprocess.Popen") as mock_popen:
            d.run_cmd(["systemctl", "enable", "httpd"])
        mock_run.assert_called_once()
        mock_popen.assert_not_called()

    def test_check_false_nonzero_exit_warns(self):
        output = self._capture_quiet_dnf([], returncode=1, check=False)
        self.assertIn("exited 1", output)

    def test_nonmatching_output_surfaces_on_failure(self):
        output = self._capture_quiet_dnf(
            ["Curl error (28): Timeout was reached for repo 'appstream'"],
            returncode=1,
            check=False,
        )
        self.assertIn("Timeout was reached", output)

    def test_check_true_nonzero_exit_raises(self):
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[], quiet=True)
        proc = self._mock_popen([], returncode=1)
        with unittest.mock.patch("subprocess.Popen", return_value=proc):
            with self.assertRaises(subprocess.CalledProcessError):
                d.run_cmd(["dnf", "install", "-y", "no-such-pkg"], check=True)


class TestUndoRpmBulkRemoveFallback(DriftifyTestCase):
    def _run_undo_rpm(self, *, bulk_stdout="", bulk_stderr=""):
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
        bulk_result = subprocess.CompletedProcess(
            ["dnf", "remove", "-y", "pkg-a", "pkg-b"],
            1,
            stdout=bulk_stdout,
            stderr=bulk_stderr,
        )
        calls = []

        def fake_run_cmd(cmd, check=True, capture=False):
            calls.append((cmd, check, capture))
            if cmd[:3] == ["dnf", "remove", "-y"] and len(cmd) > 4:
                return bulk_result
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                with unittest.mock.patch.object(driftify, "PROFILES", ["minimal"]), \
                     unittest.mock.patch.dict(driftify.BASE_PACKAGES, {"minimal": ["pkg-a", "pkg-b"]}, clear=True), \
                     unittest.mock.patch.dict(driftify.EPEL_PACKAGES, {"minimal": []}, clear=True), \
                     unittest.mock.patch.dict(driftify.RPMFUSION_PACKAGES, {"minimal": []}, clear=True), \
                     unittest.mock.patch.object(d, "run_cmd", side_effect=fake_run_cmd):
                    d.undo_rpm()
        finally:
            self._suppress.__enter__()
        return buf.getvalue(), calls

    def test_generic_bulk_remove_failure_uses_generic_message(self):
        output, calls = self._run_undo_rpm(bulk_stderr="failed to download metadata")

        self.assertIn("Bulk remove failed; falling back to one-by-one removal...", output)
        self.assertNotIn("protected-package conflict", output)
        self.assertIn((["dnf", "remove", "-y", "pkg-a"], False, False), calls)
        self.assertIn((["dnf", "remove", "-y", "pkg-b"], False, False), calls)

    def test_protected_package_failure_mentions_protected_packages(self):
        output, _ = self._run_undo_rpm(
            bulk_stderr="Error: The operation would result in removing the following protected packages: setup"
        )

        self.assertIn(
            "Bulk remove failed (protected-package conflict); falling back to one-by-one removal...",
            output,
        )

    def test_non_quiet_bulk_remove_keeps_live_output(self):
        _, calls = self._run_undo_rpm()
        self.assertIn(
            (["dnf", "remove", "-y", "pkg-a", "pkg-b"], False, False),
            calls,
        )


class TestConfirmation(DriftifyTestCase):
    def _make_drifter(self, yes=False, dry_run=False):
        return driftify.Driftify("standard", dry_run=dry_run,
                                 skip_sections=[], yes=yes)

    def test_confirm_skipped_when_yes(self):
        d = self._make_drifter(yes=True)
        with unittest.mock.patch("builtins.input",
                                 side_effect=AssertionError("input called")):
            d._confirm()

    def test_confirm_skipped_when_dry_run(self):
        d = self._make_drifter(dry_run=True)
        with unittest.mock.patch("builtins.input",
                                 side_effect=AssertionError("input called")):
            d._confirm()

    def test_confirm_y_proceeds(self):
        d = self._make_drifter()
        with unittest.mock.patch("builtins.input", return_value="y"), \
             unittest.mock.patch("builtins.print"):
            d._confirm()

    def test_confirm_n_exits(self):
        d = self._make_drifter()
        with unittest.mock.patch("builtins.input", return_value="n"), \
             unittest.mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as cm:
                d._confirm()
        self.assertEqual(cm.exception.code, 0)

    def test_confirm_empty_exits(self):
        d = self._make_drifter()
        with unittest.mock.patch("builtins.input", return_value=""), \
             unittest.mock.patch("builtins.print"):
            with self.assertRaises(SystemExit):
                d._confirm()

    def test_confirm_eof_exits(self):
        d = self._make_drifter()
        with unittest.mock.patch("builtins.input", side_effect=EOFError), \
             unittest.mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as cm:
                d._confirm()
        self.assertEqual(cm.exception.code, 0)

    def test_run_description_minimal(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        lines = d._run_description()
        self.assertTrue(any("Install" in l for l in lines))
        self.assertTrue(any("httpd" in l for l in lines))
        self.assertFalse(any("sshd" in l for l in lines))
        self.assertFalse(any("NM profile" in l for l in lines))

    def test_run_description_standard(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        lines = d._run_description()
        self.assertTrue(any("sshd" in l for l in lines))
        self.assertTrue(any("NM profile" in l for l in lines))
        self.assertTrue(any("GitHub token" in l for l in lines))

    def test_run_description_respects_skips(self):
        d = driftify.Driftify("standard", dry_run=True,
                              skip_sections=["rpm", "network"])
        lines = d._run_description()
        self.assertFalse(any("Install" in l for l in lines))
        # "Add firewall rules" is the network-section-specific phrase; the
        # config section may still mention "firewall" for the sshd port change.
        self.assertFalse(any("Add firewall rules" in l for l in lines))
        self.assertTrue(any("httpd" in l for l in lines))

    def test_yes_flag_parsed(self):
        p = driftify.build_parser()
        args = p.parse_args(["-y"])
        self.assertTrue(args.yes)
        args = p.parse_args(["--yes"])
        self.assertTrue(args.yes)
        args = p.parse_args([])
        self.assertFalse(args.yes)

    def test_run_inspectah_flag_parsed(self):
        p = driftify.build_parser()
        args = p.parse_args(["--run-inspectah"])
        self.assertTrue(args.run_inspectah)
        self.assertEqual(args.inspectah_output, "./inspectah-output")
        args = p.parse_args(["--run-inspectah", "--inspectah-output", "/tmp/out"])
        self.assertEqual(args.inspectah_output, "/tmp/out")
        args = p.parse_args([])
        self.assertFalse(args.run_inspectah)

    def test_launch_inspectah_dry_run(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[],
                              run_inspectah=True, inspectah_output="/tmp/test-out")
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._launch_inspectah()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("run-inspectah.sh", output)
        self.assertIn("/tmp/test-out", output)

    def test_quiet_flag_parsed(self):
        p = driftify.build_parser()
        args = p.parse_args(["-q"])
        self.assertTrue(args.quiet)
        args = p.parse_args(["--quiet"])
        self.assertTrue(args.quiet)
        args = p.parse_args([])
        self.assertFalse(args.quiet)

    def test_quiet_suppresses_running_lines(self):
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[],
                              quiet=True)
        import unittest.mock as _mock
        mock_result = _mock.MagicMock()
        mock_result.returncode = 0
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with _mock.patch("subprocess.run", return_value=mock_result):
                d.run_cmd(["echo", "hello"])
        self._suppress.__enter__()
        self.assertNotIn("Running:", buf.getvalue())

    def test_quiet_suppresses_wrote_lines(self):
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False,
                                  skip_sections=[], quiet=True)
            d.stamp.start(d.profile, d.os_id, d.os_major)
            f = Path(td) / "test.txt"
            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                d._write_managed_text(str(f), "content\n")
            self._suppress.__enter__()
            self.assertTrue(f.exists())
            self.assertNotIn("Wrote", buf.getvalue())

    def test_non_quiet_shows_running_and_wrote(self):
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False,
                                  skip_sections=[], quiet=False)
            d.stamp.start(d.profile, d.os_id, d.os_major)
            import unittest.mock as _mock
            mock_result = _mock.MagicMock()
            mock_result.returncode = 0
            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                with _mock.patch("subprocess.run", return_value=mock_result):
                    d.run_cmd(["echo", "hello"])
                f = Path(td) / "test.txt"
                d._write_managed_text(str(f), "hello\n")
            self._suppress.__enter__()
            output = buf.getvalue()
            self.assertIn("Running:", output)
            self.assertIn("Wrote", output)


class TestRhelEpelPath(DriftifyTestCase):
    """Verify the RHEL/CentOS path still works correctly after the Fedora refactor."""

    def test_drift_rpm_uses_epel_not_rpmfusion(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_rpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("Enabling EPEL", output)
        self.assertIn("Installing EPEL packages", output)
        self.assertNotIn("RPM Fusion", output)
        self.assertNotIn("rpmfusion", output)


class TestSummary(DriftifyTestCase):


    def test_summary_rpm_mentions_orphaned_config(self):
        """RPM summary line mentions orphaned config for standard+."""
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d._t0 = __import__("time").monotonic()

        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._print_summary()
        self._suppress.__enter__()
        self.assertIn("orphaned config", buf.getvalue())


class TestServices(DriftifyTestCase):
    def test_services_standard_dry_run_creates_httpd_dropin(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with unittest.mock.patch.object(driftify.Path, "exists", return_value=False):
                d.drift_services()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("httpd.service.d/override.conf", output)
        self.assertNotIn("nginx.service.d/override.conf", output)

    def test_services_kitchen_sink_dry_run_creates_both_dropins(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with unittest.mock.patch.object(driftify.Path, "exists", return_value=False):
                d.drift_services()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("httpd.service.d/override.conf", output)
        self.assertIn("nginx.service.d/override.conf", output)

    def test_services_minimal_dry_run_no_dropins(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with unittest.mock.patch.object(driftify.Path, "exists", return_value=False):
                d.drift_services()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertNotIn("override.conf", output)

    def test_services_dropin_content(self):
        """Verify the drop-in files contain the expected INI directives."""
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("kitchen-sink", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            files_written = {}
            mask_path = Path(td) / "etc" / "systemd" / "system" / "kdump.service"
            mask_path.parent.mkdir(parents=True)

            def patched_write(path_str, content, mode=0o644):
                files_written[path_str] = content

            def fake_path(path_str):
                if path_str == "/etc/systemd/system/kdump.service":
                    return mask_path
                return Path(path_str)

            d._write_managed_text = patched_write
            d._ensure_dir = lambda p: None
            d.run_cmd = lambda *a, **k: None
            # drift_services uses subprocess.run directly for systemctl unit checks
            mock_subp = unittest.mock.MagicMock()
            mock_subp.returncode = 1  # unit not found → skip disable/mask
            with unittest.mock.patch.object(driftify, "Path", side_effect=fake_path), \
                 unittest.mock.patch("subprocess.run", return_value=mock_subp):
                d.drift_services()

        httpd_dropin = next(
            (v for k, v in files_written.items() if "httpd.service.d" in k), ""
        )
        self.assertIn("TimeoutStartSec=600", httpd_dropin)
        self.assertIn("LimitNOFILE=65535", httpd_dropin)

        nginx_dropin = next(
            (v for k, v in files_written.items() if "nginx.service.d" in k), ""
        )
        self.assertIn("LimitNOFILE=131072", nginx_dropin)
        self.assertIn("ExecStartPost=/usr/local/bin/notify-deploy.sh", nginx_dropin)

    def test_summary_services_counts_dropins(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d._t0 = __import__("time").monotonic()
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._print_summary()
        self._suppress.__enter__()
        self.assertIn("1 drop-in override(s)", buf.getvalue())

    def test_summary_services_kitchen_sink_counts_two_dropins(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        d._t0 = __import__("time").monotonic()
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._print_summary()
        self._suppress.__enter__()
        self.assertIn("2 drop-in override(s)", buf.getvalue())

    def test_undo_services_removes_kdump_mask_before_enabling(self):
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
        events = []

        with tempfile.TemporaryDirectory() as td:
            mask_path = Path(td) / "etc" / "systemd" / "system" / "kdump.service"
            mask_path.parent.mkdir(parents=True)
            mask_path.symlink_to("/dev/null")

            def fake_path(path_str):
                if path_str == "/etc/systemd/system/kdump.service":
                    return mask_path
                return Path(path_str)

            def fake_remove(path_str):
                events.append(("remove", path_str))
                if path_str == str(mask_path):
                    Path(path_str).unlink(missing_ok=True)

            def fake_run(cmd, check=False, capture=False):
                events.append(("run", cmd))
                return unittest.mock.MagicMock(returncode=0)

            d._remove_path = fake_remove
            d.run_cmd = fake_run

            with unittest.mock.patch.object(driftify, "Path", side_effect=fake_path):
                d.undo_services()

        self.assertLess(
            events.index(("remove", str(mask_path))),
            events.index(("run", ["systemctl", "enable", "kdump"])),
        )


class TestMissingCoverageFixtures(RedirectedFixtureTestCase):
    def test_services_standard_creates_backup_timer_files_and_undo_removes_them(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path = self._build_redirected_drifter(td, "standard")
            mask_path = map_path("/etc/systemd/system/kdump.service")

            def fake_systemctl_cat(cmd, **kwargs):
                name = cmd[-1]
                return unittest.mock.MagicMock(
                    returncode=0 if name == "kdump" else 1
                )

            def fake_path(path_str):
                if path_str == "/etc/systemd/system/kdump.service":
                    return mask_path
                return Path(path_str)

            with unittest.mock.patch.object(driftify, "Path", side_effect=fake_path), \
                 unittest.mock.patch("subprocess.run", side_effect=fake_systemctl_cat):
                d.run_cmd = lambda *a, **k: None
                d.drift_services()

            timer_path = map_path("/etc/systemd/system/driftify-backup.timer")
            service_path = map_path("/etc/systemd/system/driftify-backup.service")
            self.assertTrue(timer_path.exists())
            self.assertTrue(service_path.exists())
            self.assertEqual(
                timer_path.read_text(),
                "[Unit]\n"
                "Description=Daily backup job\n\n"
                "[Timer]\n"
                "OnCalendar=*-*-* 03:00:00\n"
                "Persistent=true\n\n"
                "[Install]\n"
                "WantedBy=timers.target\n",
            )
            self.assertEqual(
                service_path.read_text(),
                "[Unit]\n"
                "Description=Run backup script\n\n"
                "[Service]\n"
                "Type=oneshot\n"
                "ExecStart=/usr/local/bin/backup.sh\n",
            )

            d.undo_services()
            self.assertFalse(timer_path.exists())
            self.assertFalse(service_path.exists())

    def test_services_minimal_masks_kdump_and_undo_removes_dev_null_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path = self._build_redirected_drifter(td, "minimal")
            mask_path = map_path("/etc/systemd/system/kdump.service")

            def fake_path(path_str):
                if path_str == "/etc/systemd/system/kdump.service":
                    return mask_path
                return Path(path_str)

            with unittest.mock.patch.object(driftify, "Path", side_effect=fake_path), \
                 unittest.mock.patch(
                     "subprocess.run",
                     return_value=unittest.mock.MagicMock(returncode=0),
                 ):
                d.run_cmd = lambda *a, **k: None
                d.drift_services()

            self.assertTrue(mask_path.is_symlink())
            self.assertEqual(os.readlink(mask_path), "/dev/null")

            with unittest.mock.patch.object(driftify, "Path", side_effect=fake_path):
                d.undo_services()
            self.assertFalse(mask_path.exists())

    def test_services_minimal_does_not_create_backup_timer_files(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path = self._build_redirected_drifter(td, "minimal")
            mask_path = map_path("/etc/systemd/system/kdump.service")

            def fake_path(path_str):
                if path_str == "/etc/systemd/system/kdump.service":
                    return mask_path
                return Path(path_str)

            with unittest.mock.patch.object(driftify, "Path", side_effect=fake_path), \
                 unittest.mock.patch(
                     "subprocess.run",
                     return_value=unittest.mock.MagicMock(returncode=0),
                 ):
                d.run_cmd = lambda *a, **k: None
                d.drift_services()

            self.assertFalse(map_path("/etc/systemd/system/driftify-backup.timer").exists())
            self.assertFalse(map_path("/etc/systemd/system/driftify-backup.service").exists())

    def test_storage_kitchen_sink_creates_lvm_and_multipath_and_undo_cleans_up(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path = self._build_redirected_drifter(td, "kitchen-sink")
            d.run_cmd = lambda *a, **k: None

            d.drift_storage()

            multipath_path = map_path("/etc/multipath.conf")
            profile_path = map_path("/etc/lvm/profile/driftify-thin.profile")
            self.assertTrue(multipath_path.exists())
            self.assertIn("BEGIN DRIFTIFY multipath-config", multipath_path.read_text())
            self.assertIn("user_friendly_names yes", multipath_path.read_text())
            self.assertEqual(
                profile_path.read_text(),
                "allocation {\n"
                "    thin_pool_autoextend_threshold = 70\n"
                "    thin_pool_autoextend_percent = 20\n"
                "}\n",
            )

            d.undo_storage()
            self.assertFalse(profile_path.exists())
            if multipath_path.exists():
                self.assertNotIn("BEGIN DRIFTIFY multipath-config", multipath_path.read_text())

    def test_storage_standard_does_not_create_lvm_or_multipath_fixtures(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path = self._build_redirected_drifter(td, "standard")
            d.run_cmd = lambda *a, **k: None

            d.drift_storage()

            self.assertFalse(map_path("/etc/multipath.conf").exists())
            self.assertFalse(map_path("/etc/lvm/profile/driftify-thin.profile").exists())

    def test_selinux_standard_creates_file_watch_rules_and_undo_removes_them(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path = self._build_redirected_drifter(td, "standard")
            d.run_cmd = lambda *a, **k: None
            d._add_selinux_fcontext = lambda: None

            d.drift_selinux()

            rules_path = map_path("/etc/audit/rules.d/driftify-file-watch.rules")
            self.assertTrue(rules_path.exists())
            self.assertEqual(
                rules_path.read_text(),
                "-w /etc/shadow -p wa -k shadow-changes\n"
                "-w /etc/passwd -p wa -k passwd-changes\n"
                "-a always,exit -F arch=b64 -S execve -F euid=0 -k root-commands\n",
            )

            d.undo_selinux()
            self.assertFalse(rules_path.exists())

    def test_selinux_minimal_does_not_create_file_watch_rules(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path = self._build_redirected_drifter(td, "minimal")
            d.run_cmd = lambda *a, **k: None
            d._add_selinux_fcontext = lambda: None

            d.drift_selinux()

            self.assertFalse(map_path("/etc/audit/rules.d/driftify-file-watch.rules").exists())


class TestScheduled(DriftifyTestCase):
    def test_scheduled_dry_run_creates_cron_files(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_scheduled()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("/etc/cron.d/backup-daily", output)
        self.assertIn("/etc/cron.daily/cleanup.sh", output)

    def test_scheduled_standard_dry_run_creates_timer_and_at(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_scheduled()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("myapp-report.timer", output)
        self.assertIn("myapp-report.service", output)
        self.assertIn("/var/spool/cron/appuser", output)
        self.assertIn("at now + 1 hour", output)

    def test_scheduled_kitchen_sink_has_complex_cron(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_scheduled()
        self._suppress.__enter__()
        self.assertIn("/etc/cron.d/complex-job", buf.getvalue())




class TestUsers(DriftifyTestCase):
    def test_users_dry_run_creates_user_and_group(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_users()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("appuser", output)
        self.assertIn("appgroup", output)

    def test_users_standard_dry_run_creates_dbuser_and_sudoers(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_users()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("dbuser", output)
        self.assertIn("developers", output)
        self.assertIn("/etc/sudoers.d/appusers", output)
        self.assertIn("/home/appuser/.ssh/authorized_keys", output)



class TestNonRpm(DriftifyTestCase):
    def _mock_nonrpm(self, d):
        """Patch out subprocesses and downloads for nonrpm dry-run tests."""
        d.run_cmd = lambda *a, **k: None
        d._ensure_dir = lambda p: None
        d._download_go_probe = lambda: None
        d._create_npm_project = lambda: None

    def test_nonrpm_minimal_dry_run_creates_venv(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_nonrpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("/opt/myapp/venv", output)
        self.assertIn("driftify-probe", output)

    def test_nonrpm_standard_dry_run_creates_npm_git_deploy(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_nonrpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("/opt/tools/some-tool", output)
        self.assertIn("/usr/local/bin/deploy.sh", output)

    def test_nonrpm_kitchen_sink_dry_run_creates_mystery_binary(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_nonrpm()
        self._suppress.__enter__()
        self.assertIn("mystery-tool", buf.getvalue())

    def test_nonrpm_skip_flag_works(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=["nonrpm"])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_nonrpm()
        self._suppress.__enter__()
        self.assertNotIn("/opt/myapp/venv", buf.getvalue())

    def test_deploy_sh_content(self):
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            files_written = {}

            def patched_write(path_str, content, mode=0o644):
                files_written[Path(path_str).name] = content

            d._write_managed_text = patched_write
            d._ensure_dir = lambda p: None
            d.run_cmd = lambda *a, **k: None
            d._download_go_probe = lambda: None
            d._create_npm_project = lambda: None

            with unittest.mock.patch("shutil.copy2"), \
                 unittest.mock.patch("os.chmod"):
                d.drift_nonrpm()

            deploy = files_written.get("deploy.sh", "")
            self.assertIn("#!/bin/sh", deploy)
            self.assertIn("APP_DIR=/opt/myapp", deploy)
            self.assertIn("systemctl start myapp", deploy)

    def test_npm_package_json_content(self):
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            files_written = {}

            def patched_write(path_str, content, mode=0o644):
                files_written[Path(path_str).name] = content

            d._write_managed_text = patched_write
            d._ensure_dir = lambda p: None
            d.run_cmd = lambda *a, **k: None

            d._create_npm_project()

            pkg = files_written.get("package.json", "")
            self.assertIn("express", pkg)
            self.assertIn("lodash", pkg)


class TestContainers(DriftifyTestCase):
    def test_containers_minimal_drops_webapp_quadlet(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_containers()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("/etc/containers/systemd/webapp.container", output)
        # Standard-only files must NOT appear
        self.assertNotIn("redis.container", output)
        self.assertNotIn("docker-compose.yml", output)

    def test_containers_standard_adds_redis_network_compose(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_containers()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("redis.container", output)
        self.assertIn("myapp.network", output)
        self.assertIn("/opt/myapp/docker-compose.yml", output)

    def test_containers_standard_file_content(self):
        """Standard container files contain the expected image refs and secrets."""
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            # Redirect all writes to temp dir
            files_written = {}

            def patched_write(path_str, content, mode=0o644):
                dest = Path(td) / Path(path_str).name
                dest.write_text(content)
                files_written[Path(path_str).name] = content

            d._write_managed_text = patched_write
            d._ensure_dir = lambda p: None
            d.run_cmd = lambda *a, **k: None
            d.drift_containers()

            self.assertIn("registry.example.com/myorg/webapp:v2.1.3",
                          files_written.get("webapp.container", ""))
            self.assertIn("docker.io/library/redis:7-alpine",
                          files_written.get("redis.container", ""))
            self.assertIn("DRIFTIFY_FAKE_r3d1s_p4ss",
                          files_written.get("redis.container", ""))
            self.assertIn("DRIFTIFY_FAKE_pgpass123",
                          files_written.get("docker-compose.yml", ""))

    def test_containers_webapp_has_required_quadlet_fields(self):
        """webapp.container must include all fields inspectah parses."""
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("minimal", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)

            container_dir = Path(td) / "etc" / "containers" / "systemd"
            container_dir.mkdir(parents=True)
            webapp_path = container_dir / "webapp.container"

            # Patch the write to use our temp path
            original_write = d._write_managed_text

            def patched_write(path_str, content, mode=0o644):
                if "webapp.container" in path_str:
                    original_write(str(webapp_path), content, mode)
                else:
                    original_write(path_str, content, mode)

            d._write_managed_text = patched_write
            d._ensure_dir = lambda p: None  # don't try to create real dirs
            d.run_cmd = lambda *a, **k: None  # suppress subprocess

            d.drift_containers()

            self.assertTrue(webapp_path.exists())
            content = webapp_path.read_text()
            for field in ("PublishPort=", "Environment=", "Volume=",
                          "Network=myapp.network", "AutoUpdate=registry"):
                self.assertIn(field, content)

    def test_containers_kitchen_sink_drops_user_quadlet(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_containers()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("dev-tools.container", output)

    def test_containers_kitchen_sink_user_quadlet_content(self):
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("kitchen-sink", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            files_written = {}

            def patched_write(path_str, content, mode=0o644):
                files_written[Path(path_str).name] = content

            d._write_managed_text = patched_write
            d._ensure_dir = lambda p: None
            d.run_cmd = lambda *a, **k: None
            d.drift_containers()

            dev = files_written.get("dev-tools.container", "")
            self.assertIn("quay.io/toolbox/toolbox:latest", dev)
            self.assertIn("%h/projects", dev)

    def test_containers_skip_flag_works(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=["containers"])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_containers()
        self._suppress.__enter__()
        self.assertNotIn("webapp.container", buf.getvalue())


class TestKernel(DriftifyTestCase):
    def test_kernel_minimal_dry_run_creates_sysctl(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_kernel()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("/etc/sysctl.d/99-driftify.conf", output)
        self.assertIn("sysctl -p", output)

    def test_kernel_standard_dry_run_creates_module_and_dracut(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_kernel()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("/etc/modules-load.d/driftify.conf", output)
        self.assertIn("/etc/dracut.conf.d/driftify.conf", output)
        self.assertIn("br_netfilter", output)

    def test_kernel_kitchen_sink_modifies_grub(self):
        with tempfile.TemporaryDirectory() as td:
            grub = Path(td) / "grub"
            grub.write_text('GRUB_CMDLINE_LINUX="crashkernel=auto"\n')

            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("kitchen-sink", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)

            with unittest.mock.patch.object(driftify, "GRUB_DEFAULT_PATH", str(grub)):
                # First call: args should be appended
                d._append_kernel_cmdline_arg("panic=60 audit=1")
                content = grub.read_text()
                self.assertIn("panic=60", content)
                self.assertIn("audit=1", content)

                # Second call: args must NOT be duplicated
                d._append_kernel_cmdline_arg("panic=60 audit=1")
                content2 = grub.read_text()
                self.assertEqual(content2.count("panic=60"), 1)
                self.assertEqual(content2.count("audit=1"), 1)


class TestRunOrdering(DriftifyTestCase):
    """Verify that run() applies drift sections in the required order."""

    def _section_order(self, profile: str) -> list:
        """Return the list of section names passed to _next_step during run()."""
        d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
        order: list = []
        d._next_step = lambda section: order.append(section)
        d._confirm = lambda: None
        d.run()
        return order

    def test_users_before_scheduled_containers_secrets(self):
        for profile in ("standard", "kitchen-sink"):
            with self.subTest(profile=profile):
                order = self._section_order(profile)
                users_idx = order.index("users")
                for dependent in ("scheduled", "containers", "secrets"):
                    if dependent in order:
                        self.assertLess(
                            users_idx, order.index(dependent),
                            msg=f"'{dependent}' must come after 'users' (profile={profile})",
                        )


class TestSELinux(DriftifyTestCase):
    def test_selinux_minimal_dry_run_sets_boolean(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_selinux()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("httpd_can_network_connect", output)
        self.assertNotIn("httpd_can_network_relay", output)

    def test_selinux_standard_dry_run_sets_two_booleans_and_rules(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_selinux()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("httpd_can_network_connect", output)
        self.assertIn("httpd_can_network_relay", output)
        self.assertIn("/etc/audit/rules.d/driftify.rules", output)


class TestFedoraSupport(DriftifyTestCase):
    """Verify Fedora-specific behavior: RPM Fusion, no EPEL, package filtering."""

    def setUp(self):
        super().setUp()
        driftify.detect_os = lambda: ("fedora", 41)

    def test_driftify_accepts_fedora(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self.assertEqual(d.os_id, "fedora")
        self.assertEqual(d.os_major, 41)

    def test_drift_rpm_uses_rpmfusion_not_epel(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_rpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("RPM Fusion", output)
        self.assertIn("rpmfusion", output)
        self.assertNotIn("Enabling EPEL", output)
        self.assertNotIn("Installing EPEL packages", output)

    def test_drift_rpm_rpmfusion_url_contains_major_version(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_rpm()
        self._suppress.__enter__()
        expected_url = driftify.RPMFUSION_URL.format(major=41)
        self.assertIn(expected_url, buf.getvalue())

    def test_drift_rpm_epel_packages_folded_into_base(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_rpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        for pkg in driftify.EPEL_PACKAGES["minimal"]:
            self.assertIn(pkg, output)

    def test_drift_rpm_installs_rpmfusion_packages(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_rpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("Installing RPM Fusion packages", output)
        for pkg in driftify.RPMFUSION_PACKAGES["minimal"]:
            self.assertIn(pkg, output)
        for pkg in driftify.RPMFUSION_PACKAGES["standard"]:
            self.assertIn(pkg, output)

    def test_rhel_only_packages_filtered_on_fedora(self):
        """Inject a RHEL-only package into BASE_PACKAGES and verify it's filtered."""
        original = driftify.BASE_PACKAGES["minimal"]
        try:
            driftify.BASE_PACKAGES["minimal"] = original + ["insights-client"]
            d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                d.drift_rpm()
            self._suppress.__enter__()
            output = buf.getvalue()
            self.assertNotIn("insights-client", output)
            self.assertIn("httpd", output)
        finally:
            driftify.BASE_PACKAGES["minimal"] = original

    def test_run_description_mentions_rpmfusion(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        lines = d._run_description()
        rpm_lines = [l for l in lines if "Install" in l]
        self.assertTrue(any("RPM Fusion" in l for l in rpm_lines))
        self.assertFalse(any("EPEL" in l for l in rpm_lines))

    def test_summary_mentions_rpmfusion(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d._t0 = __import__("time").monotonic()
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._print_summary()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("RPM Fusion", output)
        self.assertNotIn("EPEL", output)

    def test_summary_package_count_includes_rpmfusion(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d._t0 = __import__("time").monotonic()
        _base, _extra, expected_total = d._rpm_package_counts()

        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._print_summary()
        self._suppress.__enter__()
        self.assertIn(f"{expected_total} packages requested", buf.getvalue())

    def test_drift_rpm_kitchen_sink_installs_all_rpmfusion(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_rpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        for level in driftify.PROFILES:
            for pkg in driftify.RPMFUSION_PACKAGES.get(level, []):
                self.assertIn(pkg, output)

    def test_drift_rpm_standard_folds_all_epel_into_base(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_rpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        for level in ("minimal", "standard"):
            for pkg in driftify.EPEL_PACKAGES.get(level, []):
                self.assertIn(pkg, output)


class TestPrintSummary(DriftifyTestCase):
    """Verify _print_summary shows correct counts regardless of stamp contents."""

    def test_summary_nonzero_counts_on_real_run(self):
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            d.stamp.finish()
            d._t0 = driftify.time.monotonic()

            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                d._print_summary()
            self._suppress.__enter__()
            output = buf.getvalue()

        # Services should show "2 enabled", not "0 enabled"
        self.assertIn("2 enabled", output)
        self.assertNotIn("0 enabled", output)
        # Standard profile masks kdump.service and bluetooth.
        self.assertIn("2 masked", output)
        # Users section should show users and groups
        self.assertIn("2 user(s)", output)
        self.assertIn("2 group(s)", output)
        # Scheduled section should list cron files
        self.assertIn("2 cron files", output)

