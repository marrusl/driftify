import io
import json
import os
import re
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
        original_ensure_dir = d._ensure_dir

        d._write_managed_text = (
            lambda path_str, content, mode=0o644:
            original_write(str(map_path(path_str)), content, mode)
        )
        d._append_managed_block = (
            lambda path_str, marker, block, mode=0o644, create_if_missing=True,
            inside_block=None:
            original_append(
                str(map_path(path_str)),
                marker,
                block,
                mode=mode,
                create_if_missing=create_if_missing,
                inside_block=inside_block,
            )
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

    def test_write_managed_text_creates_a_new_file_at_its_final_mode(self):
        # With chmod disabled, only the mode given at creation is left, so a
        # file created under the umask and tightened afterwards shows here.
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            file_path = Path(td) / "secret.conf"
            old_umask = os.umask(0o022)
            try:
                with unittest.mock.patch("os.chmod"):
                    d._write_managed_text(str(file_path), "key\n", mode=0o600)
            finally:
                os.umask(old_umask)
            self.assertEqual(file_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(file_path.read_text(), "key\n")

    def test_write_managed_text_update_ends_at_the_requested_mode(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            file_path = Path(td) / "secret.conf"
            file_path.write_text("old\n")
            file_path.chmod(0o644)
            d._write_managed_text(str(file_path), "new\n", mode=0o600)
            self.assertEqual(file_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(file_path.read_text(), "new\n")

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
        # "Add firewall rules" is the network-section-specific phrase.
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
        self.assertIn("inspectah", output)
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

class TestMissingCoverageFixtures(RedirectedFixtureTestCase):
    def test_services_standard_creates_backup_timer_files(self):
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

    def test_services_minimal_masks_kdump_with_dev_null_symlink(self):
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

    def test_storage_kitchen_sink_creates_lvm_and_multipath(self):
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

    def test_storage_standard_does_not_create_lvm_or_multipath_fixtures(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path = self._build_redirected_drifter(td, "standard")
            d.run_cmd = lambda *a, **k: None

            d.drift_storage()

            self.assertFalse(map_path("/etc/multipath.conf").exists())
            self.assertFalse(map_path("/etc/lvm/profile/driftify-thin.profile").exists())

    def test_selinux_standard_creates_file_watch_rules(self):
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

    def test_users_sssd_configs_are_written_at_mode_0600(self):
        # The mode goes to the write itself, not to a chmod after it.
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("kitchen-sink", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            modes = {}
            d._write_managed_text = (
                lambda path_str, content, mode=0o644:
                modes.__setitem__(path_str, mode)
            )
            d._ensure_dir = lambda p: None
            d.run_cmd = lambda *a, **k: None
            d._user_exists = lambda name: True
            d._group_exists = lambda name: True
            d.drift_users()
        self.assertEqual(modes["/etc/sssd/sssd.conf"], 0o600)
        self.assertEqual(modes["/etc/sssd/conf.d/ad-domain.conf"], 0o600)



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


class TestPythonEnvironments(DriftifyTestCase):
    """Venv fixtures that back inspectah's pip/venv detection.

    inspectah rates a venv "high confidence" only when a requirements.txt
    sits in the venv's parent directory or the venv root, so the manifest
    files are as load-bearing as the venvs themselves.
    """

    def _instrument(self, profile, freeze_stdout="", freeze_rc=0):
        """Build a drifter that records run_cmd calls and file writes."""
        d = driftify.Driftify(profile, dry_run=False, skip_sections=[])
        commands = []
        files_written = {}

        def patched_run(cmd, check=True, capture=False):
            commands.append([str(c) for c in cmd])
            if capture:
                return subprocess.CompletedProcess(
                    cmd, freeze_rc, stdout=freeze_stdout, stderr="",
                )
            return subprocess.CompletedProcess(cmd, 0)

        d.run_cmd = patched_run
        d._write_managed_text = (
            lambda path_str, content, mode=0o644:
            files_written.__setitem__(path_str, content)
        )
        d._ensure_dir = lambda p: None
        return d, commands, files_written

    def test_myapp_requirements_written_from_pip_freeze(self):
        frozen = "flask==3.0.3\ngunicorn==22.0.0\nrequests==2.32.3\n"
        d, commands, files_written = self._instrument("minimal", frozen)
        d._write_venv_requirements(
            driftify.MYAPP_DIR, driftify.MYAPP_VENV,
            driftify.MYAPP_REQUIREMENTS_FALLBACK,
        )
        self.assertEqual(files_written["/opt/myapp/requirements.txt"], frozen)
        self.assertIn(
            [f"{driftify.MYAPP_VENV}/bin/pip", "freeze", "--local"], commands,
        )

    def test_requirements_falls_back_when_pip_freeze_is_empty(self):
        d, _, files_written = self._instrument("minimal", freeze_stdout="")
        d._write_venv_requirements(
            driftify.MYAPP_DIR, driftify.MYAPP_VENV,
            driftify.MYAPP_REQUIREMENTS_FALLBACK,
        )
        self.assertEqual(
            files_written["/opt/myapp/requirements.txt"],
            driftify.MYAPP_REQUIREMENTS_FALLBACK,
        )

    def test_requirements_falls_back_when_pip_freeze_fails(self):
        d, _, files_written = self._instrument(
            "minimal", freeze_stdout="ignored", freeze_rc=1,
        )
        d._write_venv_requirements(
            driftify.LEGACY_APP_DIR, driftify.LEGACY_APP_VENV,
            driftify.LEGACY_APP_REQUIREMENTS_FALLBACK,
        )
        self.assertEqual(
            files_written["/opt/legacy-app/requirements.txt"],
            driftify.LEGACY_APP_REQUIREMENTS_FALLBACK,
        )

    def test_scan_path_venv_lives_outside_default_scan_roots(self):
        default_roots = ("/opt/", "/srv/", "/usr/local/", "/var/www/")
        self.assertFalse(
            driftify.REPORTING_VENV.startswith(default_roots),
            f"{driftify.REPORTING_VENV} is inside a default scan root, so it "
            "would be found without --scan-path",
        )
        d, commands, _ = self._instrument("minimal")
        d._create_scan_path_venv()
        self.assertIn(
            ["python3", "-m", "venv", driftify.REPORTING_VENV], commands,
        )

    def test_legacy_app_venv_uses_system_site_packages(self):
        d, commands, files_written = self._instrument("standard", "six==1.16.0\n")
        d._create_legacy_app_venv()
        self.assertIn(
            ["python3", "-m", "venv", "--system-site-packages",
             driftify.LEGACY_APP_VENV],
            commands,
        )
        # requirements.txt beside the venv is what makes this the
        # high-confidence + system-site-packages combination.
        self.assertIn("/opt/legacy-app/requirements.txt", files_written)

    def test_legacy_app_install_ignores_system_packages(self):
        d, commands, _ = self._instrument("standard", "six==1.16.0\n")
        d._create_legacy_app_venv()
        install = next(c for c in commands if "install" in c)
        self.assertIn("--ignore-installed", install)
        for pkg in driftify.LEGACY_APP_PACKAGES:
            self.assertIn(pkg, install)

    def test_nonrpm_minimal_creates_both_minimal_venvs(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        d._download_go_probe = lambda: None
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_nonrpm()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn(driftify.MYAPP_VENV, output)
        self.assertIn("/opt/myapp/requirements.txt", output)
        self.assertIn(driftify.REPORTING_VENV, output)

    def test_nonrpm_minimal_does_not_create_legacy_app_venv(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        d._download_go_probe = lambda: None
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d.drift_nonrpm()
        self._suppress.__enter__()
        self.assertNotIn(driftify.LEGACY_APP_VENV, buf.getvalue())

    def test_myapp_service_declares_state_directory(self):
        """/var/lib/myapp needs a StateDirectory= backing to be classified."""
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            files_written = {}

            d._write_managed_text = (
                lambda path_str, content, mode=0o644:
                files_written.__setitem__(path_str, content)
            )
            d._ensure_dir = lambda p: None
            d.run_cmd = lambda *a, **k: None
            d._download_go_probe = lambda: None
            d._create_npm_project = lambda: None
            d._create_npm_globals = lambda: None
            d._create_pip_c_extensions = lambda: None

            with unittest.mock.patch("os.chmod"):
                d.drift_nonrpm()

            unit = files_written["/usr/lib/systemd/system/myapp.service"]
            self.assertIn("StateDirectory=myapp\n", unit)
            self.assertIn("[Service]", unit)


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


class TestSshdConfigNoPortMove(DriftifyTestCase):
    """driftify drifts sshd_config but never moves the sshd port.

    A moved port proves nothing the other sshd directives do not, and it
    locks operators and test automation out of a host that was not reverted.
    """

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    MOVED_PORTS = ("2222", "2200")

    def _run(self, profile, method):
        d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
        d._t0 = driftify.time.monotonic()
        directives = []
        commands = []
        d._apply_directives = (
            lambda path_str, mapping: directives.append((path_str, dict(mapping)))
        )
        d.run_cmd = (
            lambda cmd, check=True, capture=False:
            commands.append([str(c) for c in cmd])
        )
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            getattr(d, method)()
        self._suppress.__enter__()
        return d, directives, commands, buf.getvalue()

    def _assert_no_port_commands(self, commands):
        for cmd in commands:
            joined = " ".join(cmd)
            self.assertNotIn("ssh_port_t", joined)
            for port in self.MOVED_PORTS:
                self.assertNotIn(f"{port}/tcp", joined)

    def test_drift_config_writes_no_port_directive(self):
        for profile in ("standard", "kitchen-sink"):
            with self.subTest(profile=profile):
                _, directives, commands, _ = self._run(profile, "drift_config")
                sshd = [m for path, m in directives if path == self.SSHD_CONFIG]
                self.assertTrue(sshd, "sshd_config should still be drifted")
                for mapping in sshd:
                    self.assertNotIn("Port", mapping)
                merged = {k: v for m in sshd for k, v in m.items()}
                self.assertEqual(merged["PermitRootLogin"], "PermitRootLogin no")
                for key in ("Ciphers", "MACs", "KexAlgorithms"):
                    self.assertNotIn(key, merged)
                self._assert_no_port_commands(commands)

    def test_plan_and_summary_do_not_mention_a_port(self):
        for profile in ("standard", "kitchen-sink"):
            with self.subTest(profile=profile):
                d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
                d._t0 = driftify.time.monotonic()
                plan = "\n".join(d._run_description())
                self._suppress.__exit__(None, None, None)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    d._print_summary()
                self._suppress.__enter__()
                for text in (plan, buf.getvalue()):
                    self.assertIn("sshd_config", text)
                    self.assertNotIn("Port", text)
                    for port in self.MOVED_PORTS:
                        self.assertNotIn(port, text)


class TestSshdPermitRootLoginDropin(DriftifyTestCase):
    """standard also writes PermitRootLogin no as an early sshd drop-in.

    The stock RHEL 9 sshd_config includes sshd_config.d/*.conf before its own
    directives and sshd keeps the first value it reads, so an installer-written
    01-permitrootlogin.conf would otherwise win over driftify's sshd_config line.
    """

    STOCK_DROPINS = ("01-permitrootlogin.conf", "50-redhat.conf")

    def _writes(self, profile):
        d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
        d._t0 = driftify.time.monotonic()
        writes = []
        d._write_managed_text = (
            lambda path_str, content, mode=0o644:
            writes.append((path_str, content, mode))
        )
        d._apply_directives = lambda path_str, mapping: None
        d._append_managed_block = lambda *a, **kw: None
        d.run_cmd = lambda cmd, check=True, capture=False: None
        self._suppress.__exit__(None, None, None)
        with redirect_stdout(io.StringIO()):
            d.drift_config()
        self._suppress.__enter__()
        return {path: (content, mode) for path, content, mode in writes}

    def test_dropin_path_sorts_before_stock_dropins(self):
        path = driftify.SSHD_DRIFTIFY_DROPIN
        self.assertTrue(path.startswith("/etc/ssh/sshd_config.d/"))
        self.assertTrue(path.endswith(".conf"))
        name = path.rsplit("/", 1)[1]
        for stock in self.STOCK_DROPINS:
            self.assertLess(name, stock)

    def test_standard_writes_dropin_with_directive_and_mode(self):
        for profile in ("standard", "kitchen-sink"):
            with self.subTest(profile=profile):
                writes = self._writes(profile)
                self.assertIn(driftify.SSHD_DRIFTIFY_DROPIN, writes)
                content, mode = writes[driftify.SSHD_DRIFTIFY_DROPIN]
                live = [l for l in content.splitlines()
                        if l.strip() and not l.lstrip().startswith("#")]
                self.assertEqual(live, ["PermitRootLogin no"])
                comments = [l for l in content.splitlines() if l.startswith("#")]
                self.assertEqual(len(comments), 1)
                self.assertIn("driftify", comments[0])
                self.assertEqual(mode, 0o600)

    def test_minimal_writes_no_dropin(self):
        self.assertNotIn(driftify.SSHD_DRIFTIFY_DROPIN, self._writes("minimal"))

    def test_plan_and_summary_name_both_files(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d._t0 = driftify.time.monotonic()
        plan = "\n".join(d._run_description())
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._print_summary()
        self._suppress.__enter__()
        for text in (plan, buf.getvalue()):
            with self.subTest(text=text[:40]):
                self.assertIn("sshd_config", text)
                self.assertIn(driftify.SSHD_DRIFTIFY_DROPIN, text)
                self.assertIn("PermitRootLogin", text)
                self.assertIn("restart", text)


class TestNginxPortLabel(DriftifyTestCase):
    """standard moves nginx to a custom port with an http_port_t label.

    This is driftify's SELinux port label drift: inspectah has to detect the
    custom label and render a `semanage port` line in the Containerfile.
    """

    NGINX_CONF = "/etc/nginx/nginx.conf"
    BLOCK = "nginx-server-block"
    LABEL_ADD = ["semanage", "port", "-a", "-t", "http_port_t", "-p", "tcp", "8081"]

    def _run(self, profile, method, semanage="/usr/sbin/semanage"):
        d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
        d._t0 = driftify.time.monotonic()
        blocks = []
        commands = []
        d._append_managed_block = (
            lambda path_str, marker, block, **kw:
            blocks.append((path_str, marker, block))
        )
        d.run_cmd = (
            lambda cmd, check=True, capture=False:
            commands.append([str(c) for c in cmd])
        )
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf), \
             unittest.mock.patch("shutil.which", return_value=semanage):
            getattr(d, method)()
        self._suppress.__enter__()
        return blocks, commands, buf.getvalue()

    def _nginx_block(self, blocks):
        found = [b for p, m, b in blocks if p == self.NGINX_CONF and m == self.BLOCK]
        self.assertEqual(len(found), 1)
        return found[0]

    def test_drift_port_constant(self):
        self.assertEqual(driftify.NGINX_DRIFT_PORT, 8081)

    def test_standard_nginx_listens_on_8081_with_label(self):
        for profile in ("standard", "kitchen-sink"):
            with self.subTest(profile=profile):
                blocks, commands, _ = self._run(profile, "drift_config")
                block = self._nginx_block(blocks)
                self.assertIn("listen 8081 default_server;", block)
                self.assertNotIn("listen 8080", block)
                self.assertIn(self.LABEL_ADD, commands)

    def test_minimal_nginx_uses_stock_http_port_t_port(self):
        # 81 is in the stock http_port_t set, so minimal needs no label, and
        # httpd's drifted Listen 8080 keeps 8080 to itself.
        self.assertEqual(driftify.NGINX_MINIMAL_PORT, 81)
        blocks, commands, _ = self._run("minimal", "drift_config")
        block = self._nginx_block(blocks)
        self.assertIn("listen 81 default_server;", block)
        self.assertNotIn("listen 8080", block)
        self.assertFalse(any("http_port_t" in c for c in commands))

    def test_label_skipped_with_warning_without_semanage(self):
        _, commands, out = self._run("standard", "drift_config", semanage=None)
        self.assertFalse(any("http_port_t" in c for c in commands))
        self.assertIn("semanage not found", out)

    def test_standard_opens_8081_in_firewalld(self):
        for profile in ("standard", "kitchen-sink"):
            with self.subTest(profile=profile):
                _, commands, _ = self._run(profile, "drift_network")
                self.assertIn(
                    ["firewall-cmd", "--permanent", "--add-port=8081/tcp"], commands)
        _, commands, _ = self._run("minimal", "drift_network")
        self.assertNotIn(
            ["firewall-cmd", "--permanent", "--add-port=8081/tcp"], commands)

    def test_plan_and_summary_mention_nginx_port(self):
        for profile in ("standard", "kitchen-sink"):
            with self.subTest(profile=profile):
                d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
                d._t0 = driftify.time.monotonic()
                plan = "\n".join(d._run_description())
                self.assertIn("nginx listen→8081", plan)
                self.assertIn("http_port_t", plan)
                self.assertIn("8081/tcp", plan)
                self._suppress.__exit__(None, None, None)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    d._print_summary()
                self._suppress.__enter__()
                self.assertIn("nginx on 8081 (http_port_t label)", buf.getvalue())
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        self.assertNotIn("8081", "\n".join(d._run_description()))


# Excerpt of the stock RHEL 9 nginx.conf layout: the http block is last, its
# default server listens on 80, and a commented TLS server carries braces of
# its own after that server.
STOCK_NGINX_CONF = """\
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" ';
    access_log  /var/log/nginx/access.log  main;
    include             /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;

    server {
        listen       80;
        listen       [::]:80;
        server_name  _;
        root         /usr/share/nginx/html;

        error_page 404 /404.html;
        location = /404.html {
        }
    }

# Settings for a TLS enabled server.
#
#    server {
#        listen       443 ssl http2;
#        location = /50x.html {
#        }
#    }

}

"""

# Excerpt of the stock RHEL 9 httpd.conf: the commented Listen example comes
# before the live Listen 80, and ServerName exists only as a comment.
STOCK_HTTPD_CONF = """\
ServerRoot "/etc/httpd"

#
#Listen 12.34.56.78:80
Listen 80

#ServerName www.example.com:80

<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>
"""


def _nginx_context_of(text, needle):
    """Return the names of the nginx blocks open at the line containing needle."""
    stack, words = [], []
    for line in text.splitlines():
        if needle in line:
            return list(stack)
        for token in re.findall(r"[^\s{};]+|[{};]", line.split("#", 1)[0]):
            if token == "{":
                stack.append(words[0] if words else "")
                words = []
            elif token == "}":
                stack.pop()
                words = []
            elif token == ";":
                words = []
            else:
                words.append(token)
    raise AssertionError(f"{needle!r} not found")


class TestNginxBlockInsideHttp(RedirectedFixtureTestCase):
    """The nginx server block must land inside http {}, where nginx accepts it."""

    BLOCK = "server {\n    listen 8081 default_server;\n}"

    def _conf(self, td, text):
        p = Path(td) / "nginx.conf"
        p.write_text(text)
        return p

    def test_block_is_inserted_inside_http(self):
        with tempfile.TemporaryDirectory() as td:
            d, _ = self._build_redirected_drifter(td, "standard")
            p = self._conf(td, STOCK_NGINX_CONF)
            d._append_managed_block(str(p), "nginx-server-block", self.BLOCK,
                                    create_if_missing=False, inside_block="http")
            text = p.read_text()
            self.assertEqual(_nginx_context_of(text, "listen 8081"), ["http", "server"])
            # Still the last } at column zero closes http, after the block.
            self.assertLess(text.index("# END DRIFTIFY nginx-server-block"),
                            text.rindex("\n}\n"))

    def test_insert_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            d, _ = self._build_redirected_drifter(td, "standard")
            p = self._conf(td, STOCK_NGINX_CONF)
            for _ in range(2):
                d._append_managed_block(str(p), "nginx-server-block", self.BLOCK,
                                        inside_block="http")
            self.assertEqual(p.read_text().count("# BEGIN DRIFTIFY nginx-server-block"), 1)

    def test_http_block_not_last_in_file(self):
        conf = "http {\n    server {\n        listen 80;\n    }\n}\n\nevents {\n}\n"
        with tempfile.TemporaryDirectory() as td:
            d, _ = self._build_redirected_drifter(td, "standard")
            p = self._conf(td, conf)
            d._append_managed_block(str(p), "nginx-server-block", self.BLOCK,
                                    inside_block="http")
            self.assertEqual(_nginx_context_of(p.read_text(), "listen 8081"),
                             ["http", "server"])

    def test_missing_http_block_warns_and_leaves_file_alone(self):
        for conf in ("events {\n}\n",
                     "http {\n    server {\n        listen 80;\n    }\n",
                     "#http {\n#}\n"):
            with self.subTest(conf=conf), tempfile.TemporaryDirectory() as td:
                d, _ = self._build_redirected_drifter(td, "standard")
                p = self._conf(td, conf)
                self._suppress.__exit__(None, None, None)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    d._append_managed_block(str(p), "nginx-server-block",
                                            self.BLOCK, inside_block="http")
                self._suppress.__enter__()
                self.assertEqual(p.read_text(), conf)
                self.assertIn("http", buf.getvalue())
                self.assertIn("skipping block 'nginx-server-block'", buf.getvalue())

    def test_drift_config_asks_for_the_http_block(self):
        for profile in ("minimal", "standard", "kitchen-sink"):
            with self.subTest(profile=profile):
                d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
                calls = []
                d._append_managed_block = (
                    lambda path_str, marker, block, **kw:
                    calls.append((path_str, marker, kw))
                )
                d.run_cmd = lambda *a, **k: None
                d.drift_config()
                nginx = [kw for p, m, kw in calls if m == "nginx-server-block"]
                self.assertEqual(len(nginx), 1)
                self.assertEqual(nginx[0].get("inside_block"), "http")


class TestApplyDirectivesLiveLines(RedirectedFixtureTestCase):
    """_apply_directives replaces live directives and leaves comments alone."""

    def _apply(self, td, name, text, directives):
        d, _ = self._build_redirected_drifter(td, "standard")
        p = Path(td) / name
        p.write_text(text)
        d._apply_directives(str(p), directives)
        return p.read_text()

    def test_live_listen_replaced_not_the_commented_example(self):
        with tempfile.TemporaryDirectory() as td:
            out = self._apply(td, "httpd.conf", STOCK_HTTPD_CONF,
                              {"Listen": "Listen 8080"})
        listens = [l for l in out.splitlines() if re.match(r"\s*Listen\b", l)]
        self.assertEqual(listens, ["Listen 8080"])
        self.assertIn("#Listen 12.34.56.78:80", out)

    def test_commented_only_directive_is_appended(self):
        with tempfile.TemporaryDirectory() as td:
            out = self._apply(td, "httpd.conf", STOCK_HTTPD_CONF,
                              {"ServerName": "ServerName driftify.local"})
        self.assertIn("#ServerName www.example.com:80", out)
        self.assertTrue(out.endswith("ServerName driftify.local\n"))

    def test_sshd_commented_default_is_kept_and_directive_appended(self):
        sshd = ("#Port 22\n#PermitRootLogin prohibit-password\n"
                "#StrictModes yes\nPasswordAuthentication yes\n")
        with tempfile.TemporaryDirectory() as td:
            out = self._apply(td, "sshd_config", sshd,
                              {"PermitRootLogin": "PermitRootLogin no"})
        self.assertIn("#PermitRootLogin prohibit-password\n", out)
        live = [l for l in out.splitlines() if l.startswith("PermitRootLogin")]
        self.assertEqual(live, ["PermitRootLogin no"])

    def test_indented_live_directive_is_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            out = self._apply(td, "auditd.conf", "  max_log_file = 8\n# max_log_file = 1\n",
                              {"max_log_file": "max_log_file = 64"})
        self.assertEqual(out, "max_log_file = 64\n# max_log_file = 1\n")


class TestHttpdNginxPortsDisjoint(RedirectedFixtureTestCase):
    """httpd and nginx never claim the same port, in any profile."""

    @staticmethod
    def _ports(text, keyword):
        ports = set()
        for line in text.splitlines():
            m = re.match(rf"\s*{keyword}\s+([^\s;]+)", line)
            if m:
                ports.add(m.group(1).rsplit(":", 1)[-1])
        return ports

    def test_no_shared_port_per_profile(self):
        for profile in ("minimal", "standard", "kitchen-sink"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as td:
                # Capture what drift_config asks for, then apply it with the
                # real writers to stock-layout files.
                d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
                directives, blocks = [], []
                d._apply_directives = (
                    lambda path_str, mapping: directives.append((path_str, mapping)))
                d._append_managed_block = (
                    lambda path_str, marker, block, **kw:
                    blocks.append((path_str, marker, block, kw)))
                d.run_cmd = lambda *a, **k: None
                d.drift_config()

                real, map_path = self._build_redirected_drifter(td, profile)
                httpd = map_path("/etc/httpd/conf/httpd.conf")
                nginx = map_path("/etc/nginx/nginx.conf")
                httpd.parent.mkdir(parents=True)
                nginx.parent.mkdir(parents=True)
                httpd.write_text(STOCK_HTTPD_CONF)
                nginx.write_text(STOCK_NGINX_CONF)
                for path_str, mapping in directives:
                    if path_str in ("/etc/httpd/conf/httpd.conf", "/etc/nginx/nginx.conf"):
                        real._apply_directives(str(map_path(path_str)), mapping)
                for path_str, marker, block, kw in blocks:
                    if path_str in ("/etc/httpd/conf/httpd.conf", "/etc/nginx/nginx.conf"):
                        real._append_managed_block(path_str, marker, block, **kw)

                httpd_ports = self._ports(httpd.read_text(), "Listen")
                nginx_ports = self._ports(nginx.read_text(), "listen")
                self.assertEqual(httpd_ports, {"8080"})
                self.assertIn("80", nginx_ports)
                self.assertEqual(httpd_ports & nginx_ports, set())


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



class FakeSystemd:
    """A small stand-in for systemctl: enable/disable follow Also=, mask
    replaces the state, and is-enabled reads hand-made links from the temp
    tree. Enough to check what the unit-state cases run and what they claim."""

    def __init__(self, root, units=None, also=None, version=257):
        self.root = Path(root)
        # unit -> [state, preset]
        self.units = {k: list(v) for k, v in (units or {}).items()}
        self.also = also or {}
        self.version = version
        self.instances = {}
        self.default = "multi-user.target"
        self.commands = []
        self.genkey_calls = 0

    def _closure(self, unit):
        seen, todo = [], [unit]
        while todo:
            u = todo.pop(0)
            if u in seen:
                continue
            seen.append(u)
            todo += self.also.get(u, [])
        return seen

    def _set(self, unit, state):
        if "@" in unit and not unit.endswith("@.service"):
            self.instances[unit] = state
            return
        entry = self.units.setdefault(unit, ["disabled", "disabled"])
        if entry[0] == "static" and state != "masked":
            return
        entry[0] = state

    def run(self, cmd, check=True, capture=False):
        cmd = [str(c) for c in cmd]
        self.commands.append(cmd)
        stdout = ""
        if cmd[:2] == ["wg", "genkey"]:
            self.genkey_calls += 1
            stdout = "DRIFTIFYFAKEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        elif cmd[0] == "systemctl" and len(cmd) > 2:
            verb, unit = cmd[1], cmd[2]
            if verb == "enable":
                for u in self._closure(unit):
                    self._set(u, "enabled")
            elif verb == "disable":
                for u in self._closure(unit):
                    self._set(u, "disabled")
            elif verb == "mask":
                self._set(unit, "masked")
            elif verb == "set-default":
                self.default = unit
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout)

    def _hand_linked(self, unit):
        base = self.root / "etc" / "systemd" / "system"
        return any(p.is_symlink() for p in base.glob(f"*.wants/{unit}"))

    def query(self, args):
        if args[0] == "--version":
            return f"systemd {self.version} (fake)\n+PAM\n"
        if args[0] == "get-default":
            return self.default + "\n"
        unit = args[-1]
        if args[0] == "list-unit-files":
            if unit in self.units:
                state, preset = self.units[unit]
                return f"{unit} {state} {preset}\n"
            return ""
        if args[0] == "is-enabled":
            if unit in self.instances:
                return self.instances[unit] + "\n"
            if unit in self.units and self.units[unit][0] != "static":
                return self.units[unit][0] + "\n"
            if self._hand_linked(unit):
                return "enabled\n"
            if unit in self.units:
                return "static\n"
            return ""
        raise AssertionError(f"unexpected systemctl query {args}")

    def ran(self, *cmd):
        return list(cmd) in self.commands

    def index(self, *cmd):
        return self.commands.index(list(cmd))


# Unit states as the packages leave them, from real RHEL 9 and RHEL 10 hosts
# after dnf install (state, preset).
EL9_UNITS = {
    "tmp.mount": ("disabled", "disabled"),
    "getty@.service": ("enabled", "enabled"),
    "graphical.target": ("static", "-"),
    "cockpit.socket": ("disabled", "disabled"),
    "cups.service": ("enabled", "enabled"),
    "cups.socket": ("enabled", "enabled"),
    "cups.path": ("enabled", "enabled"),
    "iscsid.service": ("disabled", "disabled"),
    "iscsid.socket": ("enabled", "enabled"),
    "virtnetworkd.service": ("disabled", "disabled"),
    "virtnetworkd.socket": ("enabled", "enabled"),
    "virtnetworkd-ro.socket": ("enabled", "enabled"),
    "virtnetworkd-admin.socket": ("enabled", "enabled"),
    "wg-quick@.service": ("disabled", "disabled"),
    "multipathd.service": ("enabled", "enabled"),
    "multipathd.socket": ("enabled", "disabled"),
}
EL10_UNITS = dict(EL9_UNITS)
EL10_UNITS.update({
    "cockpit.socket": ("enabled", "enabled"),
    "multipathd.socket": ("static", "-"),
})
VIRTNETWORKD_SOCKETS = [
    "virtnetworkd.socket", "virtnetworkd-ro.socket", "virtnetworkd-admin.socket",
]
REAL_ALSO = {
    "cups.service": ["cups.socket", "cups.path"],
    "iscsid.service": ["iscsid.socket"],
    "virtnetworkd.service": list(VIRTNETWORKD_SOCKETS),
    "virtnetworkd.socket": ["virtnetworkd-ro.socket", "virtnetworkd-admin.socket"],
    "virtnetworkd-ro.socket": ["virtnetworkd.socket", "virtnetworkd-admin.socket"],
    "virtnetworkd-admin.socket": ["virtnetworkd.socket", "virtnetworkd-ro.socket"],
    "driftify-also-main.service": ["driftify-also-member.service"],
}
EL9_ALSO = dict(REAL_ALSO, **{"multipathd.service": ["multipathd.socket"]})


class TestUnitStates(RedirectedFixtureTestCase):
    """The unit-state cases: masks, instances, hand-made links, Also=,
    sockets against their preset, .upholds and the default target."""

    def _drifter(self, td, profile, units=EL9_UNITS, also=EL9_ALSO, version=252):
        d, map_path = self._build_redirected_drifter(td, profile)
        fake = FakeSystemd(td, units, also, version)
        d.run_cmd = fake.run
        d._systemctl_query = fake.query
        original_symlink = d._ensure_symlink
        d._ensure_symlink = (
            lambda link, target: original_symlink(str(map_path(link)), target)
        )
        original_if_absent = d._write_if_absent
        d._write_if_absent = (
            lambda path_str, make_content, mode=0o644:
            original_if_absent(str(map_path(path_str)), make_content, mode)
        )
        return d, map_path, fake

    def _planted(self, d):
        return [text for status, text in d._unit_cases if status == "planted"]

    def _skipped(self, d):
        return [text for status, text in d._unit_cases if status != "planted"]

    # ── minimal ──────────────────────────────────────────────────────────

    def test_minimal_masks_tmp_mount_and_enables_getty_instance(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "minimal")
            d._drift_unit_states()
        self.assertTrue(fake.ran("systemctl", "mask", "tmp.mount"))
        self.assertTrue(fake.ran("systemctl", "enable", "getty@tty2.service"))
        planted = "\n".join(self._planted(d))
        self.assertIn("tmp.mount masked", planted)
        self.assertIn("/etc/systemd/system/tmp.mount -> /dev/null", planted)
        self.assertIn("getty@tty2.service enabled", planted)
        self.assertIn("/etc/systemd/system/getty.target.wants/getty@tty2.service", planted)

    def test_minimal_plants_nothing_from_higher_profiles(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "minimal")
            d._drift_unit_states()
            self.assertFalse(map_path("/etc/systemd/system/driftify-static.service").exists())
            self.assertFalse(map_path("/etc/systemd/system/driftify-also-main.service").exists())
        flat = [" ".join(c) for c in fake.commands]
        for word in ("cockpit", "cups", "iscsid", "virtnetworkd", "wg-quick",
                     "multipathd", "set-default", "driftify-"):
            self.assertFalse(any(word in c for c in flat), word)
        self.assertEqual(len(self._planted(d)), 2)

    def test_minimal_skips_absent_tmp_mount_without_claiming_it(self):
        units = {k: v for k, v in EL9_UNITS.items() if k != "tmp.mount"}
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "minimal", units=units)
            d._drift_unit_states()
        self.assertFalse(fake.ran("systemctl", "mask", "tmp.mount"))
        self.assertFalse(any("tmp.mount" in t for t in self._planted(d)))
        self.assertTrue(any("tmp.mount" in t for t in self._skipped(d)))

    # ── standard ─────────────────────────────────────────────────────────

    def test_standard_static_unit_gets_a_hand_made_link(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "standard")
            d._drift_unit_states()
            unit = map_path("/etc/systemd/system/driftify-static.service")
            link = map_path(
                "/etc/systemd/system/multi-user.target.wants/driftify-static.service")
            content = unit.read_text()
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "/etc/systemd/system/driftify-static.service")
        self.assertNotIn("[Install]", content)
        self.assertIn("Type=oneshot", content)
        self.assertIn("ExecStart=/bin/true", content)
        # A static unit cannot be enabled with systemctl; the link is made by hand.
        self.assertFalse(fake.ran("systemctl", "enable", "driftify-static.service"))
        self.assertTrue(any(
            "driftify-static.service enabled" in t
            and "multi-user.target.wants/driftify-static.service" in t
            for t in self._planted(d)))

    def test_standard_also_pair_enabled_through_main_unit(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "standard")
            d._drift_unit_states()
            main = map_path("/etc/systemd/system/driftify-also-main.service").read_text()
            member = map_path("/etc/systemd/system/driftify-also-member.service").read_text()
        self.assertIn("WantedBy=multi-user.target", main)
        self.assertIn("Also=driftify-also-member.service", main)
        self.assertIn("[Install]", member)
        self.assertIn("WantedBy=multi-user.target", member)
        for content in (main, member):
            self.assertIn("ExecStart=/bin/true", content)
        self.assertTrue(fake.ran("systemctl", "enable", "driftify-also-main.service"))
        self.assertFalse(fake.ran("systemctl", "enable", "driftify-also-member.service"))
        planted = "\n".join(self._planted(d))
        self.assertIn("driftify-also-member.service enabled", planted)

    def test_standard_cockpit_socket_enabled_where_preset_is_disable(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "standard", units=EL9_UNITS)
            d._drift_unit_states()
        self.assertTrue(fake.ran("systemctl", "enable", "cockpit.socket"))
        self.assertFalse(fake.ran("systemctl", "disable", "cockpit.socket"))
        self.assertTrue(any("cockpit.socket enabled" in t for t in self._planted(d)))

    def test_standard_cockpit_socket_disabled_where_preset_is_enable(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "standard", units=EL10_UNITS, version=257)
            d._drift_unit_states()
        self.assertTrue(fake.ran("systemctl", "disable", "cockpit.socket"))
        self.assertFalse(fake.ran("systemctl", "enable", "cockpit.socket"))
        self.assertTrue(any("cockpit.socket disabled" in t for t in self._planted(d)))

    def test_standard_cockpit_follows_preset_not_current_state(self):
        # Already enabled by an earlier run on an EL9 host: still enable.
        units = dict(EL9_UNITS, **{"cockpit.socket": ("enabled", "disabled")})
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "standard", units=units)
            d._drift_unit_states()
        self.assertFalse(fake.ran("systemctl", "disable", "cockpit.socket"))
        self.assertTrue(any("cockpit.socket enabled" in t for t in self._planted(d)))

    def test_standard_cockpit_absent_is_skipped(self):
        units = {k: v for k, v in EL9_UNITS.items() if k != "cockpit.socket"}
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "standard", units=units)
            d._drift_unit_states()
        self.assertFalse(any("cockpit" in " ".join(c) for c in fake.commands))
        self.assertTrue(any("cockpit.socket" in t for t in self._skipped(d)))

    def test_standard_cockpit_without_preset_column_is_skipped(self):
        # EL8's systemd 239 prints no preset column.
        units = dict(EL9_UNITS)
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "standard", units=units)
            original = fake.query
            fake.query = lambda args: (
                "cockpit.socket disabled\n"
                if args[0] == "list-unit-files" and args[-1] == "cockpit.socket"
                else original(args))
            d._systemctl_query = fake.query
            d._drift_unit_states()
        self.assertFalse(any("cockpit" in " ".join(c) for c in fake.commands))
        self.assertTrue(any("cockpit.socket" in t for t in self._skipped(d)))

    def test_standard_plants_no_kitchen_sink_case(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "standard")
            d._drift_unit_states()
            self.assertFalse(map_path("/etc/systemd/system/driftify-upheld.service").exists())
        flat = [" ".join(c) for c in fake.commands]
        for word in ("cups", "iscsid", "virtnetworkd", "wg-quick", "multipathd",
                     "set-default", "genkey"):
            self.assertFalse(any(word in c for c in flat), word)

    # ── kitchen-sink ─────────────────────────────────────────────────────

    def _assert_pair(self, fake, on, off):
        self.assertLess(fake.index("systemctl", "enable", on),
                        fake.index("systemctl", "disable", off))

    def test_kitchen_sink_service_on_socket_off_pairs(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "kitchen-sink")
            d._drift_unit_states()
        self._assert_pair(fake, "cups.service", "cups.socket")
        self._assert_pair(fake, "iscsid.service", "iscsid.socket")
        self._assert_pair(fake, "virtnetworkd.service", "virtnetworkd-ro.socket")
        self.assertEqual(fake.units["cups.service"][0], "enabled")
        self.assertEqual(fake.units["cups.path"][0], "enabled")
        self.assertEqual(fake.units["cups.socket"][0], "disabled")
        self.assertEqual(fake.units["iscsid.service"][0], "enabled")
        self.assertEqual(fake.units["iscsid.socket"][0], "disabled")
        self.assertEqual(fake.units["virtnetworkd.service"][0], "enabled")
        for sock in VIRTNETWORKD_SOCKETS:
            self.assertEqual(fake.units[sock][0], "disabled", sock)
        planted = "\n".join(self._planted(d))
        self.assertIn("cups.socket disabled", planted)
        self.assertIn("cups.path enabled", planted)
        self.assertIn("iscsid.socket disabled", planted)
        self.assertIn("virtnetworkd-admin.socket", planted)
        self.assertFalse(any("--now" in c for c in fake.commands))

    def test_kitchen_sink_cups_path_absent_is_skipped(self):
        units = {k: v for k, v in EL9_UNITS.items() if k != "cups.path"}
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "kitchen-sink", units=units)
            d._drift_unit_states()
        self.assertFalse(fake.ran("systemctl", "enable", "cups.service"))
        self.assertFalse(any("cups" in t for t in self._planted(d)))
        self.assertTrue(any("cups.path" in t for t in self._skipped(d)))

    def test_kitchen_sink_cups_path_not_enabled_is_not_claimed(self):
        # A cups.service without Also=cups.path leaves cups.path as it was.
        units = dict(EL9_UNITS, **{"cups.path": ("disabled", "disabled")})
        also = dict(EL9_ALSO, **{"cups.service": ["cups.socket"]})
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "kitchen-sink", units=units, also=also)
            d._drift_unit_states()
        self.assertFalse(any("cups" in t for t in self._planted(d)))
        self.assertTrue(any("cups.path is disabled" in t for t in self._skipped(d)))

    def test_kitchen_sink_virtnetworkd_ro_socket_is_disabled_directly(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, _ = self._drifter(td, "kitchen-sink")
            d._drift_unit_states()
        planted = "\n".join(self._planted(d))
        self.assertIn("virtnetworkd-ro.socket disabled (no ", planted)
        self.assertNotIn("virtnetworkd-ro.socket disabled through", planted)
        for sock in ("virtnetworkd.socket", "virtnetworkd-admin.socket"):
            self.assertIn(f"{sock} disabled through Also= on virtnetworkd-ro.socket",
                          planted)

    def test_kitchen_sink_wireguard_instance_with_generated_key(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "kitchen-sink")
            d._drift_unit_states()
            conf = map_path(driftify.WG_CONF_PATH)
            mode = conf.stat().st_mode & 0o777
            content = conf.read_text()
        self.assertEqual(mode, 0o600)
        self.assertIn("PrivateKey = DRIFTIFYFAKEKEY", content)
        self.assertEqual(fake.genkey_calls, 1)
        self.assertTrue(fake.ran("systemctl", "enable", "wg-quick@wg0.service"))
        self.assertFalse(any(c[:2] == ["systemctl", "start"] for c in fake.commands))
        self.assertTrue(any("wg-quick@wg0.service enabled" in t for t in self._planted(d)))

    def test_kitchen_sink_wireguard_keeps_an_existing_config(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "kitchen-sink")
            conf = map_path(driftify.WG_CONF_PATH)
            conf.parent.mkdir(parents=True)
            conf.write_text("[Interface]\nPrivateKey = KEEPME=\n")
            d._drift_unit_states()
            self.assertEqual(conf.read_text(), "[Interface]\nPrivateKey = KEEPME=\n")
        self.assertEqual(fake.genkey_calls, 0)

    def test_kitchen_sink_wireguard_absent_is_skipped(self):
        units = {k: v for k, v in EL9_UNITS.items() if k != "wg-quick@.service"}
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "kitchen-sink", units=units)
            d._drift_unit_states()
            self.assertFalse(map_path(driftify.WG_CONF_PATH).exists())
        self.assertEqual(fake.genkey_calls, 0)
        self.assertTrue(any("wg-quick@wg0" in t for t in self._skipped(d)))

    def test_kitchen_sink_wireguard_genkey_failure_is_skipped(self):
        for label, result in (("non-zero exit", (1, "")),
                              ("empty output", (0, "\n"))):
            with self.subTest(label), tempfile.TemporaryDirectory() as td:
                d, map_path, fake = self._drifter(td, "kitchen-sink")
                original = fake.run

                def run(cmd, check=True, capture=False, result=result):
                    if [str(c) for c in cmd[:2]] == ["wg", "genkey"]:
                        fake.commands.append([str(c) for c in cmd])
                        rc, out = result
                        return subprocess.CompletedProcess(cmd, rc, stdout=out)
                    return original(cmd, check, capture)

                d.run_cmd = run
                d._drift_unit_states()
                self.assertFalse(map_path(driftify.WG_CONF_PATH).exists())
                self.assertTrue(fake.ran("wg", "genkey"))
                self.assertFalse(fake.ran("systemctl", "enable", "wg-quick@wg0.service"))
                self.assertFalse(any("wg-quick@wg0" in t for t in self._planted(d)))
                self.assertTrue(any("wg-quick@wg0" in t and "wg genkey failed" in t
                                    for t in self._skipped(d)))

    def test_keeping_an_existing_file_is_silent_when_quiet(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, _ = self._drifter(td, "kitchen-sink")
            d.quiet = True
            conf = map_path(driftify.WG_CONF_PATH)
            conf.parent.mkdir(parents=True)
            conf.write_text("[Interface]\nPrivateKey = KEEPME=\n")
            output = self._capture(
                lambda: d._write_if_absent(driftify.WG_CONF_PATH, lambda: "x\n"))
        self.assertNotIn("Keeping existing", output)

    def test_kitchen_sink_multipathd_socket_on_el9(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "kitchen-sink", units=EL9_UNITS, also=EL9_ALSO)
            d._drift_unit_states()
        self.assertTrue(fake.ran("systemctl", "enable", "multipathd.service"))
        self.assertTrue(any("multipathd.socket enabled" in t for t in self._planted(d)))

    def test_kitchen_sink_multipathd_service_not_enabled_is_not_claimed(self):
        # The text says the socket came on through multipathd.service's Also=,
        # so the service has to end enabled too.
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "kitchen-sink")
            original = fake.query
            fake.query = lambda args: (
                "disabled\n" if args == ["is-enabled", "multipathd.service"]
                else original(args))
            d._systemctl_query = fake.query
            d._drift_unit_states()
        self.assertFalse(any("multipathd" in t for t in self._planted(d)))
        self.assertTrue(any("multipathd.service is disabled" in t
                            for t in self._skipped(d)))

    def test_kitchen_sink_multipathd_socket_skipped_on_el10(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "kitchen-sink", units=EL10_UNITS,
                                       also=REAL_ALSO, version=257)
            d._drift_unit_states()
        self.assertFalse(any("multipathd" in " ".join(c) for c in fake.commands))
        skipped = "\n".join(self._skipped(d))
        self.assertIn("multipathd.socket", skipped)
        self.assertIn("[Install]", skipped)

    def test_kitchen_sink_upheld_unit_on_systemd_257(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "kitchen-sink", units=EL10_UNITS,
                                              also=REAL_ALSO, version=257)
            fake.units["driftify-upheld.service"] = ["disabled", "disabled"]
            d._drift_unit_states()
            content = map_path("/etc/systemd/system/driftify-upheld.service").read_text()
        self.assertIn("UpheldBy=multi-user.target", content)
        self.assertIn("ExecStart=/bin/true", content)
        self.assertTrue(fake.ran("systemctl", "enable", "driftify-upheld.service"))
        self.assertTrue(any(
            "multi-user.target.upholds/driftify-upheld.service" in t
            for t in self._planted(d)))

    def test_kitchen_sink_upheld_unit_skipped_on_systemd_252(self):
        with tempfile.TemporaryDirectory() as td:
            d, map_path, fake = self._drifter(td, "kitchen-sink", version=252)
            d._drift_unit_states()
            self.assertFalse(map_path("/etc/systemd/system/driftify-upheld.service").exists())
        self.assertFalse(any("driftify-upheld" in " ".join(c) for c in fake.commands))
        skipped = "\n".join(self._skipped(d))
        self.assertIn("UpheldBy=", skipped)
        self.assertIn("252", skipped)

    def test_kitchen_sink_sets_default_target(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "kitchen-sink")
            d._drift_unit_states()
        self.assertTrue(fake.ran("systemctl", "set-default", "graphical.target"))
        self.assertEqual(fake.default, "graphical.target")
        self.assertTrue(any(
            "default.target -> graphical.target" in t for t in self._planted(d)))

    def test_kitchen_sink_rerun_ends_in_the_same_state(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "kitchen-sink", units=EL10_UNITS,
                                       also=REAL_ALSO, version=257)
            d._drift_unit_states()
            first_units = {k: list(v) for k, v in fake.units.items()}
            first_inst = dict(fake.instances)
            first_default = fake.default
            first_planted = self._planted(d)
            first_skipped = self._skipped(d)
            d._unit_cases = []
            d._drift_unit_states()
        self.assertEqual(fake.units, first_units)
        self.assertEqual(fake.instances, first_inst)
        self.assertEqual(fake.default, first_default)
        self.assertEqual(self._planted(d), first_planted)
        self.assertEqual(self._skipped(d), first_skipped)
        self.assertEqual(fake.genkey_calls, 1)

    def test_kitchen_sink_after_standard_keeps_cockpit_state(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "standard")
            d._drift_unit_states()
            after_standard = fake.units["cockpit.socket"][0]
            d.profile = "kitchen-sink"
            d._drift_unit_states()
        self.assertEqual(after_standard, "enabled")
        self.assertEqual(fake.units["cockpit.socket"][0], "enabled")

    def test_state_that_does_not_take_is_not_claimed(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "minimal")
            original = fake.query
            fake.query = lambda args: (
                "disabled\n" if args == ["is-enabled", "tmp.mount"] else original(args))
            d._systemctl_query = fake.query
            d._drift_unit_states()
        self.assertFalse(any("tmp.mount" in t for t in self._planted(d)))
        self.assertTrue(any("tmp.mount" in t for t in self._skipped(d)))

    # ── daemon-reload after the local unit files ─────────────────────────

    def test_daemon_reload_follows_every_local_unit_write(self):
        reload = ("systemctl", "daemon-reload")
        for profile, units, version, last_local in (
                ("standard", EL9_UNITS, 252, "driftify-also-main.service"),
                ("kitchen-sink", EL10_UNITS, 257, "driftify-upheld.service")):
            with self.subTest(profile), tempfile.TemporaryDirectory() as td:
                d, _, fake = self._drifter(td, profile, units=units, version=version)
                d._drift_unit_states()
                self.assertEqual(fake.commands.count(list(reload)), 1)
                self.assertGreater(fake.index(*reload),
                                   fake.index("systemctl", "enable", last_local))

    def test_daemon_reload_not_run_at_minimal(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, fake = self._drifter(td, "minimal")
            d._drift_unit_states()
        self.assertFalse(fake.ran("systemctl", "daemon-reload"))

    def test_daemon_reload_not_run_in_dry_run(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        d.run_cmd = unittest.mock.MagicMock()
        with unittest.mock.patch.object(driftify.Path, "exists", return_value=False):
            self._capture(d._drift_unit_states)
        self.assertNotIn(["systemctl", "daemon-reload"],
                         [c.args[0] for c in d.run_cmd.call_args_list])

    # ── dry run, section gating, summary, packages ───────────────────────

    def _capture(self, fn):
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            fn()
        self._suppress.__enter__()
        return buf.getvalue()

    def test_dry_run_prints_the_plan_without_probing(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=[])
        with unittest.mock.patch("subprocess.run",
                                 side_effect=AssertionError("probed in dry run")), \
             unittest.mock.patch.object(driftify.Path, "exists", return_value=False):
            output = self._capture(d._drift_unit_states)
        for text in ("systemctl mask tmp.mount", "getty@tty2.service",
                     "driftify-static.service", "driftify-also-main.service",
                     "cockpit.socket", "systemctl disable cups.socket",
                     "systemctl disable iscsid.socket",
                     "systemctl disable virtnetworkd-ro.socket",
                     "wg-quick@wg0.service", "multipathd.service",
                     "driftify-upheld.service", "set-default graphical.target"):
            self.assertIn(text, output)

    def test_dry_run_minimal_prints_only_minimal_cases(self):
        d = driftify.Driftify("minimal", dry_run=True, skip_sections=[])
        with unittest.mock.patch.object(driftify.Path, "exists", return_value=False):
            output = self._capture(d._drift_unit_states)
        self.assertIn("tmp.mount", output)
        self.assertNotIn("cockpit", output)
        self.assertNotIn("cups", output)

    def test_skip_services_skips_unit_states(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=["services"])
        d._drift_unit_states = unittest.mock.MagicMock()
        d.drift_services()
        d._drift_unit_states.assert_not_called()

    def test_summary_lists_planted_and_skipped_cases(self):
        with tempfile.TemporaryDirectory() as td:
            d, _, _ = self._drifter(td, "kitchen-sink", version=252)
            d._drift_unit_states()
            d._t0 = driftify.time.monotonic()
            output = self._capture(d._print_summary)
        self.assertIn("tmp.mount masked", output)
        self.assertIn("cups.socket disabled", output)
        self.assertIn("skipped: driftify-upheld.service", output)

    def test_summary_without_services_lists_no_unit_cases(self):
        d = driftify.Driftify("kitchen-sink", dry_run=True, skip_sections=["services"])
        d._t0 = driftify.time.monotonic()
        output = self._capture(d._print_summary)
        self.assertNotIn("tmp.mount", output)

    def test_run_description_names_the_unit_cases_by_profile(self):
        minimal = " ".join(driftify.Driftify(
            "minimal", dry_run=True, skip_sections=[])._run_description())
        standard = " ".join(driftify.Driftify(
            "standard", dry_run=True, skip_sections=[])._run_description())
        sink = " ".join(driftify.Driftify(
            "kitchen-sink", dry_run=True, skip_sections=[])._run_description())
        self.assertIn("mask tmp.mount", minimal)
        self.assertNotIn("cockpit.socket", minimal)
        self.assertIn("cockpit.socket", standard)
        self.assertNotIn("cups.socket", standard)
        for text in ("cups.socket", "iscsid.socket", "virtnetworkd", "wg-quick@wg0",
                     "multipathd.socket", "UpheldBy=", "graphical.target"):
            self.assertIn(text, sink)

    def test_rpm_installs_unit_case_packages_by_profile(self):
        def dnf_lines(profile):
            d = driftify.Driftify(profile, dry_run=True, skip_sections=[])
            d._install_mixed_arch = lambda: None
            d._install_duplicate_package = lambda: None
            return self._capture(d.drift_rpm)

        minimal, standard, sink = (dnf_lines(p) for p in driftify.PROFILES)
        self.assertNotIn("cockpit", minimal)
        self.assertIn("dnf install -y cockpit", standard)
        self.assertNotIn("cups", standard)
        for pkg in ("cups", "iscsi-initiator-utils", "libvirt-daemon-driver-network",
                    "libvirt-daemon-log", "libvirt-daemon-lock", "wireguard-tools",
                    "device-mapper-multipath"):
            self.assertIn(pkg, sink)
        self.assertNotIn("libvirt-daemon-driver-qemu", sink)
        self.assertNotIn("podman-docker", sink)
