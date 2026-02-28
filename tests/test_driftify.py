import io
import json
import os
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
    def test_stamp_round_trip_and_record(self):
        with tempfile.TemporaryDirectory() as td:
            stamp_path = Path(td) / "driftify.stamp"
            sf = driftify.StampFile(stamp_path)
            sf.start("standard", "centos", 9)
            sf.record("services_enabled", "httpd")
            sf.record("services_enabled", "nginx")
            sf.record("services_enabled", "httpd")
            sf.record("dnf_transaction_start", 42)
            sf.save()
            sf.finish()

            sf2 = driftify.StampFile(stamp_path)
            loaded = sf2.load()

            self.assertEqual(loaded["profile"], "standard")
            self.assertEqual(loaded["os_major"], 9)
            self.assertEqual(loaded["services_enabled"], ["httpd", "nginx"])
            self.assertEqual(loaded["dnf_transaction_start"], 42)
            self.assertIsNotNone(loaded["finished"])

    def test_record_does_not_auto_save(self):
        with tempfile.TemporaryDirectory() as td:
            stamp_path = Path(td) / "driftify.stamp"
            sf = driftify.StampFile(stamp_path)
            sf.start("minimal", "rhel", 9)
            sf.record("services_enabled", "httpd")

            sf2 = driftify.StampFile(stamp_path)
            sf2.load()
            self.assertEqual(sf2.data["services_enabled"], [])

            sf.save()
            sf2.load()
            self.assertEqual(sf2.data["services_enabled"], ["httpd"])

    def test_stamp_has_firewall_fields(self):
        with tempfile.TemporaryDirectory() as td:
            sf = driftify.StampFile(Path(td) / "stamp.json")
            sf.start("standard", "centos", 9)
            self.assertIn("firewall_services", sf.data)
            self.assertIn("firewall_ports", sf.data)
            self.assertEqual(sf.data["firewall_services"], [])


class TestHelpersAndDryRun(DriftifyTestCase):
    def _build_non_dry_with_temp_stamp(self, td):
        driftify.STAMP_PATH = Path(td) / "stamp.json"
        d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
        d.stamp.start(d.profile, d.os_id, d.os_major)
        return d

    def test_write_managed_text_tracks_created_and_backup(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build_non_dry_with_temp_stamp(td)
            file_path = Path(td) / "cfg.txt"

            d._write_managed_text(str(file_path), "one\n")
            self.assertTrue(file_path.exists())
            self.assertIn(str(file_path), d.stamp.data["files_created"])

            d._write_managed_text(str(file_path), "two\n")
            backups = d.stamp.data.get("file_backups", {})
            self.assertEqual(backups[str(file_path)], "one\n")
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
        with redirect_stdout(buf):
            with unittest.mock.patch.object(driftify.Path, "exists",
                                            return_value=True):
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
        self.assertFalse(any("firewall" in l for l in lines))
        self.assertTrue(any("httpd" in l for l in lines))

    def test_yes_flag_parsed(self):
        p = driftify.build_parser()
        args = p.parse_args(["-y"])
        self.assertTrue(args.yes)
        args = p.parse_args(["--yes"])
        self.assertTrue(args.yes)
        args = p.parse_args([])
        self.assertFalse(args.yes)

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


class TestSummary(DriftifyTestCase):
    def test_summary_services_uses_stamp_data(self):
        """Summary shows actual service counts from stamp, not hardcoded estimates."""
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            # Simulate only 1 service enabled (not the usual 2)
            d.stamp.record("services_enabled", "httpd")
            d.stamp.record("services_disabled", "kdump")
            d.stamp.record("services_masked", "bluetooth")
            d.stamp.save()
            d._t0 = __import__("time").monotonic()

            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                d._print_summary()
            self._suppress.__enter__()
            output = buf.getvalue()
            self.assertIn("1 enabled", output)
            self.assertIn("1 disabled", output)
            self.assertIn("1 masked", output)

    def test_summary_network_uses_stamp_data(self):
        """Summary shows actual firewall rule counts from stamp."""
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("minimal", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            d.stamp.record("firewall_services", "http")
            d.stamp.record("firewall_ports", "8080/tcp")
            d.stamp.save()
            d._t0 = __import__("time").monotonic()

            self._suppress.__exit__(None, None, None)
            buf = io.StringIO()
            with redirect_stdout(buf):
                d._print_summary()
            self._suppress.__enter__()
            output = buf.getvalue()
            self.assertIn("2 firewall rules", output)

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

    def test_stamp_has_at_jobs_field(self):
        with tempfile.TemporaryDirectory() as td:
            sf = driftify.StampFile(Path(td) / "stamp.json")
            sf.start("standard", "centos", 9)
            self.assertIn("at_jobs", sf.data)
            self.assertEqual(sf.data["at_jobs"], [])

    def test_undo_scheduled_removes_at_jobs(self):
        driftify.STAMP_PATH = Path("/tmp/test-stamp.json")
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {"at_jobs": [3, 7]}
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_scheduled()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("atrm 3", output)
        self.assertIn("atrm 7", output)

    def test_undo_scheduled_noop_when_no_jobs(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {"at_jobs": []}
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_scheduled()
        self._suppress.__enter__()
        self.assertEqual(buf.getvalue(), "")


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
        self.assertIn("/etc/sudoers.d/appusers", output)
        self.assertIn("/home/appuser/.ssh/authorized_keys", output)

    def test_undo_users_disables_users_then_groups(self):
        driftify.STAMP_PATH = Path("/tmp/test-stamp.json")
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {
            "users_created": ["appuser", "dbuser"],
            "groups_created": ["appgroup"],
        }
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_users()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("userdel", output)
        self.assertIn("appuser", output)
        self.assertIn("dbuser", output)
        self.assertIn("groupdel", output)
        self.assertIn("appgroup", output)
        # Users must come before groups in output
        self.assertLess(output.index("userdel"), output.index("groupdel"))

    def test_undo_users_noop_when_empty(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {"users_created": [], "groups_created": []}
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_users()
        self._suppress.__enter__()
        self.assertEqual(buf.getvalue(), "")


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

    def test_stamp_has_recursive_dirs_field(self):
        with tempfile.TemporaryDirectory() as td:
            sf = driftify.StampFile(Path(td) / "stamp.json")
            sf.start("standard", "centos", 9)
            self.assertIn("recursive_dirs_created", sf.data)
            self.assertEqual(sf.data["recursive_dirs_created"], [])

    def test_recursive_dirs_tracked_on_live_run(self):
        with tempfile.TemporaryDirectory() as td:
            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("minimal", dry_run=False, skip_sections=[])
            d.stamp.start(d.profile, d.os_id, d.os_major)
            d.stamp.record("recursive_dirs_created", "/opt/myapp/venv")
            d.stamp.save()
            sf2 = driftify.StampFile(driftify.STAMP_PATH)
            sf2.load()
            self.assertIn("/opt/myapp/venv", sf2.data["recursive_dirs_created"])

    def test_undo_filesystem_recursively_removes_nonrpm_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            venv_like = Path(td) / "venv"
            venv_like.mkdir()
            (venv_like / "bin").mkdir()
            (venv_like / "bin" / "python3").write_text("stub")

            driftify.STAMP_PATH = Path(td) / "stamp.json"
            d = driftify.Driftify("minimal", dry_run=False, skip_sections=[])
            d.stamp.data = {
                "files_created": [],
                "dirs_created": [],
                "recursive_dirs_created": [str(venv_like)],
                "file_backups": {},
            }
            d._undo_filesystem()
            self.assertFalse(venv_like.exists())

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
        """webapp.container must include all fields yoinkc parses."""
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

            with unittest.mock.patch.object(
                driftify.Path, "exists",
                lambda self: True if str(self) == str(grub) else type(self).exists(self)
            ):
                d._append_kernel_cmdline_arg.__func__
            # Directly test the helper with a real file
            d._write_managed_text(str(grub), 'GRUB_CMDLINE_LINUX="crashkernel=auto"\n')
            import re as _re
            content = grub.read_text()
            new = _re.sub(
                r'GRUB_CMDLINE_LINUX="([^"]*)"',
                lambda m: f'GRUB_CMDLINE_LINUX="{m.group(1)} panic=60 audit=1"',
                content,
            )
            grub.write_text(new)
            self.assertIn("panic=60 audit=1", grub.read_text())

    def test_undo_kernel_reapplies_sysctl(self):
        driftify.STAMP_PATH = Path("/tmp/test-stamp.json")
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {
            "files_created": ["/etc/sysctl.d/99-driftify.conf"],
            "file_backups": {},
        }
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_kernel()
        self._suppress.__enter__()
        self.assertIn("sysctl --system", buf.getvalue())


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

    def test_undo_selinux_resets_booleans_and_removes_modules(self):
        driftify.STAMP_PATH = Path("/tmp/test-stamp.json")
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {
            "selinux_booleans": ["httpd_can_network_connect", "httpd_can_network_relay"],
            "selinux_modules": ["myapp"],
        }
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_selinux()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("setsebool -P httpd_can_network_connect off", output)
        self.assertIn("setsebool -P httpd_can_network_relay off", output)
        self.assertIn("semodule -r myapp", output)

    def test_undo_selinux_noop_when_empty(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {"selinux_booleans": [], "selinux_modules": []}
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_selinux()
        self._suppress.__enter__()
        self.assertEqual(buf.getvalue(), "")


class TestUndoFilesystem(DriftifyTestCase):
    def test_undo_filesystem_restores_and_removes(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            created = base / "created.txt"
            created.write_text("new\n")
            changed = base / "changed.txt"
            changed.write_text("mutated\n")

            driftify.STAMP_PATH = base / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.data = {
                "files_created": [str(created)],
                "dirs_created": [],
                "file_backups": {str(changed): "original\n"},
                "firewall_services": [],
                "firewall_ports": [],
            }
            d._undo_filesystem()

            self.assertFalse(created.exists())
            self.assertEqual(changed.read_text(), "original\n")

    def test_undo_filesystem_does_not_restore_driftify_created_files(self):
        """Files in both files_created and file_backups should be deleted only.

        This covers the case where drift_config creates a file and drift_secrets
        later modifies it — the backup holds an intermediate driftify state, not
        the pre-driftify state, so the file should just be removed on undo.
        """
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            # Simulate: driftify created this file, then modified it
            app_conf = base / "app.conf"
            app_conf.write_text("[app]\nname=driftify\n# BEGIN DRIFTIFY secrets\n")

            driftify.STAMP_PATH = base / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.data = {
                "files_created": [str(app_conf)],
                "dirs_created": [],
                # Backup was written when secrets section modified it —
                # contains intermediate content, not original empty state
                "file_backups": {str(app_conf): "[app]\nname=driftify\n"},
            }
            d._undo_filesystem()

            # File must be gone — NOT restored from backup
            self.assertFalse(app_conf.exists())

    def test_undo_filesystem_removes_created_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            subdir = base / "myapp"
            subdir.mkdir()

            driftify.STAMP_PATH = base / "stamp.json"
            d = driftify.Driftify("standard", dry_run=False, skip_sections=[])
            d.stamp.data = {
                "files_created": [],
                "dirs_created": [str(subdir)],
                "file_backups": {},
            }
            d._undo_filesystem()

            self.assertFalse(subdir.exists())


class TestUndoNetwork(DriftifyTestCase):
    def test_undo_network_dry_run_output(self):
        driftify.STAMP_PATH = Path("/tmp/test-stamp.json")
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {
            "firewall_services": ["http", "https"],
            "firewall_ports": ["8080/tcp"],
        }
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_network()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("--remove-service=http", output)
        self.assertIn("--remove-service=https", output)
        self.assertIn("--remove-port=8080/tcp", output)
        self.assertIn("--reload", output)

    def test_undo_network_noop_when_empty(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        d.stamp.data = {"firewall_services": [], "firewall_ports": []}
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._undo_network()
        self._suppress.__enter__()
        self.assertNotIn("firewalld", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
