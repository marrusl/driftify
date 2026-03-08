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

    def test_run_yoinkc_flag_parsed(self):
        p = driftify.build_parser()
        args = p.parse_args(["--run-yoinkc"])
        self.assertTrue(args.run_yoinkc)
        self.assertEqual(args.yoinkc_output, "./yoinkc-output")
        args = p.parse_args(["--run-yoinkc", "--yoinkc-output", "/tmp/out"])
        self.assertEqual(args.yoinkc_output, "/tmp/out")
        args = p.parse_args([])
        self.assertFalse(args.run_yoinkc)

    def test_launch_yoinkc_dry_run(self):
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[],
                              run_yoinkc=True, yoinkc_output="/tmp/test-out")
        self._suppress.__exit__(None, None, None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            d._launch_yoinkc()
        self._suppress.__enter__()
        output = buf.getvalue()
        self.assertIn("run-yoinkc.sh", output)
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
        # Standard profile adds a masked service
        self.assertIn("1 masked", output)
        # Users section should show users and groups
        self.assertIn("2 user(s)", output)
        self.assertIn("1 group(s)", output)
        # Scheduled section should list cron files
        self.assertIn("2 cron files", output)

