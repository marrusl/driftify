import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import driftify

_DEVNULL = open(os.devnull, "w")


class DriftifyTestCase(unittest.TestCase):
    """Base class that patches detect_os and suppresses log output."""

    def setUp(self):
        self.original_stamp_path = driftify.STAMP_PATH
        self.original_detect_os = driftify.detect_os
        driftify.detect_os = lambda: ("centos", 9)
        self._suppress = redirect_stdout(_DEVNULL)
        self._suppress.__enter__()

    def tearDown(self):
        self._suppress.__exit__(None, None, None)
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
        d = driftify.Driftify("standard", dry_run=True, skip_sections=[])
        self.assertEqual(d._total, 6)

        d = driftify.Driftify("standard", dry_run=True, skip_sections=["network", "storage"])
        self.assertEqual(d._total, 4)

        d = driftify.Driftify(
            "standard",
            dry_run=True,
            skip_sections=["rpm", "services", "config", "network", "storage", "secrets"],
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
