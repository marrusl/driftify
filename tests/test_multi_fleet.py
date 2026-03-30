"""Tests for multi-fleet topology fixture generation."""

import json
import tarfile
import pytest
from pathlib import Path

from driftify import FLEET_TOPOLOGIES, generate_fleet_topology, build_topology_parser


class TestFleetTopologies:
    def test_three_role_overlap_topology_exists(self):
        assert "three-role-overlap" in FLEET_TOPOLOGIES

    def test_hardware_split_topology_exists(self):
        assert "hardware-split" in FLEET_TOPOLOGIES

    def test_three_role_overlap_has_three_fleets(self):
        topo = FLEET_TOPOLOGIES["three-role-overlap"]
        assert len(topo["fleets"]) == 3

    def test_hardware_split_has_two_fleets(self):
        topo = FLEET_TOPOLOGIES["hardware-split"]
        assert len(topo["fleets"]) == 2

    def test_each_fleet_has_hosts(self):
        for name, topo in FLEET_TOPOLOGIES.items():
            for fleet in topo["fleets"]:
                assert len(fleet["hosts"]) >= 3, f"{name}/{fleet['name']} needs 3+ hosts"

    def test_fleets_have_shared_packages(self):
        topo = FLEET_TOPOLOGIES["three-role-overlap"]
        all_pkg_sets = [set(f["shared_packages"] + f["exclusive_packages"]) for f in topo["fleets"]]
        shared = all_pkg_sets[0]
        for s in all_pkg_sets[1:]:
            shared = shared & s
        assert len(shared) > 10

    def test_fleets_have_exclusive_packages(self):
        topo = FLEET_TOPOLOGIES["three-role-overlap"]
        for fleet in topo["fleets"]:
            assert len(fleet["exclusive_packages"]) >= 3, f"{fleet['name']} needs exclusive pkgs"

    def test_exclusive_packages_dont_overlap(self):
        topo = FLEET_TOPOLOGIES["three-role-overlap"]
        exclusive_sets = [set(f["exclusive_packages"]) for f in topo["fleets"]]
        for i, s1 in enumerate(exclusive_sets):
            for j, s2 in enumerate(exclusive_sets):
                if i != j:
                    overlap = s1 & s2
                    assert not overlap, f"Fleets {i} and {j} share exclusive pkg: {overlap}"


class TestGenerateFleetTopology:
    def test_generates_fleet_tarballs(self, tmp_path):
        generate_fleet_topology("three-role-overlap", tmp_path)
        tarballs = sorted(tmp_path.glob("*.tar.gz"))
        assert len(tarballs) == 3
        assert [t.stem.replace(".tar", "") for t in tarballs] == ["app", "db", "web"]

    def test_tarball_contains_inspection_snapshot(self, tmp_path):
        generate_fleet_topology("three-role-overlap", tmp_path)
        for tarball in tmp_path.glob("*.tar.gz"):
            with tarfile.open(tarball, "r:gz") as tf:
                names = tf.getnames()
                assert "inspection-snapshot.json" in names

    def test_snapshot_has_fleet_metadata(self, tmp_path):
        generate_fleet_topology("three-role-overlap", tmp_path)
        tarball = tmp_path / "web.tar.gz"
        with tarfile.open(tarball, "r:gz") as tf:
            snap = json.load(tf.extractfile("inspection-snapshot.json"))
        assert snap["meta"]["hostname"] == "web"
        assert snap["meta"]["fleet"]["total_hosts"] == 4
        assert "web-prod-01" in snap["meta"]["fleet"]["source_hosts"]

    def test_snapshot_has_correct_packages(self, tmp_path):
        generate_fleet_topology("three-role-overlap", tmp_path)
        for tarball in tmp_path.glob("*.tar.gz"):
            with tarfile.open(tarball, "r:gz") as tf:
                snap = json.load(tf.extractfile("inspection-snapshot.json"))
            pkgs = {p["name"] for p in snap["rpm"]["packages_added"]}
            # All fleets should have shared base packages
            assert "coreutils" in pkgs

    def test_hardware_split_generates_two_tarballs(self, tmp_path):
        generate_fleet_topology("hardware-split", tmp_path)
        tarballs = list(tmp_path.glob("*.tar.gz"))
        assert len(tarballs) == 2

    def test_invalid_topology_name_raises(self):
        with pytest.raises(ValueError, match="Unknown topology"):
            generate_fleet_topology("nonexistent", Path("/tmp"))


class TestTopologyCLI:
    def test_parse_positional_args(self):
        parser = build_topology_parser()
        args = parser.parse_args(["three-role-overlap", "/tmp/out"])
        assert args.topology_name == "three-role-overlap"
        assert args.output_dir == "/tmp/out"

    def test_parse_list_flag(self):
        parser = build_topology_parser()
        args = parser.parse_args(["--list"])
        assert args.list is True
        assert args.topology_name is None

    def test_list_flag_with_no_positionals(self):
        parser = build_topology_parser()
        args = parser.parse_args(["--list"])
        assert args.list is True
        assert args.output_dir is None

    def test_parse_hardware_split(self):
        parser = build_topology_parser()
        args = parser.parse_args(["hardware-split", "/tmp/hw"])
        assert args.topology_name == "hardware-split"
        assert args.output_dir == "/tmp/hw"
