"""Tests for multi-fleet topology fixture generation."""

import json
import pytest
from pathlib import Path

from driftify import FLEET_TOPOLOGIES, generate_fleet_topology


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
    def test_generates_output_directory(self, tmp_path):
        generate_fleet_topology("three-role-overlap", tmp_path)
        fleet_dirs = [d for d in tmp_path.iterdir() if d.is_dir()]
        assert len(fleet_dirs) == 3

    def test_each_fleet_dir_has_host_snapshots(self, tmp_path):
        generate_fleet_topology("three-role-overlap", tmp_path)
        for fleet_dir in tmp_path.iterdir():
            if not fleet_dir.is_dir():
                continue
            json_files = list(fleet_dir.glob("*.json"))
            assert len(json_files) >= 3

    def test_hosts_within_fleet_share_packages(self, tmp_path):
        generate_fleet_topology("three-role-overlap", tmp_path)
        for fleet_dir in tmp_path.iterdir():
            if not fleet_dir.is_dir():
                continue
            snapshots = []
            for f in fleet_dir.glob("*.json"):
                snapshots.append(json.loads(f.read_text()))
            if len(snapshots) < 2:
                continue
            pkg_sets = []
            for snap in snapshots:
                pkgs = {p["name"] for p in snap.get("rpm", {}).get("packages_added", [])}
                pkg_sets.append(pkgs)
            for ps in pkg_sets[1:]:
                assert ps == pkg_sets[0], f"Hosts in {fleet_dir.name} have different packages"

    def test_hosts_have_different_hostnames(self, tmp_path):
        generate_fleet_topology("three-role-overlap", tmp_path)
        for fleet_dir in tmp_path.iterdir():
            if not fleet_dir.is_dir():
                continue
            hostnames = set()
            for f in fleet_dir.glob("*.json"):
                snap = json.loads(f.read_text())
                hostnames.add(snap["meta"]["hostname"])
            assert len(hostnames) >= 3

    def test_invalid_topology_name_raises(self):
        with pytest.raises(ValueError, match="Unknown topology"):
            generate_fleet_topology("nonexistent", Path("/tmp"))
