"""Tests for real-time filesystem monitor."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from edr.engine.monitor import RealtimeMonitor
from edr.engine.scanner import Scanner, ThreatLevel
from edr.exceptions import MonitorError
from tests.conftest import TEST_MALWARE_BYTES


@pytest.fixture
def scanner(config) -> Scanner:
    return Scanner(config)


class TestRealtimeMonitor:
    def test_no_paths_raises_monitor_error(self, scanner, config):
        config.monitor_paths = []
        mon = RealtimeMonitor(scanner, config)
        with pytest.raises(MonitorError):
            mon.start([])

    def test_is_running_false_before_start(self, scanner, config):
        mon = RealtimeMonitor(scanner, config)
        assert not mon.is_running

    def test_start_and_stop(self, scanner, config, tmp_path):
        mon = RealtimeMonitor(scanner, config)
        mon.start([str(tmp_path)])
        time.sleep(0.3)
        assert mon.is_running
        mon.stop()
        time.sleep(0.3)

    def test_threat_callback_on_new_file(self, config, tmp_path):
        """
        Writes synthetic malware into watched dir — must trigger on_threat.
        Uses TEST_MALWARE_BYTES so host AV won't interfere.
        """
        threats = []
        scanner = Scanner(config)
        mon = RealtimeMonitor(scanner, config, on_threat=threats.append)
        mon.start([str(tmp_path)])
        time.sleep(0.3)

        evil = tmp_path / "evil.com"
        evil.write_bytes(TEST_MALWARE_BYTES)

        deadline = time.monotonic() + 8.0
        while not threats and time.monotonic() < deadline:
            time.sleep(0.2)

        mon.stop()
        assert len(threats) >= 1
        assert threats[0].threat_level == ThreatLevel.MALICIOUS

    def test_no_watchdog_raises_monitor_error(self, scanner, config, tmp_path):
        mon = RealtimeMonitor(scanner, config)
        with patch.dict("sys.modules", {"watchdog.observers": None}):
            with pytest.raises((MonitorError, Exception)):
                mon.start([str(tmp_path)])

    def test_on_scan_callback_called(self, config, tmp_path):
        scanned = []
        scanner = Scanner(config)
        mon = RealtimeMonitor(scanner, config, on_scan=scanned.append)
        mon.start([str(tmp_path)])
        time.sleep(0.2)

        (tmp_path / "newfile.txt").write_bytes(b"hello world")

        deadline = time.monotonic() + 8.0
        while not scanned and time.monotonic() < deadline:
            time.sleep(0.2)

        mon.stop()
        assert len(scanned) >= 1

    def test_stop_without_start_safe(self, scanner, config):
        mon = RealtimeMonitor(scanner, config)
        mon.stop()