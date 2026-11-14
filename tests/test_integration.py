"""
End-to-end integration tests for Exploidus EDR.

Uses TEST_MALWARE_BYTES (harmless synthetic bytes) instead of real EICAR
so that Windows Defender does not quarantine test files before Exploidus EDR reads them.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from edr.engine.scanner import Scanner, ThreatLevel
from edr.quarantine.vault import QuarantineVault
from edr.reports.logger import ScanLogger
from tests.conftest import (
    TEST_MALWARE_BYTES, TEST_MALWARE_MD5, TEST_MALWARE_SHA256, TEST_MALWARE_NAME,
)


class TestFullScanPipeline:
    def test_scan_and_quarantine_eicar(self, config, tmp_path):
        """Scan detects threat, quarantine vault moves it, log records it."""
        malware = tmp_path / "malware.com"
        malware.write_bytes(TEST_MALWARE_BYTES)

        scanner = Scanner(config)
        vault   = QuarantineVault(Path(config.quarantine_dir))
        log     = ScanLogger(Path(config.log_dir))

        result = scanner.scan_file(malware)

        # Detection
        assert result.threat_level == ThreatLevel.MALICIOUS
        assert result.threat_name  == TEST_MALWARE_NAME

        # Quarantine
        entry = vault.quarantine(malware, result.threat_name, result.md5, result.sha256)
        assert not malware.exists()
        assert vault.count == 1

        # Restore
        restored = vault.restore(entry.id)
        assert restored.exists()
        assert vault.count == 0

        # Log contains the threat
        threats = log.get_threats()
        assert any(t["threat_name"] == TEST_MALWARE_NAME for t in threats)

    def test_scan_directory_counts_correctly(self, config, tmp_path):
        """Scan of a mixed directory reports correct threat vs clean count."""
        scan_dir = tmp_path / "files"
        scan_dir.mkdir()

        for i in range(3):
            (scan_dir / f"clean{i}.txt").write_bytes(b"totally fine " * 10)
        (scan_dir / "malware.com").write_bytes(TEST_MALWARE_BYTES)

        scanner = Scanner(config)
        results = list(scanner.scan_directory(scan_dir))

        threats = [r for r in results if r.is_threat]
        clean   = [r for r in results if r.is_clean]

        assert len(threats) == 1
        assert len(clean)   == 3
        assert threats[0].threat_name == TEST_MALWARE_NAME

    def test_heuristic_threat_logged(self, config, tmp_path):
        """A heuristically detected file gets logged properly."""
        bad = tmp_path / "evil.ps1"
        bad.write_bytes(
            b"powershell -EncodedCommand AAABBB\n"
            b"Invoke-Expression $payload\n"
            b"FromBase64String('SGVsbG8=')\n"
        )

        scanner = Scanner(config)
        result  = scanner.scan_file(bad)

        assert result.is_threat
        assert result.heuristic is not None
        assert result.heuristic.score > 0

        log = ScanLogger(Path(config.log_dir))
        threats = log.get_threats()
        assert any(t["path"] == str(bad) for t in threats)

    def test_clean_file_not_in_threat_log(self, config, tmp_path):
        """Clean files should not appear in the threat log."""
        clean = tmp_path / "normal.txt"
        clean.write_bytes(b"I am clean " * 50)

        scanner = Scanner(config)
        scanner.scan_file(clean)

        log = ScanLogger(Path(config.log_dir))
        threats = log.get_threats()
        assert all(t["path"] != str(clean) for t in threats)

    def test_multiple_eicar_all_detected(self, config, tmp_path):
        """Every copy of the threat file in a directory should be detected."""
        scan_dir = tmp_path / "many"
        scan_dir.mkdir()
        for i in range(5):
            (scan_dir / f"malware_{i}.com").write_bytes(TEST_MALWARE_BYTES)

        scanner  = Scanner(config)
        results  = list(scanner.scan_directory(scan_dir))
        detected = [r for r in results if r.threat_level == ThreatLevel.MALICIOUS]
        assert len(detected) == 5

    def test_excluded_path_skipped(self, config, tmp_path):
        """Files under excluded_paths should not be scanned."""
        excluded = tmp_path / "system"
        excluded.mkdir()
        (excluded / "malware.com").write_bytes(TEST_MALWARE_BYTES)

        config.excluded_paths = [str(excluded)]
        scanner = Scanner(config)
        results = list(scanner.scan_directory(tmp_path))
        threats = [r for r in results if r.is_threat]
        assert len(threats) == 0

    def test_scan_result_has_all_fields(self, config, eicar_file):
        scanner = Scanner(config)
        result  = scanner.scan_file(eicar_file)

        assert result.path
        assert result.scanned_at > 0
        assert result.md5    == TEST_MALWARE_MD5
        assert result.sha256 == TEST_MALWARE_SHA256
        assert result.scan_duration_ms >= 0
        assert result.heuristic is not None