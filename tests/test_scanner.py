"""Tests for the core scan engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from edr.engine.scanner import Scanner, ScanResult, ThreatLevel
from tests.conftest import TEST_MALWARE_MD5, TEST_MALWARE_SHA256, TEST_MALWARE_NAME


class TestScanResult:
    def test_default_is_clean(self):
        r = ScanResult(path="/tmp/test.txt")
        assert r.is_clean
        assert not r.is_threat

    def test_malicious_is_threat(self):
        r = ScanResult(path="/tmp/x", threat_level=ThreatLevel.MALICIOUS)
        assert r.is_threat
        assert not r.is_clean

    def test_suspicious_is_threat(self):
        r = ScanResult(path="/tmp/x", threat_level=ThreatLevel.SUSPICIOUS)
        assert r.is_threat


class TestScanner:
    def test_scanner_initializes(self, config):
        scanner = Scanner(config)
        # Builtin EICAR sigs + our 2 synthetic test sigs
        assert scanner.signature_count >= 3

    def test_clean_file_result(self, config, clean_file):
        scanner = Scanner(config)
        result = scanner.scan_file(clean_file)
        assert isinstance(result, ScanResult)
        assert result.is_clean
        assert result.error is None

    def test_eicar_detected_as_malicious(self, config, eicar_file):
        """eicar_file fixture uses synthetic bytes registered in test sig DB."""
        scanner = Scanner(config)
        result = scanner.scan_file(eicar_file)
        assert result.threat_level == ThreatLevel.MALICIOUS
        assert result.threat_name == TEST_MALWARE_NAME

    def test_eicar_md5_populated(self, config, eicar_file):
        scanner = Scanner(config)
        result = scanner.scan_file(eicar_file)
        assert result.md5 == TEST_MALWARE_MD5

    def test_eicar_sha256_populated(self, config, eicar_file):
        scanner = Scanner(config)
        result = scanner.scan_file(eicar_file)
        assert result.sha256 == TEST_MALWARE_SHA256

    def test_scan_duration_recorded(self, config, clean_file):
        scanner = Scanner(config)
        result = scanner.scan_file(clean_file)
        assert result.scan_duration_ms >= 0

    def test_missing_file_returns_error(self, config, tmp_path):
        scanner = Scanner(config)
        result = scanner.scan_file(tmp_path / "ghost.exe")
        assert result.error is not None

    def test_file_too_large_skipped(self, config, tmp_path):
        config.max_file_size_mb = 0
        p = tmp_path / "big.bin"
        p.write_bytes(b"x" * 1024)
        scanner = Scanner(config)
        result = scanner.scan_file(p)
        assert result.error is not None

    def test_excluded_extension_skipped(self, config, tmp_path):
        config.excluded_extensions = [".log"]
        p = tmp_path / "debug.log"
        p.write_bytes(b"some log content")
        scanner = Scanner(config)
        result = scanner.scan_file(p)
        assert result.error == "Excluded extension"

    def test_scan_directory_yields_results(self, config, tmp_path):
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "a.txt").write_bytes(b"clean content a")
        (scan_dir / "b.txt").write_bytes(b"clean content b")
        scanner = Scanner(config)
        results = list(scanner.scan_directory(scan_dir, recursive=False))
        assert len(results) == 2

    def test_scan_directory_recursive(self, tmp_path):
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        sub = scan_dir / "sub"
        sub.mkdir()
        (scan_dir / "root.txt").write_bytes(b"root")
        (sub / "deep.txt").write_bytes(b"deep")
        from edr.config import Config
        cfg = Config(
            log_dir         = str(tmp_path / "logs"),
            signature_db    = str(tmp_path / "sigs.json"),
            quarantine_dir  = str(tmp_path / "q"),
            yara_rules_dir  = str(tmp_path / "rules"),
            clamav_cache_dir= str(tmp_path / "clamav"),
        )
        scanner = Scanner(cfg)
        results = list(scanner.scan_directory(scan_dir, recursive=True))
        assert len(results) == 2

    def test_scan_paths_mixed(self, config, tmp_path):
        f1 = tmp_path / "file1.txt"
        f1.write_bytes(b"clean1")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "file2.txt").write_bytes(b"clean2")
        scanner = Scanner(config)
        results = list(scanner.scan_paths([f1, sub]))
        assert len(results) == 2

    def test_scan_callback_called(self, config, tmp_path):
        p = tmp_path / "cb.txt"
        p.write_bytes(b"data")
        scanner = Scanner(config)
        collected = []
        list(scanner.scan_paths([p], callback=collected.append))
        assert len(collected) == 1

    def test_suspicious_script_flagged(self, config, suspicious_script):
        scanner = Scanner(config)
        result = scanner.scan_file(suspicious_script)
        assert result.is_threat

    def test_heuristic_populated(self, config, suspicious_script):
        scanner = Scanner(config)
        result = scanner.scan_file(suspicious_script)
        assert result.heuristic is not None