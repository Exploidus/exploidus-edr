"""Tests for structured scan logging."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from edr.engine.scanner import ScanResult, ThreatLevel
from edr.engine.heuristics import HeuristicResult
from edr.reports.logger import ScanLogger


@pytest.fixture
def logger(tmp_path: Path) -> ScanLogger:
    return ScanLogger(tmp_path / "logs")


def _make_result(
    path="/tmp/test.exe",
    level=ThreatLevel.CLEAN,
    threat_name=None,
    md5="aabbccdd",
    sha256="eeffgghh",
    yara=None,
    score=0,
) -> ScanResult:
    h = HeuristicResult()
    h.score = score
    return ScanResult(
        path=path,
        threat_level=level,
        threat_name=threat_name,
        md5=md5,
        sha256=sha256,
        yara_matches=yara or [],
        heuristic=h,
        scan_duration_ms=1.5,
    )


class TestScanLogger:
    def test_log_creates_file(self, logger, tmp_path):
        logger.log_result(_make_result())
        assert (tmp_path / "logs" / "scan_results.jsonl").exists()

    def test_log_writes_valid_json(self, logger):
        logger.log_result(_make_result())
        line = (logger._results_file).read_text().strip()
        record = json.loads(line)
        assert record["path"] == "/tmp/test.exe"

    def test_log_records_threat_level(self, logger):
        logger.log_result(_make_result(level=ThreatLevel.MALICIOUS, threat_name="X"))
        record = json.loads(logger._results_file.read_text().strip())
        assert record["threat_level"] == "malicious"
        assert record["threat_name"] == "X"

    def test_multiple_results_each_on_own_line(self, logger):
        for i in range(5):
            logger.log_result(_make_result(path=f"/tmp/file{i}.exe"))
        lines = logger._results_file.read_text().strip().splitlines()
        assert len(lines) == 5

    def test_get_all_returns_records(self, logger):
        for i in range(3):
            logger.log_result(_make_result(path=f"/tmp/f{i}"))
        records = logger.get_all()
        assert len(records) == 3

    def test_get_threats_filters_clean(self, logger):
        logger.log_result(_make_result(level=ThreatLevel.CLEAN))
        logger.log_result(_make_result(level=ThreatLevel.MALICIOUS, threat_name="T"))
        threats = logger.get_threats()
        assert len(threats) == 1
        assert threats[0]["threat_level"] == "malicious"

    def test_get_threats_respects_limit(self, logger):
        for i in range(10):
            logger.log_result(_make_result(level=ThreatLevel.MALICIOUS, threat_name="X"))
        threats = logger.get_threats(limit=3)
        assert len(threats) == 3

    def test_get_all_empty_when_no_file(self, logger):
        assert logger.get_all() == []

    def test_clear_removes_log(self, logger):
        logger.log_result(_make_result())
        logger.clear()
        assert not logger._results_file.exists()

    def test_heuristic_score_recorded(self, logger):
        logger.log_result(_make_result(score=75))
        record = json.loads(logger._results_file.read_text().strip())
        assert record["heuristic_score"] == 75

    def test_yara_matches_recorded(self, logger):
        logger.log_result(_make_result(yara=["SuspiciousPowerShell", "MimikatzStrings"]))
        record = json.loads(logger._results_file.read_text().strip())
        assert "SuspiciousPowerShell" in record["yara_matches"]

    def test_scan_duration_rounded(self, logger):
        r = _make_result()
        r.scan_duration_ms = 3.14159
        logger.log_result(r)
        record = json.loads(logger._results_file.read_text().strip())
        assert record["scan_duration_ms"] == 3.14
