"""
Behavioral analysis engine for Exploidus EDR.

Monitors running processes for suspicious activity patterns entirely locally,
with no external API calls.

Detection categories
--------------------
  - Suspicious process command-line arguments
  - Known malicious process names
  - Processes running from temp/user directories
  - Unusual parent-child process relationships
  - High CPU anomalies indicative of crypto-miners
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

# Module-level import so tests can patch it
try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Suspicious command-line patterns
# ---------------------------------------------------------------------------

_CMD_PATTERNS = [
    (re.compile(r"-[Ee]ncodedCommand\s+\S+", re.I),        "Encoded PowerShell command", 40),
    (re.compile(r"Invoke-Expression|IEX\(", re.I),          "PowerShell IEX invocation", 35),
    (re.compile(r"execution.{0,10}policy.{0,10}bypass|bypass.{0,10}execution", re.I),
                                                             "ExecutionPolicy bypass", 30),
    (re.compile(r"FromBase64String", re.I),                  "Base64 decode in command", 25),
    (re.compile(r"Net\.WebClient|WebClient\(\)", re.I),      "WebClient download", 30),
    (re.compile(r"DownloadFile|DownloadString", re.I),       "File download via .NET", 30),
    (re.compile(r"mshta\.exe|mshta\b", re.I),               "MSHTA execution", 35),
    (re.compile(r"regsvr32.*scrobj", re.I),                  "Regsvr32 COM scriptlet", 40),
    (re.compile(r"certutil.*(decode|urlcache)", re.I),       "Certutil abuse", 40),
    (re.compile(r"wmic.*process.*create", re.I),             "WMIC process creation", 35),
    (re.compile(r"vssadmin.*delete.*shadows", re.I),         "Shadow copy deletion (ransomware)", 80),
    (re.compile(r"bcdedit.*recoveryenabled.*no", re.I),      "Boot recovery disabled (ransomware)", 80),
    (re.compile(r"netsh.*firewall.*disable", re.I),          "Firewall disabled", 50),
    (re.compile(r"sc\s+stop\s+", re.I),                     "Service stopped via sc.exe", 20),
    (re.compile(r"taskkill.*\/f.*(av|antivirus)", re.I),    "AV process killed", 70),
    (re.compile(r"mimikatz|sekurlsa|lsadump", re.I),        "Mimikatz credential dump", 90),
    (re.compile(r"meterpreter|reverse_tcp|bind_tcp", re.I), "Metasploit payload", 90),
]

_SUSPICIOUS_CHILD_PROCS = {
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "installutil.exe", "msiexec.exe",
}

_TEMP_DIR_PATTERNS = [
    re.compile(r"\\Users\\Public\\", re.I),
    re.compile(r"\\AppData\\Local\\Temp\\", re.I),
    re.compile(r"\\AppData\\Roaming\\", re.I),
    re.compile(r"\\ProgramData\\[^\\]+\\[^\\]+\.exe", re.I),
    re.compile(r"\\Downloads\\[^\\]+\.exe", re.I),
]

_SCAN_INTERVAL = 30


@dataclass
class BehaviorAlert:
    pid: int
    process_name: str
    exe_path: str
    score: int
    flags: List[str] = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)

    @property
    def verdict(self) -> str:
        if self.score >= 70:
            return "malicious"
        if self.score >= 40:
            return "suspicious"
        return "clean"


def _score_process(proc) -> BehaviorAlert:
    try:
        name = proc.name()
        exe  = proc.exe() or ""
        cmdline = " ".join(proc.cmdline()) if proc.cmdline() else ""
    except Exception:
        return BehaviorAlert(pid=proc.pid, process_name="?", exe_path="", score=0)

    alert = BehaviorAlert(pid=proc.pid, process_name=name, exe_path=exe, score=0)

    for pattern, label, weight in _CMD_PATTERNS:
        if pattern.search(cmdline):
            alert.flags.append(label)
            alert.score += weight

    for pat in _TEMP_DIR_PATTERNS:
        if pat.search(exe):
            alert.flags.append(f"Executable in suspicious path: {exe}")
            alert.score += 25
            break

    if name.lower() in _SUSPICIOUS_CHILD_PROCS:
        try:
            parent = proc.parent()
            if parent:
                parent_name = parent.name().lower()
                if parent_name in {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}:
                    alert.flags.append(
                        f"Office app ({parent_name}) spawned {name} (macro malware)"
                    )
                    alert.score += 60
        except Exception:
            pass

    try:
        cpu = proc.cpu_percent(interval=0.1)
        if cpu > 80 and name.lower() not in {
            "ffmpeg.exe", "blender.exe", "handbrake.exe", "7z.exe"
        }:
            alert.flags.append(f"High CPU usage ({cpu:.0f}%) - possible crypto-miner")
            alert.score += 20
    except Exception:
        pass

    alert.score = min(100, alert.score)
    return alert


class BehaviorMonitor:
    def __init__(
        self,
        on_alert: Optional[Callable[[BehaviorAlert], None]] = None,
        scan_interval: float = 10.0,
    ) -> None:
        self._on_alert = on_alert
        self._scan_interval = scan_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen: Dict[int, float] = {}

    def _run(self) -> None:
        if psutil is None:
            logger.warning("psutil not installed; behavioral monitoring disabled.")
            return

        logger.info("Behavioral monitor started")
        while not self._stop.is_set():
            now = time.monotonic()
            try:
                for proc in psutil.process_iter(["pid", "name"]):
                    pid = proc.pid
                    if now - self._seen.get(pid, 0) < _SCAN_INTERVAL:
                        continue
                    self._seen[pid] = now
                    alert = _score_process(proc)
                    if alert.verdict != "clean" and self._on_alert:
                        self._on_alert(alert)
            except Exception as exc:
                logger.debug("Behavior scan error: %s", exc)
            self._stop.wait(self._scan_interval)
        logger.info("Behavioral monitor stopped")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="edr-behavior", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


def scan_all_processes() -> List[BehaviorAlert]:
    if psutil is None:
        logger.warning("psutil not installed; run: pip install psutil")
        return []
    alerts = []
    for proc in psutil.process_iter(["pid", "name"]):
        alert = _score_process(proc)
        if alert.verdict != "clean":
            alerts.append(alert)
    return alerts
