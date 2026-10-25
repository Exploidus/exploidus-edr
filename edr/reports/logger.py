"""Structured logging for Exploidus EDR scan results."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from edr.engine.scanner import ScanResult

logger = logging.getLogger(__name__)


def setup_logging(log_dir: Path, level: int = logging.INFO) -> None:
    """Configure root logger to write to both file and console."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "edr.log"

    fmt = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(fmt, datefmt))

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(fmt, datefmt))

    root = logging.getLogger()
    root.setLevel(level)
    # Avoid duplicate handlers if called more than once
    if not root.handlers:
        root.addHandler(file_handler)
        root.addHandler(console_handler)


class ScanLogger:
    """Appends scan results to a newline-delimited JSON file."""

    def __init__(self, log_dir: Path) -> None:
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._results_file = self._log_dir / "scan_results.jsonl"

    def log_result(self, result: "ScanResult") -> None:
        record = {
            "path": result.path,
            "scanned_at": result.scanned_at,
            "threat_level": result.threat_level.value,
            "threat_name": result.threat_name,
            "md5": result.md5,
            "sha256": result.sha256,
            "yara_matches": result.yara_matches,
            "heuristic_score": result.heuristic.score if result.heuristic else 0,
            "heuristic_flags": result.heuristic.flags if result.heuristic else [],
            "error": result.error,
            "scan_duration_ms": round(result.scan_duration_ms, 2),
        }
        try:
            with open(self._results_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as exc:
            logger.error("Cannot write scan log: %s", exc)

    def get_all(self, limit: int = 500) -> List[dict]:
        """Return the most recent scan records."""
        if not self._results_file.exists():
            return []
        records = []
        with open(self._results_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records[-limit:]

    def get_threats(self, limit: int = 100) -> List[dict]:
        """Return only records where a threat was detected."""
        return [r for r in self.get_all(limit * 5) if r.get("threat_level") != "clean"][-limit:]

    def clear(self) -> None:
        if self._results_file.exists():
            self._results_file.unlink()
