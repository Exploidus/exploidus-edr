"""Core scan engine for Exploidus EDR."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Generator, List, Optional

from edr.config import Config
from edr.engine.heuristics import HeuristicResult, analyze as heuristic_analyze
from edr.engine.signatures import SignatureDatabase, compute_hashes
from edr.reports.logger import ScanLogger

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class ScanResult:
    path: str
    scanned_at: float = field(default_factory=time.time)
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    threat_name: Optional[str] = None
    md5: str = ""
    sha256: str = ""
    heuristic: Optional[HeuristicResult] = None
    yara_matches: List[str] = field(default_factory=list)
    error: Optional[str] = None
    scan_duration_ms: float = 0.0

    @property
    def is_clean(self) -> bool:
        return self.threat_level == ThreatLevel.CLEAN

    @property
    def is_threat(self) -> bool:
        return self.threat_level != ThreatLevel.CLEAN


class Scanner:
    """
    Multi-layer file scanner.

    Detection order:
      1. Hash signature match (MD5 / SHA256)
      2. YARA rule match
      3. Heuristic analysis (string patterns + PE analysis)
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.config._ensure_dirs()
        self._sig_db = SignatureDatabase(
            Path(self.config.signature_db) if self.config.signature_db else None
        )
        self._yara_rules = self._load_yara_rules()
        self._scan_logger = ScanLogger(Path(self.config.log_dir))
        logger.info(
            "Scanner initialized | signatures=%d | yara=%s",
            self._sig_db.count,
            "enabled" if self._yara_rules else "disabled",
        )

    def _load_yara_rules(self):
        rules_dir = Path(self.config.yara_rules_dir)
        if not rules_dir.exists():
            return None
        try:
            import yara

            rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
            if not rule_files:
                return None
            sources = {f.stem: str(f) for f in rule_files}
            compiled = yara.compile(filepaths=sources)
            logger.info("Loaded %d YARA rule file(s)", len(rule_files))
            return compiled
        except ImportError:
            logger.debug("yara-python not installed; YARA scanning disabled")
        except Exception as exc:
            logger.warning("Failed to compile YARA rules: %s", exc)
        return None

    def scan_file(self, path: Path) -> ScanResult:
        """Scan a single file through all detection layers."""
        start = time.perf_counter()
        result = ScanResult(path=str(path))

        if not path.exists() or not path.is_file():
            result.error = "File not found"
            return result

        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > self.config.max_file_size_mb:
            result.error = f"File too large ({size_mb:.1f} MB)"
            return result

        if path.suffix.lower() in self.config.excluded_extensions:
            result.error = "Excluded extension"
            return result

        try:
            # --- Layer 1: Signature ---
            hashes = compute_hashes(path)
            result.md5 = hashes["md5"]
            result.sha256 = hashes["sha256"]

            threat = self._sig_db.lookup_md5(result.md5) or self._sig_db.lookup_sha256(
                result.sha256
            )
            if threat:
                result.threat_level = ThreatLevel.MALICIOUS
                result.threat_name = threat

            # --- Layer 2: YARA ---
            if self._yara_rules and result.is_clean:
                try:
                    matches = self._yara_rules.match(str(path))
                    if matches:
                        result.yara_matches = [str(m) for m in matches]
                        result.threat_level = ThreatLevel.MALICIOUS
                        result.threat_name = f"YARA:{result.yara_matches[0]}"
                except Exception as exc:
                    logger.debug("YARA match failed for %s: %s", path, exc)

            # --- Layer 3: Heuristics ---
            heuristic = heuristic_analyze(path)
            result.heuristic = heuristic
            if result.is_clean:
                if heuristic.verdict == "malicious":
                    result.threat_level = ThreatLevel.MALICIOUS
                    first_flag = heuristic.flags[0] if heuristic.flags else "Unknown"
                    result.threat_name = f"Heuristic:{first_flag}"
                elif heuristic.verdict == "suspicious":
                    result.threat_level = ThreatLevel.SUSPICIOUS
                    result.threat_name = f"Heuristic:Suspicious (score={heuristic.score})"

        except Exception as exc:
            result.error = str(exc)
            logger.error("Scan error for %s: %s", path, exc)

        result.scan_duration_ms = (time.perf_counter() - start) * 1000
        self._scan_logger.log_result(result)

        if result.is_threat:
            logger.warning("THREAT | %s | %s", result.threat_level.value.upper(), path)

        return result

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = True,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """Yield ScanResult for every file in directory."""
        pattern = "**/*" if recursive else "*"
        for file_path in directory.glob(pattern):
            if not file_path.is_file():
                continue
            if any(
                str(file_path).startswith(excl) for excl in self.config.excluded_paths
            ):
                continue
            result = self.scan_file(file_path)
            if callback:
                callback(result)
            yield result

    def scan_paths(
        self,
        paths: List[Path],
        recursive: bool = True,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """Scan a mixed list of files and/or directories."""
        for p in paths:
            if p.is_file():
                r = self.scan_file(p)
                if callback:
                    callback(r)
                yield r
            elif p.is_dir():
                yield from self.scan_directory(p, recursive=recursive, callback=callback)

    @property
    def signature_count(self) -> int:
        return self._sig_db.count
