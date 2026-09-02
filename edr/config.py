"""Configuration management for Exploidus EDR."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List

DEFAULT_CONFIG_PATH   = Path.home() / ".exploidus-edr" / "config.json"
DEFAULT_QUARANTINE_DIR = Path.home() / ".exploidus-edr" / "quarantine"
DEFAULT_SIGNATURE_DB  = Path.home() / ".exploidus-edr" / "signatures.json"
DEFAULT_LOG_DIR       = Path.home() / ".exploidus-edr" / "logs"
DEFAULT_YARA_RULES_DIR = Path.home() / ".exploidus-edr" / "rules"
DEFAULT_CLAMAV_CACHE  = Path.home() / ".exploidus-edr" / "clamav"


@dataclass
class Config:
    quarantine_dir: str        = str(DEFAULT_QUARANTINE_DIR)
    signature_db: str          = str(DEFAULT_SIGNATURE_DB)
    log_dir: str               = str(DEFAULT_LOG_DIR)
    yara_rules_dir: str        = str(DEFAULT_YARA_RULES_DIR)
    clamav_cache_dir: str      = str(DEFAULT_CLAMAV_CACHE)
    monitor_paths: List[str]   = field(default_factory=list)
    excluded_paths: List[str]  = field(default_factory=list)
    excluded_extensions: List[str] = field(
        default_factory=lambda: [".log", ".tmp", ".bak"]
    )
    max_file_size_mb: int      = 256
    heuristic_threshold: int   = 60
    auto_quarantine: bool      = False
    behavior_monitor_enabled: bool  = False
    behavior_scan_interval: float   = 10.0

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "Config":
        if not path.exists():
            return cls()
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid)

    def save(self, path: Path = DEFAULT_CONFIG_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

    def _ensure_dirs(self) -> None:
        for d in [
            self.quarantine_dir,
            self.log_dir,
            self.yara_rules_dir,
            self.clamav_cache_dir,
        ]:
            Path(d).mkdir(parents=True, exist_ok=True)
