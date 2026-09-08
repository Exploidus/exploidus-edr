"""
Signature update manager for Exploidus EDR.

Free sources (no API key, no payment):
  1. MalwareBazaar (abuse.ch) — primary, always works
  2. ClamAV CDN              — secondary, tries multiple mirrors
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Callable, Optional

from edr.engine.clamav import ClamAVUpdater
from edr.intel.mbazaar import download_recent as mbazaar_recent

logger = logging.getLogger(__name__)


class SignatureUpdater:
    """
    Orchestrates signature updates from all free sources.
    Call run() from the CLI or GUI Update view.
    """

    def __init__(
        self,
        cache_dir: Path,
        sig_db_path: Path,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._cache_dir   = Path(cache_dir)
        self._sig_db_path = Path(sig_db_path)
        self._on_log      = on_log or print
        self._clamav      = ClamAVUpdater(
            cache_dir   = self._cache_dir / "clamav",
            sig_db_path = self._sig_db_path,
        )

    def _log(self, msg: str) -> None:
        self._on_log(msg)

    def run(
        self,
        include_main: bool = False,
        force: bool = False,
        skip_clamav: bool = False,
    ) -> int:
        """
        Full update cycle.
        Returns total signatures in DB after update.
        """
        self._log("[Updater] Starting signature update...")
        start = time.monotonic()

        # --- Source 1: MalwareBazaar (primary, always works) ---
        self._log("[MalwareBazaar] Downloading recent malware hashes (free)...")
        mb_sigs = mbazaar_recent(print_progress=False)
        if mb_sigs:
            self._log(f"[MalwareBazaar] {len(mb_sigs):,} hashes downloaded")
            self._merge_into_db(mb_sigs)
        else:
            self._log("[MalwareBazaar] Download failed — check your internet connection")

        # --- Source 2: ClamAV (secondary, tries multiple mirrors) ---
        if not skip_clamav:
            self._log("[ClamAV] Attempting ClamAV database download...")
            try:
                self._clamav.update(include_main=include_main, force=force)
            except Exception as exc:
                self._log(f"[ClamAV] Failed: {exc}")

        total   = self._count_signatures()
        elapsed = time.monotonic() - start
        self._log(f"[Updater] Done in {elapsed:.1f}s — {total:,} signatures total")
        return total

    def _merge_into_db(self, new_sigs: dict) -> None:
        existing: dict = {}
        if self._sig_db_path.exists():
            try:
                existing = json.loads(self._sig_db_path.read_text()).get("signatures", {})
            except Exception:
                pass
        existing.update(new_sigs)
        self._sig_db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._sig_db_path, "w", encoding="utf-8") as f:
            json.dump({"signatures": existing}, f)

    def status(self) -> dict:
        clamav_stats = self._clamav.local_stats()
        total        = self._count_signatures()
        db_info      = {}
        for db, info in clamav_stats.items():
            if info["downloaded"]:
                ts  = info.get("updated_at")
                age = f"{int((time.time() - ts) / 3600)}h ago" if ts else "unknown"
                db_info[db] = {
                    "size_mb":     info["size_mb"],
                    "signatures":  info["signatures"],
                    "last_updated": age,
                }
        return {
            "total_signatures": total,
            "databases":        db_info,
            "db_path":          str(self._sig_db_path),
        }

    def _count_signatures(self) -> int:
        if not self._sig_db_path.exists():
            return 0
        try:
            return len(json.loads(self._sig_db_path.read_text()).get("signatures", {}))
        except Exception:
            return 0