"""Quarantine vault for Exploidus EDR."""

from __future__ import annotations

import json
import logging
import shutil
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

from edr.exceptions import QuarantineError

logger = logging.getLogger(__name__)

MANIFEST_FILE = "manifest.json"


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    quarantined_at: float
    threat_name: Optional[str]
    md5: str
    sha256: str
    vault_filename: str


class QuarantineVault:
    """
    Isolates detected threats by moving them into a locked vault directory.
    Files are renamed to <uuid>.quar so they cannot be executed accidentally.
    """

    def __init__(self, vault_dir: Path) -> None:
        self._vault_dir = Path(vault_dir)
        self._vault_dir.mkdir(parents=True, exist_ok=True)
        self._manifest_path = self._vault_dir / MANIFEST_FILE
        self._entries: List[QuarantineEntry] = []
        self._load_manifest()

    def _load_manifest(self) -> None:
        if not self._manifest_path.exists():
            return
        try:
            with open(self._manifest_path, encoding="utf-8") as f:
                data = json.load(f)
            self._entries = [QuarantineEntry(**e) for e in data]
            logger.debug("Loaded %d quarantine entries", len(self._entries))
        except Exception as exc:
            logger.warning("Could not load quarantine manifest: %s", exc)

    def _save_manifest(self) -> None:
        with open(self._manifest_path, "w", encoding="utf-8") as f:
            json.dump([asdict(e) for e in self._entries], f, indent=2)

    def quarantine(
        self,
        path: Path,
        threat_name: Optional[str] = None,
        md5: str = "",
        sha256: str = "",
    ) -> QuarantineEntry:
        """Move a file into the vault. Returns the created QuarantineEntry."""
        path = Path(path)
        if not path.exists():
            raise QuarantineError(f"File not found: {path}")

        entry_id = str(uuid.uuid4())
        vault_filename = f"{entry_id}.quar"
        vault_path = self._vault_dir / vault_filename

        try:
            shutil.move(str(path), str(vault_path))
        except OSError as exc:
            raise QuarantineError(f"Cannot move file to vault: {exc}") from exc

        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(path),
            quarantined_at=time.time(),
            threat_name=threat_name,
            md5=md5,
            sha256=sha256,
            vault_filename=vault_filename,
        )
        self._entries.append(entry)
        self._save_manifest()
        logger.info("Quarantined: %s (%s)", path, threat_name or "unknown threat")
        return entry

    def restore(self, entry_id: str) -> Path:
        """Restore a quarantined file back to its original location."""
        entry = self._find(entry_id)
        if not entry:
            raise QuarantineError(f"No quarantine entry with id: {entry_id}")

        vault_path = self._vault_dir / entry.vault_filename
        if not vault_path.exists():
            raise QuarantineError(f"Vault file is missing: {vault_path}")

        original = Path(entry.original_path)
        original.parent.mkdir(parents=True, exist_ok=True)

        shutil.move(str(vault_path), str(original))
        self._entries.remove(entry)
        self._save_manifest()
        logger.info("Restored: %s", original)
        return original

    def delete(self, entry_id: str) -> None:
        """Permanently delete a quarantined file."""
        entry = self._find(entry_id)
        if not entry:
            raise QuarantineError(f"No quarantine entry with id: {entry_id}")

        vault_path = self._vault_dir / entry.vault_filename
        if vault_path.exists():
            vault_path.unlink()
        self._entries.remove(entry)
        self._save_manifest()
        logger.info("Deleted quarantine entry: %s (was %s)", entry_id[:8], entry.original_path)

    def list_entries(self) -> List[QuarantineEntry]:
        return list(self._entries)

    def _find(self, entry_id: str) -> Optional[QuarantineEntry]:
        for e in self._entries:
            if e.id == entry_id or e.id.startswith(entry_id):
                return e
        return None

    @property
    def count(self) -> int:
        return len(self._entries)
