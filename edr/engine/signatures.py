"""Signature database management for Exploidus EDR."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Optional, Set

from edr.exceptions import SignatureLoadError

logger = logging.getLogger(__name__)

# Bundled built-in signatures (hash -> threat name)
BUILTIN_SIGNATURES: Dict[str, str] = {
    # EICAR test file - MD5
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
    "69630e4574ec6798239b091cda43dca0": "EICAR-Test-File",
    # EICAR test file - SHA256
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}


class SignatureDatabase:
    """Manages malware signature hashes (MD5 + SHA256)."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path
        self._signatures: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        self._signatures.update(BUILTIN_SIGNATURES)

        if self._db_path and Path(self._db_path).exists():
            try:
                with open(self._db_path, encoding="utf-8") as f:
                    data = json.load(f)
                entries: Dict[str, str] = data.get("signatures", {})
                self._signatures.update(
                    {k.lower(): v for k, v in entries.items()}
                )
                logger.info(
                    "Loaded %d signatures from %s", len(entries), self._db_path
                )
            except (json.JSONDecodeError, OSError) as exc:
                raise SignatureLoadError(
                    f"Cannot load signature DB: {exc}"
                ) from exc

    def lookup(self, file_hash: str) -> Optional[str]:
        """Look up any hash (MD5 or SHA256). Returns threat name or None."""
        return self._signatures.get(file_hash.lower())

    def lookup_md5(self, md5: str) -> Optional[str]:
        return self._signatures.get(md5.lower())

    def lookup_sha256(self, sha256: str) -> Optional[str]:
        return self._signatures.get(sha256.lower())

    def add_signature(self, hash_value: str, name: str) -> None:
        self._signatures[hash_value.lower()] = name

    def save(self) -> None:
        if not self._db_path:
            return
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self._db_path, "w", encoding="utf-8") as f:
            json.dump({"signatures": self._signatures}, f, indent=2)
        logger.info("Saved %d signatures to %s", len(self._signatures), self._db_path)

    @property
    def count(self) -> int:
        return len(self._signatures)


def compute_hashes(path: Path) -> Dict[str, str]:
    """Compute MD5 and SHA256 for a file. Returns empty strings on failure."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
    except OSError as exc:
        logger.debug("Cannot hash %s: %s", path, exc)
        return {"md5": "", "sha256": ""}
