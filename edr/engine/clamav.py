"""
ClamAV signature database integration for Exploidus EDR.

NOTE: ClamAV's primary servers block direct HTTP downloads.
This module tries multiple mirrors and falls back gracefully.
For reliable updates, use MalwareBazaar (intel/mbazaar.py) instead.

Mirror priority
---------------
  1. cdn.clamav.net  (CDN, usually works)
  2. database.clamav.net  (primary, may 403)
  3. Alternative regional mirrors

CVD file layout
---------------
  Bytes 0-511  : plaintext header
  Bytes 512+   : gzip-compressed tar archive

Relevant signature files
------------------------
  *.hdb   MD5  ->  <md5>:<size>:<name>
  *.hsb   SHA1/SHA256 ->  <hash>:<size>:<name>
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import tarfile
import time
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

# Mirror list — tried in order until one works
_MIRRORS = [
    "https://cdn.clamav.net/{db}.cvd",
    "https://database.clamav.net/{db}.cvd",
    "http://db.us.clamav.net/{db}.cvd",
    "http://db.eu.clamav.net/{db}.cvd",
]

DATABASES = ["daily", "bytecode"]
MAIN_DB   = "main"
HEADER_SIZE = 512
TIMEOUT   = 60
CHUNK_SIZE = 256 * 1024

# Mimic freshclam User-Agent to avoid 403
_UA = "ClamAV/0.103.9 (OS: Windows-x86_64, ARCH: x86_64)"
_HEADERS = {
    "User-Agent": _UA,
    "Accept": "*/*",
    "Connection": "keep-alive",
}


def _download_file(url: str, dest: Path, progress: bool = True) -> bool:
    req = Request(url, headers=_HEADERS)
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            total      = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as out:
                while True:
                    chunk = resp.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    out.write(chunk)
                    downloaded += len(chunk)
                    if progress and total:
                        pct = downloaded / total * 100
                        print(
                            f"\r  {dest.name}: {pct:5.1f}%  "
                            f"({downloaded // 1_048_576} / {total // 1_048_576} MB)",
                            end="", flush=True,
                        )
        if progress:
            print()
        return True
    except HTTPError as exc:
        logger.debug("HTTP %s for %s", exc.code, url)
        return False
    except URLError as exc:
        logger.debug("URL error for %s: %s", url, exc)
        return False


def _try_download(db_name: str, dest: Path, progress: bool = True) -> bool:
    """Try each mirror in order until one succeeds."""
    for mirror_tpl in _MIRRORS:
        url = mirror_tpl.format(db=db_name)
        if progress:
            print(f"  Trying {url} ...", flush=True)
        if _download_file(url, dest, progress=progress):
            return True
    return False


def _iter_hdb(lines: Iterator[bytes]) -> Iterator[Tuple[str, str]]:
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(b"#"):
            continue
        parts = line.split(b":")
        if len(parts) >= 3:
            yield parts[0].decode().lower(), parts[2].decode(errors="replace")


def _iter_hsb(lines: Iterator[bytes]) -> Iterator[Tuple[str, str]]:
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(b"#"):
            continue
        parts = line.split(b":")
        if len(parts) >= 3:
            h = parts[0].decode().lower()
            if len(h) == 64:
                yield h, parts[2].decode(errors="replace")


def parse_cvd(cvd_path: Path) -> Dict[str, str]:
    """Extract hash signatures from a ClamAV .cvd/.cld file."""
    signatures: Dict[str, str] = {}
    try:
        with open(cvd_path, "rb") as f:
            f.read(HEADER_SIZE)
            compressed = f.read()

        with gzip.open(io.BytesIO(compressed)) as gz:
            with tarfile.open(fileobj=gz, mode="r|") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    name = member.name.lower()
                    if not (name.endswith(".hdb") or name.endswith(".hsb")):
                        continue
                    fobj = tar.extractfile(member)
                    if fobj is None:
                        continue
                    if name.endswith(".hdb"):
                        for h, t in _iter_hdb(fobj):
                            signatures[h] = t
                    else:
                        for h, t in _iter_hsb(fobj):
                            signatures[h] = t
                    fobj.close()

        logger.info("Parsed %s: %d signatures", cvd_path.name, len(signatures))
    except Exception as exc:
        logger.error("Failed to parse %s: %s", cvd_path, exc)
    return signatures


class ClamAVUpdater:
    """Downloads and parses ClamAV CVD databases (tries multiple mirrors)."""

    def __init__(self, cache_dir: Path, sig_db_path: Path) -> None:
        self._cache_dir   = Path(cache_dir)
        self._sig_db_path = Path(sig_db_path)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._meta_path   = self._cache_dir / "clamav_meta.json"

    def _load_meta(self) -> dict:
        if self._meta_path.exists():
            try:
                return json.loads(self._meta_path.read_text())
            except Exception:
                pass
        return {}

    def _save_meta(self, meta: dict) -> None:
        self._meta_path.write_text(json.dumps(meta, indent=2))

    def _needs_update(self, db_name: str, meta: dict) -> bool:
        last = meta.get(db_name, {}).get("updated_at", 0)
        return (time.time() - last) > 86400

    def update(self, include_main: bool = False, force: bool = False) -> int:
        meta    = self._load_meta()
        to_fetch = list(DATABASES)
        if include_main:
            to_fetch.append(MAIN_DB)

        all_sigs: Dict[str, str] = {}
        if self._sig_db_path.exists():
            try:
                all_sigs.update(
                    json.loads(self._sig_db_path.read_text()).get("signatures", {})
                )
            except Exception:
                pass

        before = len(all_sigs)

        for db_name in to_fetch:
            if not force and not self._needs_update(db_name, meta):
                logger.info("Skipping %s (updated recently)", db_name)
                continue

            dest = self._cache_dir / f"{db_name}.cvd"
            print(f"[ClamAV] Fetching {db_name} database...")
            ok = _try_download(db_name, dest, progress=True)

            if not ok:
                print(f"[ClamAV] All mirrors failed for {db_name}. Skipping.")
                continue

            sigs = parse_cvd(dest)
            all_sigs.update(sigs)
            meta.setdefault(db_name, {})["updated_at"] = time.time()
            meta[db_name]["count"] = len(sigs)
            print(f"[ClamAV] {db_name}: {len(sigs):,} signatures imported")

        self._sig_db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._sig_db_path, "w", encoding="utf-8") as f:
            json.dump({"signatures": all_sigs}, f)

        self._save_meta(meta)
        added = len(all_sigs) - before
        print(f"[ClamAV] Total: {len(all_sigs):,} signatures (+{added:,} new)")
        return added

    def local_stats(self) -> dict:
        meta  = self._load_meta()
        stats = {}
        for db_name in DATABASES + [MAIN_DB]:
            cvd  = self._cache_dir / f"{db_name}.cvd"
            info = meta.get(db_name, {})
            stats[db_name] = {
                "downloaded": cvd.exists(),
                "size_mb": round(cvd.stat().st_size / 1_048_576, 1) if cvd.exists() else 0,
                "signatures": info.get("count", 0),
                "updated_at":  info.get("updated_at"),
            }
        return stats