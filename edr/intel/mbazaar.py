"""
MalwareBazaar (abuse.ch) free signature downloader for Exploidus EDR.

Completely free — no API key, no registration required.
Downloads the latest malware hash exports directly from abuse.ch.

Free endpoints used
-------------------
  MD5    : https://bazaar.abuse.ch/export/txt/md5/recent/
  SHA256 : https://bazaar.abuse.ch/export/txt/sha256/recent/

Each export contains the ~1 000 most recently submitted samples.
For a full database, abuse.ch also provides weekly bulk exports
(no auth needed) at https://bazaar.abuse.ch/dump/
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

EXPORTS = {
    "md5":    "https://bazaar.abuse.ch/export/txt/md5/recent/",
    "sha256": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
}

# Full weekly dump — significantly larger (~200 MB uncompressed)
FULL_DUMP_URL = "https://bazaar.abuse.ch/dump/bazaar.abuse.ch.zip"

THREAT_NAME  = "Malware.MalwareBazaar"
TIMEOUT      = 30
CHUNK_SIZE   = 256 * 1024

_HEADERS = {
    "User-Agent": "Exploidus EDR/1.0 (https://github.com/rahadbhuiya/edr)",
    "Accept": "text/plain",
}


def _fetch_text(url: str) -> Optional[str]:
    req = Request(url, headers=_HEADERS)
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except URLError as exc:
        logger.error("MalwareBazaar fetch failed (%s): %s", url, exc)
        return None


def download_recent(print_progress: bool = True) -> Dict[str, str]:
    """
    Download recent malware hashes from MalwareBazaar.
    Returns {hash_hex: threat_name} dict.
    No API key or registration required.
    """
    signatures: Dict[str, str] = {}

    for hash_type, url in EXPORTS.items():
        if print_progress:
            print(f"  [MalwareBazaar] Fetching recent {hash_type.upper()} hashes...", flush=True)

        text = _fetch_text(url)
        if not text:
            continue

        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            signatures[line.lower()] = THREAT_NAME
            count += 1

        if print_progress:
            print(f"  [MalwareBazaar] {hash_type.upper()}: {count:,} hashes loaded")

    return signatures