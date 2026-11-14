"""
Shared pytest fixtures for Exploidus EDR tests.

IMPORTANT — Windows Defender compatibility
------------------------------------------
Real EICAR bytes written to disk are immediately quarantined by Windows Defender
before Exploidus EDR can read them, causing hash-based tests to fail.

Strategy used here:
  - Signature-DB lookup tests  : still use real EICAR hashes (no file I/O needed)
  - File-write / scan tests    : use TEST_MALWARE_BYTES — harmless synthetic bytes
                                 whose hash is pre-registered in the test signature DB
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from edr.config import Config


# Synthetic test "malware" — harmless, won't trigger host AV

TEST_MALWARE_BYTES = b"EXPLOIDUS-EDR-TEST-SIG-DO-NOT-SHIP:" * 20
TEST_MALWARE_MD5    = "0da87ef3e4952e0c711fa06f2056bc4f"
TEST_MALWARE_SHA256 = "7439d2ee98a9ad6930d3ec6e3283943e58ba8d9e413196d3108201a1b821519a"
TEST_MALWARE_NAME   = "ExploidusEDR.TestSignature"

# EICAR constants kept for signature-DB lookup tests (no file I/O required)
EICAR_MD5    = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

CLEAN_BYTES = b"Hello, I am a completely harmless text file.\n" * 20



# Fixtures


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """
    Config pointing entirely into tmp_path.
    The signature DB is pre-populated with TEST_MALWARE so that
    file-write tests work even when host AV blocks EICAR.
    """
    cfg = Config(
        quarantine_dir  = str(tmp_path / "quarantine"),
        signature_db    = str(tmp_path / "signatures.json"),
        log_dir         = str(tmp_path / "logs"),
        yara_rules_dir  = str(tmp_path / "rules"),
        clamav_cache_dir= str(tmp_path / "clamav"),
    )
    # Pre-populate with synthetic test signature
    sig_path = Path(cfg.signature_db)
    sig_path.parent.mkdir(parents=True, exist_ok=True)
    sig_path.write_text(json.dumps({"signatures": {
        TEST_MALWARE_MD5:    TEST_MALWARE_NAME,
        TEST_MALWARE_SHA256: TEST_MALWARE_NAME,
    }}))
    return cfg


@pytest.fixture
def eicar_file(tmp_path: Path) -> Path:
    """
    A file that Exploidus EDR will detect as malicious.
    Uses synthetic bytes instead of real EICAR to avoid host-AV interference.
    The hash is registered in the config fixture's signature DB.
    """
    p = tmp_path / "test_malware.com"
    p.write_bytes(TEST_MALWARE_BYTES)
    return p


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    p = tmp_path / "clean.txt"
    p.write_bytes(CLEAN_BYTES)
    return p


@pytest.fixture
def suspicious_script(tmp_path: Path) -> Path:
    """PS1 file that triggers heuristic string detection."""
    p = tmp_path / "bad.ps1"
    p.write_bytes(
        b"powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0AT\n"
        b"Invoke-Expression $payload\n"
        b"FromBase64String('SGVsbG8=')\n"
    )
    return p


@pytest.fixture
def double_ext_file(tmp_path: Path) -> Path:
    """File with a double extension (disguised executable)."""
    p = tmp_path / "invoice.pdf.exe"
    p.write_bytes(b"file.pdf.exe content here")
    return p


@pytest.fixture
def mock_cvd(tmp_path: Path) -> Path:
    """A minimal ClamAV .cvd file with a few test signatures."""
    hdb_content = (
        b"# Exploidus EDR test signatures\n"
        b"aabbccddeeff00112233445566778899:1234:TestTrojan.A\n"
        b"deadbeefdeadbeefdeadbeefdeadbeef:5678:TestTrojan.B\n"
    )
    hsb_content = (
        b"# SHA256 test signatures\n"
        b"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:*:EICAR-SHA256\n"
    )

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        with tarfile.open(fileobj=gz, mode="w|") as tar:
            for name, content in [("test.hdb", hdb_content), ("test.hsb", hsb_content)]:
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))

    payload = buf.getvalue()
    header = b"ClamAV-VDB:01 Jan 2025:999:99:MD5SIG:builder:build_time:dsig"
    header = header.ljust(512, b"\x00")[:512]

    cvd_path = tmp_path / "test.cvd"
    cvd_path.write_bytes(header + payload)
    return cvd_path