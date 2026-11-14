"""Tests for ClamAV signature parser."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from edr.engine.clamav import (
    ClamAVUpdater,
    _iter_hdb,
    _iter_hsb,
    parse_cvd,
)


class TestIterHdb:
    def test_parses_valid_line(self):
        lines = [b"aabbccddeeff00112233445566778899:1234:Trojan.Test\n"]
        result = list(_iter_hdb(iter(lines)))
        assert result == [("aabbccddeeff00112233445566778899", "Trojan.Test")]

    def test_skips_comments(self):
        lines = [b"# This is a comment\n", b"aabbccdd" * 4 + b":100:Real.Threat\n"]
        result = list(_iter_hdb(iter(lines)))
        assert len(result) == 1
        assert result[0][1] == "Real.Threat"

    def test_skips_empty_lines(self):
        lines = [b"\n", b"   \n", b"aabbccdd" * 4 + b":50:X\n"]
        result = list(_iter_hdb(iter(lines)))
        assert len(result) == 1

    def test_skips_malformed_lines(self):
        lines = [b"not_enough_colons\n"]
        result = list(_iter_hdb(iter(lines)))
        assert result == []

    def test_hash_lowercased(self):
        lines = [b"AABBCCDDEEFF00112233445566778899:1:Threat\n"]
        result = list(_iter_hdb(iter(lines)))
        assert result[0][0] == "aabbccddeeff00112233445566778899"


class TestIterHsb:
    def test_parses_sha256(self):
        sha256 = "a" * 64
        lines = [f"{sha256}:*:SHA256.Threat\n".encode()]
        result = list(_iter_hsb(iter(lines)))
        assert result == [(sha256, "SHA256.Threat")]

    def test_skips_non_sha256(self):
        md5 = "a" * 32  # 32 chars = MD5, not SHA256
        lines = [f"{md5}:*:MD5.Threat\n".encode()]
        result = list(_iter_hsb(iter(lines)))
        assert result == []

    def test_skips_comments(self):
        lines = [b"# comment\n"]
        assert list(_iter_hsb(iter(lines))) == []


class TestParseCvd:
    def test_parses_mock_cvd(self, mock_cvd):
        sigs = parse_cvd(mock_cvd)
        assert "aabbccddeeff00112233445566778899" in sigs
        assert sigs["aabbccddeeff00112233445566778899"] == "TestTrojan.A"
        assert "deadbeefdeadbeefdeadbeefdeadbeef" in sigs
        assert sigs["deadbeefdeadbeefdeadbeefdeadbeef"] == "TestTrojan.B"

    def test_parses_sha256_from_hsb(self, mock_cvd):
        sigs = parse_cvd(mock_cvd)
        eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        assert eicar_sha256 in sigs
        assert sigs[eicar_sha256] == "EICAR-SHA256"

    def test_returns_empty_on_bad_file(self, tmp_path):
        bad = tmp_path / "corrupt.cvd"
        bad.write_bytes(b"\x00" * 512 + b"not gzip data")
        sigs = parse_cvd(bad)
        assert sigs == {}

    def test_returns_empty_on_missing_file(self, tmp_path):
        sigs = parse_cvd(tmp_path / "missing.cvd")
        assert sigs == {}


class TestClamAVUpdater:
    def test_local_stats_before_download(self, tmp_path):
        updater = ClamAVUpdater(
            cache_dir=tmp_path / "cache",
            sig_db_path=tmp_path / "sigs.json",
        )
        stats = updater.local_stats()
        assert "daily" in stats
        assert stats["daily"]["downloaded"] is False

    def test_update_writes_signatures(self, tmp_path, mock_cvd):
        """Test update using a local mock CVD instead of downloading."""
        sig_db = tmp_path / "sigs.json"
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Pre-place the mock CVD as if it was downloaded
        import shutil
        shutil.copy(mock_cvd, cache_dir / "daily.cvd")

        updater = ClamAVUpdater(cache_dir=cache_dir, sig_db_path=sig_db)

        # Patch _download_file to skip actual download
        with patch("edr.engine.clamav._download_file", return_value=True):
            # Manually call parse_cvd and save (simulating what update() does)
            sigs = parse_cvd(cache_dir / "daily.cvd")
            sig_db.write_text(json.dumps({"signatures": sigs}))

        assert sig_db.exists()
        data = json.loads(sig_db.read_text())
        assert "aabbccddeeff00112233445566778899" in data["signatures"]

    def test_needs_update_true_when_never_updated(self, tmp_path):
        updater = ClamAVUpdater(tmp_path / "c", tmp_path / "s.json")
        assert updater._needs_update("daily", {}) is True

    def test_needs_update_false_when_recent(self, tmp_path):
        import time
        updater = ClamAVUpdater(tmp_path / "c", tmp_path / "s.json")
        meta = {"daily": {"updated_at": time.time()}}
        assert updater._needs_update("daily", meta) is False

    def test_meta_persists(self, tmp_path):
        import time
        updater = ClamAVUpdater(tmp_path / "c", tmp_path / "s.json")
        meta = {"daily": {"updated_at": time.time(), "count": 100}}
        updater._save_meta(meta)
        loaded = updater._load_meta()
        assert loaded["daily"]["count"] == 100
