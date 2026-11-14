"""Tests for the signature database."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from edr.engine.signatures import SignatureDatabase, compute_hashes, BUILTIN_SIGNATURES
from tests.conftest import (
    TEST_MALWARE_BYTES, TEST_MALWARE_MD5, TEST_MALWARE_SHA256,
    EICAR_MD5, EICAR_SHA256,
)


class TestSignatureDatabase:
    def test_builtin_signatures_loaded(self, config):
        db = SignatureDatabase(Path(config.signature_db))
        assert db.count >= len(BUILTIN_SIGNATURES)

    def test_eicar_md5_in_builtin(self):
        """EICAR MD5 is in BUILTIN_SIGNATURES — no file I/O needed."""
        db = SignatureDatabase()
        assert db.lookup_md5(EICAR_MD5) == "EICAR-Test-File"

    def test_eicar_sha256_in_builtin(self):
        """EICAR SHA256 is in BUILTIN_SIGNATURES — no file I/O needed."""
        db = SignatureDatabase()
        assert db.lookup_sha256(EICAR_SHA256) == "EICAR-Test-File"

    def test_unknown_hash_returns_none(self, config):
        db = SignatureDatabase(Path(config.signature_db))
        assert db.lookup_md5("00000000000000000000000000000000") is None
        assert db.lookup_sha256("a" * 64) is None

    def test_add_and_lookup_custom_signature(self, config):
        db = SignatureDatabase(Path(config.signature_db))
        fake_hash = "a" * 32
        db.add_signature(fake_hash, "CustomThreat.X")
        assert db.lookup_md5(fake_hash) == "CustomThreat.X"

    def test_save_and_reload(self, config):
        db = SignatureDatabase(Path(config.signature_db))
        db.add_signature("b" * 32, "PersistentThreat.Y")
        db.save()
        db2 = SignatureDatabase(Path(config.signature_db))
        assert db2.lookup_md5("b" * 32) == "PersistentThreat.Y"

    def test_case_insensitive_lookup(self, config):
        db = SignatureDatabase(Path(config.signature_db))
        db.add_signature("AABBCCDD" * 4, "CaseThreat")
        assert db.lookup_md5("aabbccdd" * 4) == "CaseThreat"
        assert db.lookup_md5("AABBCCDD" * 4) == "CaseThreat"

    def test_load_from_json_file(self, tmp_path):
        db_path = tmp_path / "custom.json"
        db_path.write_text(
            json.dumps({"signatures": {"cafebabe" * 4: "Custom.Threat.Z"}})
        )
        db = SignatureDatabase(db_path)
        assert db.lookup_md5("cafebabe" * 4) == "Custom.Threat.Z"

    def test_corrupt_db_raises_error(self, tmp_path):
        from edr.exceptions import SignatureLoadError
        bad_path = tmp_path / "bad.json"
        bad_path.write_text("{not valid json{{")
        with pytest.raises(SignatureLoadError):
            SignatureDatabase(bad_path)


class TestComputeHashes:
    def test_synthetic_malware_hashes(self, tmp_path):
        """
        Use synthetic bytes so host AV (e.g. Windows Defender) won't
        interfere with the file before we can read it.
        """
        p = tmp_path / "test_malware.bin"
        p.write_bytes(TEST_MALWARE_BYTES)
        hashes = compute_hashes(p)
        assert hashes["md5"]    == TEST_MALWARE_MD5
        assert hashes["sha256"] == TEST_MALWARE_SHA256

    def test_missing_file_returns_empty(self, tmp_path):
        hashes = compute_hashes(tmp_path / "nonexistent.bin")
        assert hashes["md5"]    == ""
        assert hashes["sha256"] == ""

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        hashes = compute_hashes(p)
        assert hashes["md5"]    == "d41d8cd98f00b204e9800998ecf8427e"
        assert hashes["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"