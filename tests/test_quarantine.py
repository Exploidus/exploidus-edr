"""Tests for the quarantine vault."""

from __future__ import annotations

from pathlib import Path

import pytest

from edr.quarantine.vault import QuarantineVault, QuarantineEntry
from edr.exceptions import QuarantineError


@pytest.fixture
def vault(tmp_path: Path) -> QuarantineVault:
    return QuarantineVault(tmp_path / "vault")


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "malware.exe"
    p.write_bytes(b"I am a fake malware")
    return p


class TestQuarantineVault:
    def test_vault_dir_created(self, tmp_path):
        vault_dir = tmp_path / "new_vault"
        QuarantineVault(vault_dir)
        assert vault_dir.exists()

    def test_quarantine_moves_file(self, vault, sample_file):
        vault.quarantine(sample_file, "Trojan.Test")
        assert not sample_file.exists()
        assert vault.count == 1

    def test_quarantine_returns_entry(self, vault, sample_file):
        entry = vault.quarantine(sample_file, "Trojan.Test")
        assert isinstance(entry, QuarantineEntry)
        assert entry.threat_name == "Trojan.Test"
        assert entry.original_path == str(sample_file)

    def test_quarantine_stores_hashes(self, vault, sample_file):
        entry = vault.quarantine(
            sample_file, "Trojan.Test", md5="abc123", sha256="def456"
        )
        assert entry.md5 == "abc123"
        assert entry.sha256 == "def456"

    def test_quarantined_file_not_executable(self, vault, sample_file):
        entry = vault.quarantine(sample_file)
        vault_file = Path(vault._vault_dir) / entry.vault_filename
        assert vault_file.suffix == ".quar"

    def test_list_entries_empty(self, vault):
        assert vault.list_entries() == []

    def test_list_entries_after_quarantine(self, vault, sample_file):
        vault.quarantine(sample_file, "X")
        entries = vault.list_entries()
        assert len(entries) == 1

    def test_restore_brings_file_back(self, vault, sample_file):
        original_path = sample_file
        entry = vault.quarantine(sample_file, "X")
        restored = vault.restore(entry.id)
        assert restored == original_path
        assert restored.exists()

    def test_restore_removes_from_vault(self, vault, sample_file):
        entry = vault.quarantine(sample_file, "X")
        vault.restore(entry.id)
        assert vault.count == 0

    def test_restore_partial_id(self, vault, sample_file):
        entry = vault.quarantine(sample_file, "X")
        short_id = entry.id[:8]
        vault.restore(short_id)
        assert vault.count == 0

    def test_delete_removes_permanently(self, vault, sample_file):
        entry = vault.quarantine(sample_file, "X")
        vault.delete(entry.id)
        assert vault.count == 0

    def test_delete_nonexistent_raises(self, vault):
        with pytest.raises(QuarantineError):
            vault.delete("nonexistent-id")

    def test_restore_nonexistent_raises(self, vault):
        with pytest.raises(QuarantineError):
            vault.restore("nonexistent-id")

    def test_quarantine_missing_file_raises(self, vault, tmp_path):
        with pytest.raises(QuarantineError):
            vault.quarantine(tmp_path / "ghost.exe")

    def test_manifest_persists_across_instances(self, vault, sample_file, tmp_path):
        entry = vault.quarantine(sample_file, "Persist.Test")
        # Create a new vault instance pointing to same directory
        vault2 = QuarantineVault(vault._vault_dir)
        assert vault2.count == 1
        assert vault2.list_entries()[0].id == entry.id

    def test_multiple_files(self, vault, tmp_path):
        for i in range(5):
            p = tmp_path / f"file{i}.exe"
            p.write_bytes(f"content {i}".encode())
            vault.quarantine(p, f"Threat.{i}")
        assert vault.count == 5
