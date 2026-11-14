"""Tests for configuration management."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from edr.config import Config


class TestConfig:
    def test_default_config_created(self):
        cfg = Config()
        assert cfg.max_file_size_mb == 256
        assert cfg.heuristic_threshold == 60
        assert cfg.auto_quarantine is False
        assert cfg.behavior_monitor_enabled is False

    def test_save_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "config.json"
        cfg = Config(
            max_file_size_mb=512,
            auto_quarantine=True,
            excluded_extensions=[".tmp", ".bak", ".swp"],
        )
        cfg.save(path)
        loaded = Config.load(path)
        assert loaded.max_file_size_mb == 512
        assert loaded.auto_quarantine is True
        assert ".swp" in loaded.excluded_extensions

    def test_load_nonexistent_returns_defaults(self, tmp_path):
        cfg = Config.load(tmp_path / "missing.json")
        assert cfg.max_file_size_mb == 256

    def test_load_ignores_unknown_keys(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"unknown_key": "value", "max_file_size_mb": 128}))
        cfg = Config.load(path)
        assert cfg.max_file_size_mb == 128

    def test_ensure_dirs_creates_directories(self, tmp_path):
        cfg = Config(
            quarantine_dir=str(tmp_path / "q"),
            log_dir=str(tmp_path / "l"),
            yara_rules_dir=str(tmp_path / "r"),
            clamav_cache_dir=str(tmp_path / "c"),
            signature_db=str(tmp_path / "sigs.json"),
        )
        cfg._ensure_dirs()
        assert (tmp_path / "q").exists()
        assert (tmp_path / "l").exists()
        assert (tmp_path / "r").exists()
        assert (tmp_path / "c").exists()

    def test_save_creates_parent_dirs(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "config.json"
        Config().save(deep)
        assert deep.exists()

    def test_monitor_paths_default_empty(self):
        cfg = Config()
        assert cfg.monitor_paths == []

    def test_excluded_extensions_default(self):
        cfg = Config()
        assert ".log" in cfg.excluded_extensions
        assert ".tmp" in cfg.excluded_extensions

    def test_no_virustotal_fields(self):
        cfg = Config()
        assert not hasattr(cfg, "virustotal_api_key")
        assert not hasattr(cfg, "virustotal_enabled")

    def test_behavior_config_fields(self):
        cfg = Config(behavior_monitor_enabled=True, behavior_scan_interval=5.0)
        assert cfg.behavior_monitor_enabled is True
        assert cfg.behavior_scan_interval == 5.0
