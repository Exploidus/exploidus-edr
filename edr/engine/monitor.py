"""Real-time filesystem monitor for Exploidus EDR."""

from __future__ import annotations

import logging
import queue
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from edr.config import Config
from edr.engine.scanner import Scanner, ScanResult, ThreatLevel
from edr.exceptions import MonitorError

logger = logging.getLogger(__name__)


class RealtimeMonitor:
    """
    Watches one or more directories and scans every new or modified
    file as it appears on disk.
    """

    def __init__(
        self,
        scanner: Scanner,
        config: Optional[Config] = None,
        on_threat: Optional[Callable[[ScanResult], None]] = None,
        on_scan: Optional[Callable[[ScanResult], None]] = None,
    ) -> None:
        self._scanner = scanner
        self._config = config or Config()
        self._on_threat = on_threat
        self._on_scan = on_scan
        self._queue: queue.Queue[Path] = queue.Queue()
        self._stop_event = threading.Event()
        self._observer = None
        self._worker_thread: Optional[threading.Thread] = None

    def _build_observer(self):
        try:
            from watchdog.observers import Observer
            return Observer()
        except ImportError:
            raise MonitorError(
                "watchdog is required for real-time monitoring. "
                "Install it with: pip install watchdog"
            )

    def _build_handler(self):
        from watchdog.events import FileSystemEventHandler

        monitor_queue = self._queue

        class _Handler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory:
                    monitor_queue.put(Path(event.src_path))

            def on_modified(self, event):
                if not event.is_directory:
                    monitor_queue.put(Path(event.src_path))

        return _Handler()

    def _worker(self) -> None:
        recently_seen: dict = {}
        DEBOUNCE_SECONDS = 5

        while not self._stop_event.is_set():
            try:
                path = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            now = time.monotonic()
            key = str(path)

            # Debounce: skip files scanned within the last N seconds
            if now - recently_seen.get(key, 0) < DEBOUNCE_SECONDS:
                continue
            recently_seen[key] = now

            # Brief pause so the write completes
            time.sleep(0.25)

            if not path.exists() or not path.is_file():
                continue

            result = self._scanner.scan_file(path)

            if self._on_scan:
                self._on_scan(result)

            if result.is_threat:
                logger.warning(
                    "[REALTIME] %s | %s | %s",
                    result.threat_level.value.upper(),
                    result.threat_name,
                    path,
                )
                if self._on_threat:
                    self._on_threat(result)

    def start(self, paths: Optional[List[str]] = None) -> None:
        """Start the monitor. Uses config.monitor_paths if paths is None."""
        watch_paths = paths or self._config.monitor_paths
        if not watch_paths:
            raise MonitorError(
                "No paths configured for monitoring. "
                "Pass paths to start() or set monitor_paths in config."
            )

        self._stop_event.clear()
        self._observer = self._build_observer()
        handler = self._build_handler()

        for p in watch_paths:
            self._observer.schedule(handler, str(p), recursive=True)
            logger.info("Watching: %s", p)

        self._observer.start()
        self._worker_thread = threading.Thread(
            target=self._worker, name="edr-worker", daemon=True
        )
        self._worker_thread.start()
        logger.info("Real-time monitor started (%d path(s))", len(watch_paths))

    def stop(self) -> None:
        """Stop monitoring gracefully."""
        self._stop_event.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        logger.info("Real-time monitor stopped")

    @property
    def is_running(self) -> bool:
        return (
            self._observer is not None
            and self._observer.is_alive()
        )
