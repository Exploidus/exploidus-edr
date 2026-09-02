"""Custom exceptions for Exploidus EDR."""

from __future__ import annotations


class EDRError(Exception):
    """Base exception for all Exploidus EDR runtime errors."""


# Backward compatibility alias
# Legacy alias removed


class SignatureLoadError(EDRError):
    """Raised when signature database cannot be parsed or loaded."""


class QuarantineError(EDRError):
    """Raised when an encrypted quarantine vault operation fails."""


class ScanError(EDRError):
    """Raised when an active scan encounters an unrecoverable I/O or permission error."""


class ThreatIntelError(EDRError):
    """Raised when an external threat intelligence API lookup fails."""


class MonitorError(EDRError):
    """Raised when the real-time filesystem monitor daemon cannot initialize."""
