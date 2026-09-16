"""Heuristic analysis engine for Exploidus EDR."""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

SUSPICIOUS_STRINGS: List[bytes] = [
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"ShellExecute",
    b"RegSetValueEx",
    b"WinExec",
    b"cmd.exe",
    b"powershell",
    b"base64",
    b"eval(",
    b"exec(",
    b"wget ",
    b"curl ",
    b"Invoke-Expression",
    b"IEX(",
    b"bypass",
    b"EncodedCommand",
    b"FromBase64String",
    b"mimikatz",
    b"meterpreter",
    b"reverse_tcp",
    b"bind_tcp",
    b"GetProcAddress",
    b"LoadLibrary",
    b"NtCreateThread",
    b"NtWriteVirtualMemory",
    b"ZwUnmapViewOfSection",
]

SUSPICIOUS_SECTIONS: set = {".upx0", ".upx1", ".nsp0", ".nsp1", ".themida", ".packed"}

DOUBLE_EXT_PATTERN = re.compile(
    rb"\.(pdf|doc|docx|xls|jpg|png|txt)\.(exe|bat|cmd|vbs|ps1|scr|com)\b",
    re.IGNORECASE,
)

PACKED_ENTROPY_THRESHOLD = 7.2


@dataclass
class HeuristicResult:
    score: int = 0
    flags: List[str] = field(default_factory=list)
    verdict: str = "clean"

    def add_flag(self, description: str, weight: int) -> None:
        self.flags.append(description)
        self.score = min(100, self.score + weight)
        self._update_verdict()

    def _update_verdict(self) -> None:
        if self.score >= 80:
            self.verdict = "malicious"
        elif self.score >= 40:
            self.verdict = "suspicious"
        else:
            self.verdict = "clean"

    def merge(self, other: "HeuristicResult") -> None:
        self.flags.extend(other.flags)
        self.score = min(100, self.score + other.score)
        self._update_verdict()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    result = 0.0
    for count in freq:
        if count:
            p = count / length
            result -= p * math.log2(p)
    return result


def analyze_pe(path: Path) -> HeuristicResult:
    """Analyze PE file header, sections, and imports for suspicious traits."""
    result = HeuristicResult()
    try:
        import pefile

        pe = pefile.PE(str(path), fast_load=False)

        for section in pe.sections:
            name = section.Name.decode(errors="replace").strip("\x00").lower()
            if name in SUSPICIOUS_SECTIONS:
                result.add_flag(f"Suspicious PE section: {name}", 25)
            entropy = section.get_entropy()
            if entropy > PACKED_ENTROPY_THRESHOLD:
                result.add_flag(
                    f"High entropy section '{name}' ({entropy:.2f}) - possible packing", 20
                )

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            result.add_flag("No import table - likely packed or obfuscated", 25)
        else:
            suspicious_imports = {
                "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                "NtCreateThread", "ZwUnmapViewOfSection",
            }
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode(errors="replace") in suspicious_imports:
                        result.add_flag(
                            f"Suspicious import: {imp.name.decode(errors='replace')}", 15
                        )

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for res in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(res, "directory"):
                    for entry in res.directory.entries:
                        if hasattr(entry, "data"):
                            data = pe.get_data(
                                entry.data.struct.OffsetToData,
                                entry.data.struct.Size,
                            )
                            if _entropy(data) > PACKED_ENTROPY_THRESHOLD:
                                result.add_flag("High entropy resource (possible dropper)", 15)
                                break

        pe.close()

    except ImportError:
        logger.debug("pefile not installed, skipping PE analysis")
    except pefile.PEFormatError:
        pass
    except Exception as exc:
        logger.debug("PE analysis error on %s: %s", path, exc)

    return result


def analyze_strings(path: Path, max_bytes: int = 10 * 1024 * 1024) -> HeuristicResult:
    """Scan raw file bytes for suspicious patterns."""
    result = HeuristicResult()
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)

        data_lower = data.lower()
        for pattern in SUSPICIOUS_STRINGS:
            if pattern.lower() in data_lower:
                result.add_flag(
                    f"Suspicious string: {pattern.decode(errors='replace')}", 8
                )

        if DOUBLE_EXT_PATTERN.search(data):
            result.add_flag("Double extension detected (possible disguise)", 35)

        file_entropy = _entropy(data)
        if file_entropy > PACKED_ENTROPY_THRESHOLD:
            result.add_flag(
                f"High file entropy ({file_entropy:.2f}) - possible encryption/packing", 15
            )

    except OSError as exc:
        logger.debug("String analysis failed for %s: %s", path, exc)

    return result


def analyze(path: Path) -> HeuristicResult:
    """Run all heuristic layers and return a merged result."""
    combined = HeuristicResult()
    combined.merge(analyze_strings(path))

    ext = path.suffix.lower()
    if ext in {".exe", ".dll", ".sys", ".scr", ".com", ".ocx"}:
        combined.merge(analyze_pe(path))

    return combined
