# Exploidus EDR

> **High-Integrity Multi-Layered Endpoint Detection & Response (EDR) Suite**  
> Developed by **Exploidus Labs**  
> Repository: https://github.com/Exploidus/exploidus-edr  

---

## Overview

`exploidus-edr` is an enterprise-grade, zero-dependency endpoint detection and response (EDR) and antivirus platform written in Python. Designed for high-integrity defense environments, cloud hosts, and mission-critical endpoints, it integrates static signature analysis, dynamic process behavioral monitoring, PE structural heuristics, and automated quarantine isolation without relying on mandatory cloud connections.

---

## Detection Architecture

Exploidus EDR operates a phased, 5-layer detection pipeline:

```
Target File or Running Process
    |
    +--> [Layer 1] Cryptographic Signature Engine (MD5 & SHA-256 hash database)
    |
    +--> [Layer 2] YARA Pattern Engine (Compiled ruleset for droppers & payloads)
    |
    +--> [Layer 3] PE Structural Heuristics (Shannon entropy, packed sections, import abuse)
    |
    +--> [Layer 4] Process Behavioral Monitor (Parent-child process trees, ransomware triggers)
    |
    +--> [Layer 5] Threat Intelligence & ClamAV (MalwareBazaar hash correlation)
    |
    v
Encrypted Quarantine Vault & Live Threat Telemetry
```

---

## Installation

```bash
# Standard installation
pip install exploidus-edr

# With YARA rule engine
pip install "exploidus-edr[yara]"

# Complete suite with CustomTkinter GUI and behavioral monitoring
pip install "exploidus-edr[full]"
```

---

## CLI Usage

Exploidus EDR provides both `exploidus-edr` and the short alias `xedr`:

```bash
# Scan a directory recursively
xedr scan /path/to/target

# Scan and automatically quarantine malicious threats
xedr scan /path/to/target --quarantine

# Real-time directory monitoring daemon
xedr monitor /path/to/watch

# Active process behavioral scan
xedr behavior scan

# Inspect isolated quarantine vault
xedr quarantine list

# Restore a quarantined file
xedr quarantine restore <id>

# Launch modern desktop dark-mode GUI
exploidus-edr-gui
```

---

## Python API Integration

You can integrate Exploidus EDR directly into your Python security pipelines:

```python
from pathlib import Path
from edr import Scanner
from edr.config import Config

config = Config(auto_quarantine=True)
scanner = Scanner(config)

result = scanner.scan_file(Path("suspicious_binary.exe"))
print(f"Status: {result.threat_level.value} | Detection: {result.threat_name}")

for res in scanner.scan_directory(Path("/opt/deployments")):
    if res.is_threat:
        print(f"[THREAT DETECTED] {res.path} -> {res.threat_name}")
```

---

## Documentation

Full architectural specifications, YARA rule authoring, and heuristic tuning are documented in [docs/FEATURES.md](docs/FEATURES.md).

---

## License & Commercial Inquiries

`exploidus-edr` is dual-licensed under open-source copyleft and commercial enterprise terms:

### 1. Open Source (GNU AGPLv3 or Later)
For open-source projects, academic security research, and defensive evaluation, Exploidus EDR is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**.
Under this license, any hosted security scanner, multi-tenant EDR dashboard, remote verification service, or cloud security platform that incorporates or runs Exploidus EDR over a network must provide complete source code under AGPL-3.0-or-later to users interacting with it remotely. See [LICENSE](LICENSE) for the full text.

### 2. Proprietary Commercial License
For cybersecurity vendors, Managed Detection and Response (MDR) providers, enterprise defense contractors, and cloud hypervisors that wish to embed Exploidus EDR detection engines or behavioral hooks into proprietary closed-source security suites without AGPL-3.0 copyleft obligations:
- Commercial licenses are available without copyleft requirements.
- Includes custom YARA rule authoring, zero-day heuristic tuning, dedicated telemetry exporters, and SLA support.
- For commercial licensing terms and enterprise OEM inquiries, contact: **`rahadbhuiya2021@gmail.com`**.
