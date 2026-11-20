# Exploidus EDR - Engineering & Feature Specifications

## Architecture

Exploidus EDR employs a layered, defense-in-depth detection pipeline. Every inspected file or execution flow passes through active analysis engines in strict sequence:

```
File on disk
    |
    v
Layer 1: Signature Engine (MD5 / SHA256 hash lookup)
    |
    v
Layer 2: YARA Rule Engine (pattern-based rules)
    |
    v
Layer 3: Heuristic Engine (string analysis + PE analysis)
    |
    v
ScanResult (clean / suspicious / malicious)
```

---

## Layer 1 - Signature Engine

### How it works

The signature engine computes MD5 and SHA256 hashes of every scanned file
and looks them up against a database of known malware hashes.

### Built-in signatures

Exploidus EDR ships with a small set of built-in signatures including the EICAR
test file. Additional signatures are loaded from `~/.exploidus-edr/signatures.json`
at startup.

### Signature database format

```json
{
  "signatures": {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
    "<sha256-hash>": "Trojan.GenericKD.12345"
  }
}
```

Keys may be MD5 (32 hex chars) or SHA256 (64 hex chars). Values are the
human-readable threat name returned in `ScanResult.threat_name`.

### Python API

```python
from edr.engine.signatures import SignatureDatabase

db = SignatureDatabase(db_path=Path("my_signatures.json"))
name = db.lookup_md5("44d88612fea8a8f36de82e1278abb02f")
# -> "EICAR-Test-File"
```

---

## Layer 2 - YARA Rule Engine

### Requirements

```bash
pip install "edr[yara]"
```

### How it works

At startup, Exploidus EDR compiles all `*.yar` and `*.yara` files found in
`~/.exploidus-edr/rules/` into a single YARA ruleset. Files that match any rule
are flagged as malicious with the rule name as the threat identifier.

### Example YARA rule

```yara
rule SuspiciousPowerShell {
    meta:
        description = "Encoded PowerShell command"
        severity = "high"
    strings:
        $enc = "EncodedCommand" nocase
        $iex = "IEX(" nocase
    condition:
        any of them
}
```

### Python API

```python
# YARA rules are loaded automatically when the rules directory is populated.
scanner = Scanner(config)
result = scanner.scan_file(Path("script.ps1"))
print(result.yara_matches)   # ["SuspiciousPowerShell"]
```

---

## Layer 3 - Heuristic Engine

The heuristic engine scores files using two sub-engines.

### 3a - String Analysis (all file types)

Scans raw file bytes for patterns associated with malicious behaviour:

- Process injection APIs (CreateRemoteThread, VirtualAllocEx, WriteProcessMemory)
- Encoded payload markers (base64, EncodedCommand, FromBase64String)
- Post-exploitation tools (mimikatz, meterpreter, reverse_tcp)
- Shell launchers (cmd.exe, powershell, Invoke-Expression)
- Double extension filenames (e.g. `document.pdf.exe`)
- High entropy content (indicates encryption or packing)

### 3b - PE Analysis (Windows executables: .exe, .dll, .sys, .scr)

Requires `pefile` (installed automatically with Exploidus EDR):

- Suspicious section names (.upx0, .upx1, .themida, .packed)
- Sections with entropy above 7.2 (typical of packers/cryptors)
- Missing import table (common in shellcode loaders)
- Dangerous imports (NtCreateThread, ZwUnmapViewOfSection)
- High-entropy resources (possible embedded dropper)

### Score thresholds

| Score | Verdict    |
|-------|------------|
| 0-49  | clean      |
| 50-79 | suspicious |
| 80+   | malicious  |

---

## Quarantine Vault

Detected threats can be moved to an isolated vault directory where they
cannot be executed. Files are renamed to `<uuid>.quar` on disk.

### CLI

```bash
# Quarantine threats during a scan
xedr scan C:\Temp --quarantine

# List quarantined files
xedr quarantine list

# Restore a file (use the first 8 chars of the ID)
xedr quarantine restore a1b2c3d4

# Permanently delete
xedr quarantine delete a1b2c3d4
```

### Python API

```python
from edr.quarantine.vault import QuarantineVault

vault = QuarantineVault(Path("~/.exploidus-edr/quarantine"))
entry = vault.quarantine(Path("malware.exe"), threat_name="Trojan.X")
print(entry.id)

vault.restore(entry.id)
vault.delete(entry.id)
```

---

## Real-time Monitor

Watches directories using OS filesystem events and scans every new or
modified file as it appears.

### CLI

```bash
# Monitor a directory
xedr monitor C:\Users\you\Downloads

# Monitor with auto-quarantine
xedr monitor C:\Users\you\Downloads --auto-quarantine
```

### Python API

```python
from edr import Scanner, RealtimeMonitor

scanner = Scanner(config)

def handle_threat(result):
    print(f"Threat detected: {result.path}")

mon = RealtimeMonitor(scanner, on_threat=handle_threat)
mon.start(["C:/Users/you/Downloads"])

import time
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    mon.stop()
```

---

## VirusTotal Integration

### Configuration

```bash
xedr config init
# Edit ~/.exploidus-edr/config.json and set virustotal_api_key
```

### Python API

```python
from edr.intel.virustotal import VirusTotalClient

vt = VirusTotalClient(api_key="YOUR_VT_API_KEY")

# Look up a hash
report = vt.lookup_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
print(report["malicious"], "/", report["total"])

# Look up a local file
report = vt.lookup_file(Path("suspicious.exe"))

# Submit a file for analysis (if not yet known)
report = vt.upload_file(Path("unknown.exe"))
```

Rate limiting is handled automatically (15 second interval between requests
for the free API tier).

---

## Configuration

Default config location: `~/.exploidus-edr/config.json`

| Key                   | Default                        | Description                              |
|-----------------------|--------------------------------|------------------------------------------|
| quarantine_dir        | ~/.exploidus-edr/quarantine         | Where quarantined files are stored       |
| signature_db          | ~/.exploidus-edr/signatures.json    | Path to custom signature database        |
| log_dir               | ~/.exploidus-edr/logs               | Directory for log files                  |
| yara_rules_dir        | ~/.exploidus-edr/rules              | Directory for YARA rule files            |
| virustotal_api_key    | ""                             | VirusTotal API v3 key                    |
| monitor_paths         | []                             | Default paths for real-time monitoring   |
| excluded_paths        | []                             | Paths to skip during scans               |
| excluded_extensions   | [".log", ".tmp", ".bak"]       | File extensions to skip                  |
| max_file_size_mb      | 256                            | Skip files larger than this              |
| heuristic_threshold   | 60                             | Minimum heuristic score for suspicious   |
| auto_quarantine       | false                          | Auto-quarantine during monitoring        |
| virustotal_enabled    | false                          | Enable VT lookups in scanner             |

---

## Logging

Exploidus EDR writes two log files to `log_dir`:

- `edr.log` - human-readable runtime log (all INFO/WARNING/ERROR events)
- `scan_results.jsonl` - newline-delimited JSON with one record per scanned file

The JSONL format makes it easy to pipe into SIEM tools, grep, or `jq`.

```bash
# View all threats from scan logs
jq 'select(.threat_level != "clean")' ~/.exploidus-edr/logs/scan_results.jsonl
```

---

## Extending Exploidus EDR

### Custom signature sources

```python
from edr.engine.signatures import SignatureDatabase

db = SignatureDatabase()
db.add_signature("aabbccddeeff...", "MyOrg.CustomTrojan")
db.save()
```

### Custom on-scan callback

```python
def my_callback(result):
    if result.is_threat:
        send_alert(result)

for r in scanner.scan_directory(Path("C:/Data"), callback=my_callback):
    pass
```

### Subclassing Scanner

```python
from edr.engine.scanner import Scanner, ScanResult

class CloudScanner(Scanner):
    def scan_file(self, path):
        result = super().scan_file(path)
        if result.is_clean:
            cloud_result = self.cloud_lookup(result.sha256)
            # merge cloud_result into result
        return result
```
