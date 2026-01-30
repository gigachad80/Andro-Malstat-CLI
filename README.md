# Andro-Malstat

**Full-Featured Static Analysis Orchestration Automation Framework for APK Files**

![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-purple.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)
![Development Time](https://img.shields.io/badge/Development%20Time-Approx%2040%20min-blue.svg)

Andro-Malstat is a comprehensive hybrid static analysis engine for Android APK files that combines bytecode analysis with pattern matching to detect malicious behavior, obfuscation techniques, and security vulnerabilities.

## Table of Contents

- [Overview](#overview)
- [Comparison with MobSF](#comparison-with-mobsf)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [YARA Rules](#yara-rules)
- [Analysis Phases](#analysis-phases)
- [TODO](#todo)
- [License](#license)
- [Contact](#contact)

## Overview

Andro-Malstat performs multi-phase static analysis on Android applications to identify potential threats and security issues. It uses a combination of techniques including:

- File profiling and entropy analysis
- Certificate verification
- Permission and component analysis
- Obfuscation detection
- Hybrid code analysis (bytecode tracing + string pattern matching)
- Native library inspection
- YARA malware signature scanning
- Anti-analysis technique detection

## Comparison with MobSF

| Feature | Andro-Malstat | MobSF |
|---------|---------------|-------|
| **Type** | Lightweight CLI orchestration automation framework | Full-featured web platform |
| **Installation** | `pip install` (3 dependencies) | Docker/complex setup required |
| **Runtime** | Fast (~30-60 seconds) | Slower (2-5 minutes) |
| **Memory Usage** | Low (~200-500 MB) | High (~1-2 GB) |
| **YARA Support** | Custom rules via `yara_rules/` directory | Built-in ruleset |
| **User Interface** | Terminal with color output | Web dashboard |
| **Report Format** | JSON + terminal | PDF, JSON, HTML |
| **Obfuscation Detection** | ProGuard/R8 entropy analysis | Code complexity metrics |
| **Anti-Analysis Detection** | Debugger/Emulator/Root/Frida | Limited |
| **Native Code Analysis** | Shell payload detection | Comprehensive binary analysis |
| **Dynamic Analysis** | No | Yes (with emulator) |
| **API Scanning** | Hybrid (bytecode + strings) | Bytecode only |
| **Nested APK Detection** | Yes | Yes |
| **Learning Curve** | Minimal (CLI arguments) | Moderate (web interface) |
| **Use Case** | Quick triage, CI/CD integration, malware hunting | In-depth security audit, compliance |
| **Deployment** | Local script | Self-hosted server |
| **Best For** | Rapid analysis, automation, researchers | Comprehensive reports, teams, enterprises |

**When to use Andro-Malstat:**
- Quick malware triage and threat hunting
- CI/CD pipeline integration
- Resource-constrained environments
- Command-line automation workflows
- Custom YARA rule development

**When to use MobSF:**
- Comprehensive security audits
- Team collaboration with web UI
- Detailed compliance reports (PDF)
- Dynamic analysis requirements
- Enterprise security assessments

## Features

**Core Analysis Capabilities:**
- Automated APK unpacking and parsing with Androguard
- SHA256/MD5 hash generation and entropy calculation
- Certificate chain analysis and debug key detection
- Dangerous permission enumeration
- ProGuard/R8 obfuscation metrics
- Suspicious API call detection
- Native code shell execution detection
- Nested APK/DEX dropper identification
- Network security configuration parsing
- Anti-debugging and anti-emulator detection
- YARA malware signature matching
- Risk scoring system with severity classification

**Advanced Features:**
- Hybrid analysis combining bytecode tracing with raw string fallback
- Automatic detection of C2 domains and hardcoded IPs
- Persistence mechanism identification
- Reflection and dynamic code loading detection
- Cleartext traffic vulnerability detection
- Emergency fallback analysis for corrupted APKs

## Requirements

- Python 3.7 or higher
- androguard
- yara-python
- colorama

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/gigachad80/Andro-Malstat-CLI
cd Andro-Malstat-CLI

# Install dependencies
pip install -r requirements.txt

# Run the analyzer
python andromalstat.py sample.apk
```

## Usage

### Basic Usage

```bash
# Analyze an APK with default settings
python andromalstat.py malware.apk

# Specify custom output directory
python andromalstat.py malware.apk analysis_output

# Show help
python andromalstat.py
```

### Command Line Arguments

```
Usage: python andromalstat.py <apk_file> [output_dir]

Arguments:
  apk_file    Path to the APK file to analyze
  output_dir  Output directory for analysis results (default: analysis_result)
```

### Example

```bash
# Analyze a suspicious APK
python andromalstat.py suspicious_app.apk ./results

# Output will be saved to:
# ./results/report_suspicious_app_20260130_143022.json
```

## YARA Rules

Andro-Malstat supports custom YARA rules for malware detection. Place your `.yar` files in the `yara_rules/` directory.

### Directory Structure

```
andro-malstat/
├── andromalstat.py
├── yara_rules/
│   ├── ania-analysis.yar
│   ├── bank_overlay.yar
│   ├── clayrat.yar
│   ├── commercial.yar
│   ├── craxs.yar
│   ├── crypto.yar
│   ├── cypher.yar
│   ├── dropper.yar
│   ├── joker.yar
│   ├── lemon.yar
│   ├── ransomware.yar
│   ├── rat888.yar
│   ├── spynote.yar
│   └── venom_rat.yar
└── analysis_result/
```

### Built-in YARA Rules

If no `yara_rules/` directory exists, the tool uses these internal signatures:

- **Suspicious_Overlay_Attack** - Banking trojan overlay patterns
- **APK_Dropper_Payload** - Nested APK detection
- **Native_Shell_Execution** - Shell command execution
- **Crypto_Ransomware_Pattern** - Encryption operations

### Custom YARA Rules Format

```yara
rule Your_Custom_Rule {
    meta:
        description = "Description of the malware"
        severity = "high"  // critical, high, medium, low
    strings:
        $a = "malicious_string"
        $b = "suspicious_api"
    condition:
        any of them
}
```

## Analysis Phases

### Phase 1: File Profiling
- MD5, SHA1, SHA256 hash calculation
- File size and entropy analysis
- Packing/encryption detection

### Phase 2: Androguard Loading
- DEX bytecode parsing
- Animated progress indicator
- Fallback for corrupted APKs

### Phase 3: Manifest & Certificate
- Certificate chain validation
- Debug certificate detection
- Dangerous permission enumeration
- Component analysis (activities, services, receivers, providers)
- Boot persistence detection

### Phase 4: Obfuscation Detection
- ProGuard/R8 detection via class name entropy
- Average name length calculation
- Obfuscation ratio metrics

### Phase 5: Hybrid Code Analysis
- Bytecode API tracing for accurate detection
- Raw string pattern matching for obfuscated code
- Detection of:
  - Encryption APIs
  - Command execution
  - SMS operations
  - Dynamic code loading
  - Reflection usage
  - Admin abuse

### Phase 6: Native & Nested Analysis
- Native library (.so) enumeration
- Shell payload detection in native code
- Nested APK/DEX dropper identification

### Phase 7: Network Security Config
- network_security_config.xml parsing
- Cleartext traffic permission detection
- MITM vulnerability assessment

### Phase 8: Anti-Analysis Detection
- Debugger detection
- Emulator detection
- Root detection
- Frida/instrumentation detection

### Phase 9: YARA Scan
- Malware signature matching
- Severity-based scoring
- Custom rule support

### Phase 10: Final Report
- Risk score calculation
- Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- JSON report generation
260130_143022.json


### Risk Score Classification

| Score Range | Severity | Description |
|-------------|----------|-------------|
| 100+ | CRITICAL | Highly malicious, immediate threat |
| 60-99 | HIGH | Significant security concerns |
| 30-59 | MEDIUM | Moderate risk, review recommended |
| 0-29 | LOW | Minor issues or clean |

## TODO

### Planned Features

- [ ] **Web UI Version** (Coming Soon)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

Email: pookielinuxuser@tutamail.com

---

**Made with Python** - Advanced static analysis for Android security research.

--- 

First Released : 30st January 2026

Last updated : 30st January 2026
