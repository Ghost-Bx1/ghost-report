# Ghost-Report

> Pentest report generator - ingests JSON output from any ghost-* tool and produces HTML or Markdown reports.

```
  GHOST-REPORT  v1.0.0  |  Unified Pentest Report Generator
  By Gh0st-Bx1          |  github.com/Ghost-Bx1
```

![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
![Category](https://img.shields.io/badge/Category-Reporting-green?style=flat-square)

---

## Overview

Ghost-Report is the reporting layer of the Ghost toolkit. It accepts JSON output from any ghost-* tool and generates professional reports with executive summary, risk scoring, severity breakdown, and per-finding remediation guidance.

**Supported input sources:**

| Tool          | Description                        |
|---------------|------------------------------------|
| ghost-recon   | Reconnaissance findings            |
| ghost-fuzz    | Web fuzzing results                |
| ghost-cloud   | Cloud misconfiguration findings    |
| ghost-osint   | OSINT intelligence data            |
| Any JSON      | Files with a `findings` array      |

**Report contents:**

- Executive summary with risk score and finding counts by severity
- Severity breakdown: Critical / High / Medium / Low / Info
- Per-finding: title, severity badge, category, description, evidence
- Per-category remediation guidance
- Dark theme HTML optimized for screen sharing and delivery

---

## Requirements

```
Python 3.6+
No external dependencies (stdlib only)
```

---

## Installation

```bash
git clone https://github.com/Ghost-Bx1/ghost-report
cd ghost-report
python ghost-report.py --help
```

---

## Usage

```bash
# Report from a single JSON file
python ghost-report.py --input recon.json --output report.html

# Merge multiple JSON files into one report
python ghost-report.py --input cloud.json fuzz.json --output report.html

# Report from a folder of JSON files
python ghost-report.py --input results/ --output report.md --format markdown

# Generate demo report with sample data
python ghost-report.py --demo --output demo-report.html

# Full options
python ghost-report.py --input cloud.json fuzz.json \
    --title "Red Team 2026" \
    --author "Gh0st-Bx1" \
    --target example.com \
    --output report.html
```

### Typical workflow with other ghost tools

```bash
python ghost-recon.py -d example.com --completo -o recon.json
python ghost-cloud.py -t example.com --all -o cloud.json
python ghost-fuzz.py dir -u https://example.com -o fuzz.json
python ghost-report.py --input recon.json cloud.json fuzz.json --output report.html
```

---

## Reference

| Flag              | Description                                          |
|-------------------|------------------------------------------------------|
| `--input / -i`    | JSON file(s) or directory from any ghost-* tool      |
| `--output / -o`   | Output file (.html or .md)                           |
| `--format`        | Output format: html (default) or markdown            |
| `--title`         | Report title                                         |
| `--author`        | Author name (default: Gh0st-Bx1)                    |
| `--target`        | Target name or domain                                |
| `--demo`          | Generate demo report with sample findings            |

---

## Disclaimer

For use in authorized environments only. Penetration testing, CTF competitions, and offensive security research with explicit permission from the environment owner. The author is not responsible for misuse.

---

**By [Gh0st-Bx1](https://github.com/Ghost-Bx1)**
