# ghost-report

**Unified Pentest Report Generator**

By Gh0st-Bx1 | github.com/Ghost-Bx1

---

## Description

ghost-report ingests JSON output from any ghost-* tool and generates professional HTML or Markdown pentest reports. It includes an executive summary, risk score, severity breakdown, and per-finding remediation guidance.

## Usage

```
python ghost-report.py --input recon.json --output report.html
python ghost-report.py --input *.json --output report.html
python ghost-report.py --input results/ --output report.md --format markdown
python ghost-report.py --demo --output demo-report.html
python ghost-report.py --input cloud.json fuzz.json --title "Red Team 2026" --author "Gh0st-Bx1" --target example.com
```

## Options

| Flag | Description |
|------|-------------|
| `--input` / `-i` | JSON file(s) or folder from any ghost-* tool |
| `--output` / `-o` | Output file (.html or .md) |
| `--format` | Output format: `html` (default) or `markdown` |
| `--title` | Report title |
| `--author` | Author name (default: Gh0st-Bx1) |
| `--target` | Target name/domain |
| `--demo` | Generate demo report with sample data |

## Report Contents

- **Executive Summary** - risk score, finding counts by severity
- **Stat Cards** - Critical / High / Medium / Low / Info breakdown
- **Findings List** - title, severity badge, category, description, evidence
- **Remediation** - per-category remediation steps
- **Dark Theme** - professional dark UI optimized for screen sharing

## Supported Input

ghost-report accepts JSON from any ghost-* tool:
- ghost-recon (reconnaissance)
- ghost-fuzz (web fuzzing)
- ghost-cloud (cloud misconfigs)
- ghost-osint (OSINT)
- Any JSON with `findings` array or flat finding objects

## Requirements

- Python 3.6+
- No external dependencies (stdlib only)
