# Honeypots Normalization Pipeline

**Innovation Lab 2 — FH Technikum Wien | Team 11**  
Supervisor: MSc. Recep Balıbey

---

## Overview

This project collects raw logs from four honeypot sensors (**Cowrie**, **Endlessh**, **Heralding**, and **Nginx**) and normalizes them into a single Unified Common Event Schemastored in a SQLite database. The unified dataset enables cross-sensor correlation and attacker behavior analysis.

For the data analysis read docs/analysis_normalized_data.md.

The py-scripts are build for Windows.

> **Note:** The `blob/` directory (raw log files) and `honeypot_normalized.db` (~18 GB) are **not included** in this repository due to their size. Raw logs can be downloaded from **Azure Blob Storage**.

---

## Folder Structure

```
honeypots-normalization/
├── blob/                          # Raw honeypot log files (NOT in repo — download from Azure)
│   ├── cowrie/                    #   JSON Lines logs (SSH/Telnet honeypot)
│   ├── endlessh/                  #   Syslog plain-text logs (SSH tarpit)
│   ├── heralding/                 #   CSV + JSON Lines logs (credential harvester)
│   └── nginx/                     #   JSON Lines logs (HTTP honeypot)
│
├── scripts/                       # Python pipeline scripts
│   ├── normalizer.py              #   Parses all sensors → inserts into SQLite (UCES)
│   ├── analyzer4_results.py       #   Reads analysis JSON → renders Markdown report
│   └── analysis_normalized_data.md-generator.py  # Generates the analysis doc
│
├── scripts-out/                   # Script output files
│   └── analyzer4_results.json     # Cross-sensor analysis results (JSON)
│
├── docs/                          # Project documentation
│   ├── project_documentation.md   # Full schema, parser details, workflow
│   └── analysis_normalized_data.md# Data analysis and answers to interesting questions
│
└── honeypot_normalized.db         # Unified SQLite database (~18 GB, NOT in repo)
```

---

## Unified Common Event Schema (UCES)

All events are stored in a single `events` table:

| Field | Type | Description |
|---|---|---|
| `event_id` | TEXT (PK) | SHA-256 hash — ensures idempotency |
| `timestamp` | TEXT | ISO 8601 UTC |
| `sensor_type` | TEXT | `cowrie`, `endlessh`, `heralding`, `nginx` |
| `sensor_instance` | TEXT | Specific sensor ID |
| `src_ip` | TEXT | Attacker source IP |
| `src_port` | INTEGER | Attacker ephemeral port |
| `dst_port` | INTEGER | Target port on the honeypot |
| `event_category` | TEXT | `authentication_attempt`, `command_execution`, `connection_established`, `payload_delivery`, `other` |
| `payload` | TEXT | Credentials, commands, URLs, etc. |
| `session_id` | TEXT | Session identifier |
| `raw_data` | TEXT | First 1000 chars of original log line |
| `src_country` | TEXT | Two-letter country code (via `iptocc`) |
| `attack_type` | TEXT | `automated`, `human_or_manual`, or `uncertain` |

---

## Pipeline Usage

### 1. Download raw logs
Download the `blob/` directory from **Azure Blob Storage** and place it at `C:\honeypots-normalization\blob\`.

### 2. Install dependencies
```bash
pip install iptocc
```

### 3. Run the normalizer
```bash
python scripts/normalizer.py
```
This parses all log files, performs SHA-256-based deduplication, and inserts events into `honeypot_normalized.db`. The pipeline is **incremental** — re-running it safely skips already-processed files.

### 4. Run the analyzer
```bash
python scripts/analyzer4_results.py
```
Reads `scripts-out/analyzer4_results.json` and renders the Markdown analysis report.

---

## Dataset Summary (Jan – June 2026)

| Honeypot | Total Events | Unique IPs |
|---|---|---|
| Cowrie | 12,684,265 | 26,194 |
| Heralding | 8,684,631 | 27,319 |
| Nginx | 37,451 | 3,886 |
| Endlessh | 1,367 | 302 |
| **Total** | **21,407,714** | — |

---

## Documentation

- [`docs/project_documentation.md`](docs/project_documentation.md) — Full schema, parser details, attack classification methodology, and query examples.
- [`docs/analysis_normalized_data.md`](docs/analysis_normalized_data.md) — Gathered Data.
