# Honeypot Project Documentation

**Innovation Lab 2 — FH Technikum Wien**
Team 11 · Supervisor: MSc. Recep Balıbey

---

## 1. Project Overview

This project collects raw logs from four distinct honeypot sensors — **Cowrie**, **Endlessh**, **Heralding**, and **Nginx** — each producing data in different formats (JSON Lines, syslog plain text, headless CSV). The goal of the normalization pipeline is to transform all of these heterogeneous sources into a single **Unified Common Event Schema (UCES)**, stored in a SQLite database, enabling cross-sensor correlation and analysis.

The pipeline consists of two stages entirely built using **Windows-native standard Python libraries** (`sqlite3`, `json`, `csv`, `re`, `pathlib`):

2. **`analyzer.py`** — Runs cross-sensor correlation queries and exports comprehensive analytical JSON reports.

---

## 2. Unified Common Event Schema (UCES)

All events, regardless of source, are stored in a single `events` table with this structure:

| Field | Type | Constraints | Description |
|:---|:---|:---|:---|
| `event_id` | `TEXT` | `PRIMARY KEY` | SHA-256 hash of key fields (ensures idempotency) |
| `timestamp` | `TEXT` | `NOT NULL` | ISO 8601 UTC timestamp of the event |
| `sensor_type` | `TEXT` | `NOT NULL` | Honeypot type: `cowrie`, `endlessh`, `heralding`, `nginx` |
| `sensor_instance` | `TEXT` | `NOT NULL` | Specific sensor ID, e.g. `sensor-cowrie-01` |
| `src_ip` | `TEXT` | `NOT NULL` | Attacker source IP address |
| `src_port` | `INTEGER` | nullable | Attacker ephemeral source port |
| `dst_port` | `INTEGER` | nullable | Target port on the honeypot |
| `event_category` | `TEXT` | `NOT NULL` | One of: `authentication_attempt`, `command_execution`, `connection_established`, `payload_delivery`, `other` |
| `payload` | `TEXT` | nullable | Context-dependent data (credentials, commands, URLs, etc.) |
| `session_id` | `TEXT` | nullable | Session identifier as reported by the sensor |
| `raw_data` | `TEXT` | nullable | First 1000 characters of the original log line |
| `src_country` | `TEXT` | nullable | Two-letter country code of the attacker IP (added via offline iptocc library) |
| `attack_type` | `TEXT` | `DEFAULT 'uncertain'` | Heuristic classification: `automated`, `human_or_manual`, or `uncertain` |

---

## 3. Common Event Structure — Field Mapping

The UCES brings all four honeypots under one roof by mapping each sensor's native fields into the shared schema:

| UCES Field | Cowrie (JSON) | Endlessh (syslog) | Heralding (CSV/JSON) | Nginx (JSON) |
|:---|:---|:---|:---|:---|
| `timestamp` | `timestamp` | ISO8601 from syslog line | `timestamp` (col 0) | `ts` |
| `sensor_type` | `"cowrie"` | `"endlessh"` | `"heralding"` | `"nginx"` |
| `sensor_instance` | `sensor` field | from directory path | from directory path | `sensor` field |
| `src_ip` | `src_ip` | `host` (regex) | `source_ip` (col 3) | `src_ip` |
| `src_port` | `src_port` | `port` (regex) | `source_port` (col 4) | `src_port` |
| `dst_port` | `dst_port` | — | `destination_port` (col 6) | `dst_port` |
| `event_category` | derived from `eventid` | always `connection_established` | `authentication_attempt` (auth.csv) / `connection_established` (session.json) | always `payload_delivery` |
| `payload` | varies by event type | — | `username:password` | `METHOD URI HTTP_VERSION` |
| `session_id` | `session` | — | `session_id` (col 2) | — |
| `raw_data` | full JSON line (truncated) | full syslog line (truncated) | full CSV/JSON line (truncated) | full JSON line (truncated) |

---

## 4. Parser Details

### 4.1 Cowrie Parser (SSH/Telnet)
**Input format:** JSON Lines (`cowrie.json.YYYY-MM-DD`)

| `eventid` pattern | → `event_category` | `payload` content |
|:---|:---|:---|
| `cowrie.login.success`, `cowrie.login.failed` | `authentication_attempt` | `username:password` |
| `cowrie.command.input`, `cowrie.client.*` | `command_execution` | `input` or `ttylog` field |
| `cowrie.session.connect`, `cowrie.session.closed` | `connection_established` | — |
| any event with `shasum` present | `payload_delivery` | `url` and/or `shasum` |
| everything else | `other` | `message` field |

### 4.2 Endlessh Parser (SSH Tarpit)
**Input format:** Syslog plain text (`endlessh-YYYY-MM-DD.log`)
A regex extracts the timestamp, action, IP address, and port. All Endlessh events map to `connection_established`.

### 4.3 Heralding Parser (Credential Harvester)
**Input format:** Headless CSV (`log_auth.csv`) and JSON Lines (`log_session.json`)
- `log_auth.csv` → `authentication_attempt` (Payload: `username:password`)
- `log_session.json` → `connection_established`

### 4.4 Nginx Parser (HTTP Honeypot)
**Input format:** JSON Lines (`access.log`, `honeypot_*.log`)
All Nginx events map to `payload_delivery`. The payload is assembled as `METHOD URI HTTP_VERSION`.

---

## 5. Normalization Workflow & Idempotency

The `normalizer.py` pipeline runs in three phases:
1. **Discovery** — Recursively walks the workspace identifying log files. 
2. **Parsing** — Feeds each file to its respective parser. An offline IP-to-Country geolocation library (`iptocc`) is used to append geographic data.
3. **Batch Insertion** — Buffers 50,000 records and executes `executemany()` into SQLite.

**Incremental File Processing (SQL-Based Deduplication):**
The pipeline uses deterministic SHA-256 hashing to generate the `event_id`:
`event_id = SHA-256( timestamp | sensor_instance | src_ip | event_category | payload )`

Before parsing an entire file, the script reads the first valid log line, generates its `event_id`, and runs a rapid SQL lookup. If the ID exists, the file is instantly bypassed. Furthermore, `INSERT OR IGNORE` silently skips any row whose `event_id` already exists. This allows adding new files seamlessly without fully recreating the database.

---

## 6. Attack Classification Methodology (Automated vs. Human)

The `attack_type` field categorizes events as `automated`, `human_or_manual`, or `uncertain`. This is a heuristic indicator, not strict forensic attribution.

### Cowrie
- **Automated:** Bot libraries (`SSH-2.0-Go`), scripts containing known malware signatures (e.g., `mdrfckr`, `lockr`), extreme command lengths (>100 chars per command line), or automated downloading utilities (`wget`, `curl`).
- **Human or Manual:** Detected strictly via a combination of interactive editor usage (`nano`, `vi`, `vim`) with a very low average command length (<20 chars), or explicit human typographical errors (e.g., typing `sudp`, `passwwd`). This strict heuristic eliminates sophisticated automated recon scripts that commonly abuse utilities like `top` or `ping`.

### Heralding
- **Automated:** High-speed brute-forcing (Auth attempts / duration > 2.0), or bot libraries.

### Nginx
- **Automated:** Scanner User-Agents (`zgrab`, `masscan`, `curl`), or blind exploit probing (`/.env`, `phpunit`, `PROPFIND`).

### Endlessh
- **Automated:** Clients staying connected >10.0 seconds, failing to recognize the tarpit.

**Uncertain:** Any mixed, ambiguous, or insufficient signals across all sensors default to `uncertain`.

---

## 7. Database Usage & Examples

You can query the database using standard `sqlite3` tools or the Python `sqlite3`/`pandas` libraries.

**A. Find the most active attacker IPs**
```sql
SELECT src_ip, COUNT(*) as event_count FROM events GROUP BY src_ip ORDER BY event_count DESC LIMIT 10;
```

**B. Extract harvested credentials**
```sql
SELECT timestamp, sensor_type, src_ip, payload as credentials FROM events WHERE event_category = 'authentication_attempt' ORDER BY timestamp DESC;
```

**C. Cross-Sensor Correlation**
```sql
SELECT src_ip, COUNT(DISTINCT sensor_type) as honeypot_types_hit FROM events GROUP BY src_ip HAVING honeypot_types_hit > 1 ORDER BY honeypot_types_hit DESC;
```

**D. Trace an attacker's complete journey**
```sql
SELECT timestamp, sensor_type, event_category, payload FROM events WHERE src_ip = '192.168.1.100' ORDER BY timestamp ASC;
```

Once all events are unified, the `db_analyzer.py` script automatically runs these advanced correlation queries across the full dataset to generate analytical reports, which are then formatted by `md-generator.py`.
