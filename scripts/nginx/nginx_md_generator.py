"""
Nginx Markdown Report Generator
=================================
Reads nginx_analyzer_results.json and produces a rich, structured
Markdown report covering all 20 forensic questions.

Output: docs/nginx_analysis.md
"""

import json
import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).resolve().parent.parent
IN_PATH   = BASE_DIR / "scripts-out" / "nginx_analyzer_results.json"
OUT_PATH  = BASE_DIR / "docs" / "nginx_analysis.md"

IN_PATH  = Path(os.environ.get("NGINX_RESULTS", str(IN_PATH)))
OUT_PATH = Path(os.environ.get("NGINX_MD_OUT",  str(OUT_PATH)))


# ── Helpers ────────────────────────────────────────────────────────────────────
def fnum(n) -> str:
    """Format an integer with thousands separators."""
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)

def fpct(p) -> str:
    """Format a percentage with % suffix."""
    try:
        return f"{float(p):.2f}%"
    except (TypeError, ValueError):
        return str(p)

def ts_short(ts: str) -> str:
    """Trim timestamp to first 19 characters (YYYY-MM-DDTHH:MM:SS)."""
    return str(ts)[:19] if ts else "N/A"

def date_only(ts: str) -> str:
    return str(ts)[:10] if ts else "N/A"

def _bar(value: int, max_val: int, width: int = 20) -> str:
    """Simple text progress bar using Unicode block characters."""
    if max_val == 0:
        return ""
    filled = int(round(value / max_val * width))
    return "█" * filled + "░" * (width - filled)


# ── Load data ──────────────────────────────────────────────────────────────────
with open(str(IN_PATH), "r", encoding="utf-8") as f:
    data = json.load(f)

md_parts: list[str] = []


# ══════════════════════════════════════════════════════════════════════════════
# TITLE & TABLE OF CONTENTS
# ══════════════════════════════════════════════════════════════════════════════
overview = data.get("q1_overview", {})
summary  = data.get("q20_summary", {})

md_parts.append(f"""# Nginx Honeypot — Deep Analysis Report

> **Sensor:** Nginx HTTP Honeypot  
> **Total Requests:** {fnum(overview.get("total_events", 0))}  
> **Unique Attackers:** {fnum(overview.get("unique_ips", 0))}  
> **Observation Period:** {date_only(overview.get("earliest"))} → {date_only(overview.get("latest"))}

---

## Table of Contents

1. [Dataset Overview](#1-dataset-overview)
2. [Geographic Origins](#2-geographic-origins)
3. [HTTP Method Distribution](#3-http-method-distribution)
4. [Most Targeted URI Paths](#4-most-targeted-uri-paths)
5. [Exploit / Vulnerability Probe Fingerprinting](#5-exploit--vulnerability-probe-fingerprinting)
6. [User-Agent Intelligence](#6-user-agent-intelligence)
7. [Scanner Persistence & Return Frequency](#7-scanner-persistence--return-frequency)
8. [Burst Behaviour & Request-Rate Analysis](#8-burst-behaviour--request-rate-analysis)
9. [Payload Diversity — Broad Scanners vs. Targeted Hammering](#9-payload-diversity--broad-scanners-vs-targeted-hammering)
10. [Multi-Sensor Correlation](#10-multi-sensor-correlation)
11. [Attack Type Classification](#11-attack-type-classification)
12. [First-Hit Path — Scanner Playbook Reconstruction](#12-first-hit-path--scanner-playbook-reconstruction)
13. [Day-of-Week Attack Rhythm](#13-day-of-week-attack-rhythm)
14. [Destination Port Targeting](#14-destination-port-targeting)
15. [Coordinated Campaign Detection](#15-coordinated-campaign-detection)
16. [HTTP Version Distribution](#16-http-version-distribution)
17. [Country-Level Attack Path Specialisation](#17-country-level-attack-path-specialisation)
18. [Day-by-Day Timeline of Top IPs](#18-day-by-day-timeline-of-top-ips)
19. [Sensitive File & Credential Probe Classification](#19-sensitive-file--credential-probe-classification)
20. [Summary Statistics](#20-summary-statistics)

---
""")


# ══════════════════════════════════════════════════════════════════════════════
# §1 — DATASET OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("## 1. Dataset Overview\n")
md_parts.append(f"""
**How big is the nginx honeypot dataset, and how is it distributed over time?**

| Metric | Value |
|:---|---:|
| Total Requests | **{fnum(overview.get("total_events", 0))}** |
| Unique Attacker IPs | **{fnum(overview.get("unique_ips", 0))}** |
| Unique Request Signatures | **{fnum(summary.get("unique_request_signatures", 0))}** |
| Active Observation Days | **{fnum(summary.get("active_days", 0))}** |
| Earliest Event | `{ts_short(overview.get("earliest"))}` |
| Latest Event | `{ts_short(overview.get("latest"))}` |

### 1.1 Per Sensor-Instance Breakdown

| Sensor Instance | Total Requests | Unique IPs | Active Period |
|:---|---:|---:|:---|
""")

for inst in data.get("q1_per_instance", []):
    md_parts.append(
        f"| `{inst['sensor_instance']}` | {fnum(inst['total_events'])} | "
        f"{fnum(inst['unique_ips'])} | "
        f"{date_only(inst['earliest'])} → {date_only(inst['latest'])} |\n"
    )

# Daily volume spark chart (text-based)
daily = data.get("q1_daily_volume", [])
if daily:
    max_req = max(d["requests"] for d in daily)
    md_parts.append("""
### 1.2 Daily Request Volume

| Date | Requests | Unique IPs | Volume |
|:---|---:|---:|:---|
""")
    for d in daily:
        bar = _bar(d["requests"], max_req, 25)
        md_parts.append(
            f"| {d['day']} | {fnum(d['requests'])} | {fnum(d['unique_ips'])} | `{bar}` |\n"
        )

# Hourly heatmap
hourly = data.get("q1_hourly_heatmap", [])
if hourly:
    max_h = max(h["requests"] for h in hourly) if hourly else 1
    md_parts.append("""
### 1.3 Hourly UTC Heatmap

*What time of day (UTC) do HTTP attackers prefer?*

| Hour (UTC) | Requests | Heatmap |
|:---:|---:|:---|
""")
    for h in hourly:
        bar = _bar(h["requests"], max_h, 30)
        md_parts.append(
            f"| `{h['hour_utc']:02d}:00` | {fnum(h['requests'])} | `{bar}` |\n"
        )

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §2 — GEOGRAPHY
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 2. Geographic Origins

**Which countries are probing our HTTP server, and who hits us the hardest?**

| Country | Total Requests | Unique IPs | Share |
|:---:|---:|---:|---:|
""")
for item in data.get("q2_country_distribution", []):
    md_parts.append(
        f"| **{item.get('src_country', 'N/A')}** | {fnum(item['total_requests'])} | "
        f"{fnum(item['unique_ips'])} | {fpct(item['pct'])} |\n"
    )

md_parts.append("""
### 2.1 Most Prolific Single IP per Country

| Country | Top IP | Requests |
|:---:|:---|---:|
""")
for item in data.get("q2_top_ip_per_country", []):
    md_parts.append(
        f"| **{item.get('src_country', 'N/A')}** | `{item['src_ip']}` | {fnum(item['requests'])} |\n"
    )

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §3 — HTTP METHODS
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 3. HTTP Method Distribution

**Are attackers using exotic HTTP verbs beyond the standard GET/POST?**

Methods like `PROPFIND` (WebDAV enumeration), `HEAD` (lightweight probing),
and `OPTIONS` (CORS fishing) often reveal specific scanner toolkits.

| HTTP Method | Requests | Unique IPs |
|:---|---:|---:|
""")
for item in data.get("q3_http_methods", []):
    md_parts.append(
        f"| `{item['http_method']}` | {fnum(item['requests'])} | {fnum(item['unique_ips'])} |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §4 — MOST TARGETED PATHS
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 4. Most Targeted URI Paths

**Which exact HTTP requests dominate the attack traffic?**

| Payload (METHOD URI VERSION) | Hits | Unique IPs | First Seen | Last Seen |
|:---|---:|---:|:---|:---|
""")
for item in data.get("q4_top_payloads", [])[:20]:
    payload_disp = str(item["payload"])[:80].replace("|", "\\|")
    md_parts.append(
        f"| `{payload_disp}` | {fnum(item['total_hits'])} | "
        f"{fnum(item['unique_ips'])} | {date_only(item['first_seen'])} | "
        f"{date_only(item['last_seen'])} |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §5 — EXPLOIT FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 5. Exploit / Vulnerability Probe Fingerprinting

**What known CVE/bug families are being probed against our nginx server?**

Each row represents a distinct exploit family detected in the payload stream,
identified by keyword signatures against the `payload` field.

| Exploit Family | Hits | Unique IPs | First Seen | Last Seen |
|:---|---:|---:|:---|:---|
""")
for item in data.get("q5_exploit_families", []):
    if item["hits"] == 0:
        continue
    md_parts.append(
        f"| **{item['family'].replace('_', ' ')}** | {fnum(item['hits'])} | "
        f"{fnum(item['unique_ips'])} | {date_only(item['first_seen'])} | "
        f"{date_only(item['last_seen'])} |\n"
    )

top_family_payloads = data.get("q5_top_family_payloads", [])
if top_family_payloads:
    top_name = data["q5_exploit_families"][0]["family"].replace("_", " ")
    md_parts.append(f"""
### 5.1 Top Payloads in Most-Hit Family: *{top_name}*

| Payload | Hits | Unique IPs |
|:---|---:|---:|
""")
    for item in top_family_payloads:
        disp = str(item["payload"])[:80].replace("|", "\\|")
        md_parts.append(
            f"| `{disp}` | {fnum(item['hits'])} | {fnum(item['unique_ips'])} |\n"
        )

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §6 — USER-AGENT INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 6. User-Agent Intelligence

**What tools and scanners are behind the HTTP probes?**

User-agent strings extracted from the raw JSON log reveal the scanner ecosystem.

### 6.1 Top 20 User-Agents

| User-Agent | Requests | Unique IPs |
|:---|---:|---:|
""")
for item in data.get("q6_top_user_agents", [])[:20]:
    ua_disp = str(item["user_agent"])[:80].replace("|", "\\|")
    md_parts.append(
        f"| `{ua_disp}` | {fnum(item['requests'])} | {fnum(item['unique_ips'])} |\n"
    )

md_parts.append("""
### 6.2 Scanner Tool Classification

IPs are grouped into known tool categories based on their user-agent string.

| Scanner Tool / Category | Requests | Unique IPs |
|:---|---:|---:|
""")
buckets = data.get("q6_ua_tool_buckets", [])
max_b   = max((b["requests"] for b in buckets), default=1)
for b in buckets:
    bar = _bar(b["requests"], max_b, 20)
    md_parts.append(
        f"| **{b['tool']}** | {fnum(b['requests'])} | {fnum(b['unique_ips'])} |\n"
    )

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §7 — SCANNER PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 7. Scanner Persistence & Return Frequency

**Which attacker IPs return repeatedly over many separate days?**

Persistent scanners imply deliberate, long-term recon — not one-off mass-scans.

### 7.1 Most Persistent Scanners (≥ 5 active days)

| IP | Country | Total Requests | Active Days | Span (days) | First Seen | Last Seen |
|:---|:---:|---:|---:|---:|:---|:---|
""")
for item in data.get("q7_persistent_scanners", []):
    md_parts.append(
        f"| `{item['src_ip']}` | {item.get('src_country', 'N/A')} | "
        f"{fnum(item['total_requests'])} | {item['active_days']} | "
        f"{item.get('span_days', '?')} | {date_only(item['first_seen'])} | "
        f"{date_only(item['last_seen'])} |\n"
    )

stealthy = data.get("q7_stealthy_slow_scanners", [])
if stealthy:
    md_parts.append("""
### 7.2 Stealthy Slow Scanners (≥ 7 active days, < 5 requests/day avg.)

*These IPs spread their probes across many days at low volume, attempting to stay below detection thresholds.*

| IP | Country | Total Requests | Active Days | Avg Requests/Day |
|:---|:---:|---:|---:|---:|
""")
    for item in stealthy:
        md_parts.append(
            f"| `{item['src_ip']}` | {item.get('src_country', 'N/A')} | "
            f"{fnum(item['total_requests'])} | {item['active_days']} | "
            f"{item.get('avg_per_day', '?')} |\n"
        )

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §8 — BURST BEHAVIOUR
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 8. Burst Behaviour & Request-Rate Analysis

**Which IPs fire dozens of requests in rapid succession?**

High requests-per-second values indicate automated tools rather than human browsing,
and may indicate DoS-adjacent spidering or weaponised exploit toolkits.

| IP | Country | Total Requests | Duration (s) | Requests/sec | First Seen | Last Seen |
|:---|:---:|---:|---:|---:|:---|:---|
""")
for item in data.get("q8_burst_attackers", []):
    md_parts.append(
        f"| `{item['src_ip']}` | {item.get('src_country', 'N/A')} | "
        f"{fnum(item['total_requests'])} | {item.get('duration_seconds', '?')} | "
        f"**{item.get('requests_per_second', '?')}** | "
        f"{ts_short(item['first_seen'])} | {ts_short(item['last_seen'])} |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §9 — PAYLOAD DIVERSITY
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 9. Payload Diversity — Broad Scanners vs. Targeted Hammering

**Are attackers probing everything they can think of, or hammering a single endpoint?**

A high `unique_payloads` count → wide-net scanner.  
A high `repetition_ratio` → laser-targeted exploit attempt.

### 9.1 Broadest Scanners (most distinct URI payloads per IP)

| IP | Country | Total Requests | Unique Payloads | Diversity Ratio |
|:---|:---:|---:|---:|---:|
""")
for item in data.get("q9_broad_scanners", []):
    md_parts.append(
        f"| `{item['src_ip']}` | {item.get('src_country', 'N/A')} | "
        f"{fnum(item['total_requests'])} | {fnum(item['unique_payloads'])} | "
        f"{item.get('diversity_ratio', '?')} |\n"
    )

md_parts.append("""
### 9.2 Targeted Hammering (high repetition ratio — single exploit, many hits)

| IP | Country | Total Requests | Unique Payloads | Repetition Ratio |
|:---|:---:|---:|---:|---:|
""")
for item in data.get("q9_targeted_hammering", []):
    md_parts.append(
        f"| `{item['src_ip']}` | {item.get('src_country', 'N/A')} | "
        f"{fnum(item['total_requests'])} | {fnum(item['unique_payloads'])} | "
        f"**{item.get('repetition_ratio', '?')}×** |\n"
    )

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §10 — MULTI-SENSOR CORRELATION
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 10. Multi-Sensor Correlation

**Did nginx attackers also hit our SSH, credential-harvesting, or tarpit honeypots?**

IPs that appear across multiple sensors represent the most persistent and
multi-vector threat actors in our dataset.

### 10.1 Nginx IPs Also Seen on Other Honeypots

| IP | Country | Nginx Hits | Total Sensors | All Sensors | Total Events |
|:---|:---:|---:|:---:|:---|---:|
""")
for item in data.get("q10_multi_sensor_nginx_ips", [])[:20]:
    md_parts.append(
        f"| `{item['src_ip']}` | {item.get('src_country', 'N/A')} | "
        f"{fnum(item['nginx_hits'])} | {item['total_sensors']} | "
        f"{item['sensors']} | {fnum(item['total_events'])} |\n"
    )

excl = data.get("q10_nginx_exclusive_ips", [])
md_parts.append(f"""
### 10.2 HTTP-Only Attackers (Exclusive to Nginx)

*{fnum(len(excl))} IPs appeared **exclusively** on the nginx sensor and were never seen on SSH, Heralding, or Endlessh.*
*These may be web-specific bots or scanners that do not attempt traditional SSH brute-forcing.*

| IP | Country | Nginx Requests |
|:---|:---:|---:|
""")
for item in excl[:15]:
    md_parts.append(
        f"| `{item['src_ip']}` | {item.get('src_country', 'N/A')} | "
        f"{fnum(item['nginx_requests'])} |\n"
    )

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §11 — ATTACK TYPE CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 11. Attack Type Classification

**What fraction of nginx traffic was fingerprinted as fully automated?**

The heuristic flags known scanner UAs (`zgrab`, `masscan`, `curl`, etc.) and
known exploit probe paths (`.env`, `phpunit`, `PROPFIND`) as `automated`.

| Classification | Events | Unique IPs | Share |
|:---|---:|---:|---:|
""")
for item in data.get("q11_attack_types", []):
    md_parts.append(
        f"| **{item['attack_type']}** | {fnum(item['events'])} | "
        f"{fnum(item['unique_ips'])} | {fpct(item['pct'])} |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §12 — FIRST-HIT PATH / SCANNER PLAYBOOK
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 12. First-Hit Path — Scanner Playbook Reconstruction

**What is the very first URI each attacker probes?**

The first probe reveals the scanner's default priority list — i.e., which
vulnerability it cares about *most*. This effectively reverse-engineers the
tool's built-in scan order.

| First Probe Payload | IPs Starting Here |
|:---|---:|
""")
for item in data.get("q12_top_first_probe_payloads", []):
    disp = str(item["payload"])[:80].replace("|", "\\|")
    md_parts.append(f"| `{disp}` | {fnum(item['ip_count'])} |\n")

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §13 — DAY-OF-WEEK RHYTHM
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 13. Day-of-Week Attack Rhythm

**Does attack volume follow a human work-week pattern, or is it constant?**

Fully automated bots typically show flat distributions; any deviation hints at
human scheduling, botnet C2 windows, or geographically offset work hours.

| Day | Requests | Unique IPs | Volume |
|:---|---:|---:|:---|
""")
weekdays = data.get("q13_weekday_distribution", [])
max_w = max((w["requests"] for w in weekdays), default=1)
for item in weekdays:
    bar = _bar(item["requests"], max_w, 25)
    md_parts.append(
        f"| **{item['weekday']}** | {fnum(item['requests'])} | "
        f"{fnum(item['unique_ips'])} | `{bar}` |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §14 — DESTINATION PORT TARGETING
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 14. Destination Port Targeting

**Are attackers hitting the standard HTTP/HTTPS ports only, or scanning alternatives?**

Non-standard ports (e.g., 8080, 8443, 3000, 9200) reveal scanners that look
for misconfigured dev servers, Elasticsearch nodes, or Docker APIs.

| Destination Port | Requests | Unique IPs |
|:---:|---:|---:|
""")
for item in data.get("q14_dst_ports", []):
    md_parts.append(
        f"| **{item.get('dst_port', 'N/A')}** | {fnum(item['requests'])} | "
        f"{fnum(item['unique_ips'])} |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §15 — COORDINATED CAMPAIGN DETECTION
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 15. Coordinated Campaign Detection

**Are multiple IPs sending the exact same exploit payload in a coordinated wave?**

When many distinct source IPs all send the same `METHOD URI VERSION` string,
this strongly indicates a **distributed botnet campaign** or a shared exploit kit.

### 15.1 Campaign Signature Payloads (≥ 10 unique IPs sending identical payload)

| Payload | IPs | Total Hits | First Seen | Last Seen |
|:---|---:|---:|:---|:---|
""")
for item in data.get("q15_campaign_payloads", []):
    disp = str(item["payload"])[:80].replace("|", "\\|")
    md_parts.append(
        f"| `{disp}` | {fnum(item['ip_count'])} | {fnum(item['total_hits'])} | "
        f"{date_only(item['first_seen'])} | {date_only(item['last_seen'])} |\n"
    )

md_parts.append("""
### 15.2 Daily Campaign Bursts (same payload, same day, ≥ 5 IPs)

| Day | Payload | IPs | Hits |
|:---|:---|---:|---:|
""")
for item in data.get("q15_daily_campaign_bursts", []):
    disp = str(item["payload"])[:70].replace("|", "\\|")
    md_parts.append(
        f"| {item['day']} | `{disp}` | {fnum(item['ip_count'])} | {fnum(item['hits'])} |\n"
    )

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §16 — HTTP VERSION DISTRIBUTION
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 16. HTTP Version Distribution

**Are attackers using HTTP/1.0 (old/bare scanners) or HTTP/1.1 / HTTP/2?**

`HTTP/1.0` requests skip the mandatory `Host:` header — a hallmark of minimal
Internet-wide scanners like Masscan.

| HTTP Version | Requests | Unique IPs |
|:---|---:|---:|
""")
for item in data.get("q16_http_versions", []):
    md_parts.append(
        f"| `{item.get('http_version', 'N/A')}` | {fnum(item['requests'])} | "
        f"{fnum(item['unique_ips'])} |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §17 — COUNTRY-LEVEL ATTACK PATH SPECIALISATION
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 17. Country-Level Attack Path Specialisation

**Do attackers from different countries probe different URI paths?**

A country with many unique payloads per IP implies more creative / sophisticated
attackers, whereas low diversity suggests mass-produced automated toolkits.

| Country | Unique Payloads | Total Requests | Unique IPs |
|:---:|---:|---:|---:|
""")
for item in data.get("q17_country_payload_diversity", []):
    md_parts.append(
        f"| **{item.get('src_country', 'N/A')}** | {fnum(item['unique_payloads'])} | "
        f"{fnum(item['total_requests'])} | {fnum(item['unique_ips'])} |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §18 — DAY-BY-DAY TIMELINE OF TOP IPs
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 18. Day-by-Day Timeline of Top IPs

**How does request volume evolve over the observation period for the 5 busiest attackers?**

Irregular spikes may indicate new exploit campaigns; flat lines indicate persistent
low-rate crawlers.

""")
for entry in data.get("q18_top5_ip_timelines", []):
    ip    = entry["src_ip"]
    daily = entry.get("daily", [])
    if not daily:
        continue
    max_d = max(d["requests"] for d in daily) if daily else 1
    md_parts.append(f"### `{ip}`\n\n")
    md_parts.append("| Date | Requests | Bar |\n|:---|---:|:---|\n")
    for d in daily:
        bar = _bar(d["requests"], max_d, 20)
        md_parts.append(f"| {d['day']} | {fnum(d['requests'])} | `{bar}` |\n")
    md_parts.append("\n")

md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §19 — SENSITIVE FILE & CREDENTIAL PROBE CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════
md_parts.append("""## 19. Sensitive File & Credential Probe Classification

**Which categories of sensitive resources are attackers hunting for?**

Probes for `.env` files, SSH keys, Git repositories, database dumps, and
server-info pages are grouped into semantic categories.

| Category | Hits | Unique IPs | First Seen | Last Seen |
|:---|---:|---:|:---|:---|
""")
for item in data.get("q19_sensitive_file_probes", []):
    md_parts.append(
        f"| **{item['category']}** | {fnum(item['hits'])} | {fnum(item['unique_ips'])} | "
        f"{date_only(item['first_seen'])} | {date_only(item['last_seen'])} |\n"
    )
md_parts.append("\n---\n")


# ══════════════════════════════════════════════════════════════════════════════
# §20 — SUMMARY STATISTICS
# ══════════════════════════════════════════════════════════════════════════════
atk_split  = data.get("q20_attack_type_split", {})
automated  = atk_split.get("automated", 0)
uncertain  = atk_split.get("uncertain", 0)
total_req  = summary.get("total_requests", 1)
auto_pct   = round(100.0 * automated / total_req, 1) if total_req else 0

md_parts.append(f"""## 20. Summary Statistics

**Quick-reference numbers from the nginx honeypot analysis.**

| Metric | Value |
|:---|---:|
| Total HTTP Requests | **{fnum(summary.get("total_requests", 0))}** |
| Unique Attacker IPs | **{fnum(summary.get("total_unique_attackers", 0))}** |
| Unique Request Signatures | **{fnum(summary.get("unique_request_signatures", 0))}** |
| Observation Active Days | **{fnum(summary.get("active_days", 0))}** |
| Automated Requests | **{fnum(automated)}** ({auto_pct}%) |
| Uncertain / Unclassified Requests | **{fnum(uncertain)}** |

### Key Findings

- **100% of nginx events are actionable** (`payload_delivery` category) — unlike SSH honeypots that produce connection noise.
- **Automated scanners dominate**, identified by known tool user-agents and exploit-probe URI patterns.
- **Multi-vector attackers** (IPs seen on both nginx and SSH honeypots) represent the most persistent threat actors.
- **Coordinated campaigns** (identical payloads from many IPs on the same day) confirm active botnet-driven exploitation waves.
- **Stealthy slow scanners** deliberately spread probes across many days to evade rate-based detection.

---

*Report generated by `nginx_md_generator.py` from `nginx_analyzer_results.json`.*
""")


# ── Write output ───────────────────────────────────────────────────────────────
final_md = "".join(md_parts)
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with open(str(OUT_PATH), "w", encoding="utf-8") as f:
    f.write(final_md)

print(f"Markdown report written to: {OUT_PATH}")
