"""
Markdown Report Generator for Honeypot Unified Analytics

Reads scripts-out/analyzer_results.json and renders a comprehensive,
visually rich Markdown report at docs/analysis_normalized_data.md.
All metrics, percentages, counts, and findings are 100% dynamically
derived from the JSON telemetry data. Sections whose data is missing
(e.g. an older analyzer_results.json) are skipped with a short note.
"""

import json
import sys
from pathlib import Path

# Dynamic path resolution: prefer C:\honeypots-normalization if exists, else repo root
C_IN_JSON = Path(r'C:\honeypots-normalization\scripts-out\analyzer_results.json')
C_OUT_MD = Path(r'C:\honeypots-normalization\docs\analysis_normalized_data.md')

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_IN_JSON = REPO_ROOT / 'scripts-out' / 'analyzer_results.json'
REPO_OUT_MD = REPO_ROOT / 'docs' / 'analysis_normalized_data.md'

JSON_PATH = C_IN_JSON if C_IN_JSON.exists() else REPO_IN_JSON
MD_PATH = C_OUT_MD if C_OUT_MD.parent.exists() else REPO_OUT_MD

SENSORS = [
    ('cowrie', 'Cowrie', 'SSH / Telnet Honeypot'),
    ('heralding', 'Heralding', 'Credential Harvester'),
    ('nginx', 'Nginx', 'HTTP Honeypot'),
    ('endlessh', 'Endlessh', 'SSH Tarpit'),
]

CADENCE_DESC = {
    'Burst Script (< 0.5s)': 'Commands sent faster than a person can type (scripted loaders)',
    'Fast Bot Recon (0.5s - 2.0s)': 'Bots that wait for each prompt before sending the next command',
    'Paced Script (2.0s - 5.0s)': 'Throttled scripts or slow network paths',
    'Human Interactive Pace (>= 5.0s)': 'Typing pace of a person, or scripts with sleeps',
    'Single Command / No Gap': 'Only one command, no gap measurable',
}

ARCHETYPE_DESC = {
    '1. Single-Command Probe': 'One check or one-liner payload, then disconnect',
    '2. Multi-Stage Diverse Malware Chain': 'Many different commands: recon, download, execute',
    '3. Monotonous Redundant Looper': 'Same commands repeated, polling or broken loops',
    '4. Standard Automated Recon': 'Typical bot script with some repetition',
    '5. Brief Interaction (2-4 Cmds)': 'Short scripted check',
}

INTENT_DESC = {
    'recon': 'System fingerprinting (uname, /proc/cpuinfo, nproc, free ...)',
    'download': 'Fetching tools or malware (wget, curl, tftp, /dev/tcp)',
    'execute': 'Making files executable or running them (chmod +x, ./x, | sh)',
    'persistence': 'Keeping access (authorized_keys, crontab, chpasswd, useradd)',
    'cleanup_evasion': 'Hiding traces or removing competitors (history -c, rm -rf, pkill, iptables)',
    'cryptomining': 'Miner indicators (xmrig, stratum+tcp, c3pool, kinsing)',
    'iot_botnet_probe': 'Mirai-style busybox checks (/bin/busybox XXXX)',
}

# Helper functions
def fnum(n):
    """Format numbers with comma separators."""
    if n is None: return "0"
    return f"{n:,}"

def pbar(pct, width=16):
    """Render a clean Unicode visual progress bar."""
    try:
        pct_float = max(0.0, min(100.0, float(pct)))
    except (ValueError, TypeError):
        pct_float = 0.0
    filled = int(round(width * (pct_float / 100.0)))
    return "█" * filled + "░" * (width - filled)

def cell(text, max_len=120):
    """Make arbitrary text (commands, payloads) safe for a Markdown table code cell."""
    s = str(text if text is not None else '').replace('\r', ' ').replace('\n', ' ⏎ ')
    if len(s) > max_len:
        s = s[:max_len - 1] + '…'
    return s.replace('`', "'").replace('|', '\\|')

def day(ts):
    return (ts or '')[:10] or 'N/A'

def session_label(item):
    """Same rules as the Q12 archetype SQL, applied to a single sessions-table row."""
    n = item.get('command_count') or 0
    rep = item.get('repetition_ratio') or 0
    if n == 1:
        return ARCHETYPE_DESC['1. Single-Command Probe']
    if n >= 5 and rep <= 0.25:
        return ARCHETYPE_DESC['2. Multi-Stage Diverse Malware Chain']
    if n >= 5 and rep >= 0.70:
        return ARCHETYPE_DESC['3. Monotonous Redundant Looper']
    if n >= 2 and 0.26 <= rep <= 0.69:
        return ARCHETYPE_DESC['4. Standard Automated Recon']
    return ARCHETYPE_DESC['5. Brief Interaction (2-4 Cmds)']

def overall_period(data):
    ranges = data.get('q1_date_ranges', [])
    earliest = [r['earliest'][:10] for r in ranges if r.get('earliest')]
    latest = [r['latest'][:10] for r in ranges if r.get('latest')]
    return f"{min(earliest)} to {max(latest)}" if (earliest and latest) else "N/A"

def missing(name):
    return f"\n*{name} is not in analyzer_results.json yet. Re-run db_analyzer.py to compute it.*\n"

# ------------------------------------------------------------
# Sections
# ------------------------------------------------------------
def section_header(data):
    total = data.get('validation_total_records', 0)
    meta = data.get('meta', {})
    gen = f" · Generated: {meta['generated_at'][:16].replace('T', ' ')}" if meta.get('generated_at') else ""
    return f"""# Honeypot Data Analysis & Threat Intelligence Report

**Innovation Lab 3 — FH Technikum Wien | Team 11**
Analysis Period: **{overall_period(data)}** · Total Unified Events: **{fnum(total)}**{gen}

---
"""

def section_key_findings(data):
    lines = []
    total = data.get('validation_total_records', 0)
    lines.append(f"- **{fnum(total)} events** from {len(data.get('q1_total_per_type', []))} honeypot types between {overall_period(data)}.")

    ds = data.get('q13_ml_dataset')
    div = data.get('q13_sequence_diversity')
    if ds and div:
        lines.append(
            f"- **{fnum(ds['sessions_with_commands'])} Cowrie sessions contain typed commands** "
            f"({fnum(ds['sessions_2plus_commands'])} with 2 or more). These are the usable units for clustering."
        )
        lines.append(
            f"- Behavior is highly repetitive: only **{fnum(div['distinct_exact_sequences'])} distinct command sequences** "
            f"({div['exact_duplicate_pct']}% exact duplicates). After masking URLs, IPs and secrets, "
            f"**{fnum(div['distinct_templates'])} command families** remain and the top 10 families cover "
            f"**{div['top10_template_share_pct']}%** of all command sessions."
        )
    split = data.get('q15_time_split')
    if split:
        lines.append(
            f"- In a time-based {int(split['train_share'] * 100)}/{100 - int(split['train_share'] * 100)} split, "
            f"**{split['test_unseen_template_pct']}% of later sessions use a command family never seen before**. "
            f"This is the part where ML can add value beyond exact matching."
        )
    clean = {x['cadence_tier']: x for x in data.get('q14_clean_cadence', [])}
    table = {x['cadence_tier']: x for x in data.get('q12_cadence_distribution', [])}
    burst = 'Burst Script (< 0.5s)'
    if burst in clean and burst in table:
        lines.append(
            f"- Burst-speed sessions: **{table[burst]['pct_sessions']}%** in the sessions table, "
            f"**{clean[burst]['pct_sessions']}%** when only real typed commands are counted (see 6.3)."
        )
    if ds:
        lines.append(
            f"- **{ds['human_flagged_sessions']}** of {fnum(ds['human_candidate_sessions'])} candidate sessions show human signals "
            f"(typos, editors, corrections). Almost all traffic is automated."
        )
    if data.get('q16_login_success_pct') is not None and data.get('q16_cowrie_funnel'):
        lines.append(f"- **{data['q16_login_success_pct']}%** of Cowrie login attempts succeed (honeypot accepts weak credentials by design).")
    return "\n## Key Findings\n\n" + "\n".join(lines) + "\n\n---\n"

def section_ingestion(data):
    q1_type = {item['sensor_type']: item['cnt'] for item in data.get('q1_total_per_type', [])}
    q1_ips = {item['sensor_type']: item['unique_ips'] for item in data.get('q1_unique_ips_per_sensor', [])}
    q1_dates = {item['sensor_type']: item for item in data.get('q1_date_ranges', [])}
    total = data.get('validation_total_records', 0)
    period = overall_period(data)

    def date_str(stype):
        d = q1_dates.get(stype)
        if d and d.get('earliest') and d.get('latest'):
            return f"{d['earliest'][:10]} to {d['latest'][:10]}"
        return "N/A"

    md = """
## 1. Data Ingestion & Quality

### Data Volume Per Honeypot Sensor

| Honeypot | Sensor Type | Total Events | Unique Source IPs | Active Period |
|:---|:---|---:|---:|:---|
"""
    for key, name, kind in SENSORS:
        md += f"| **{name}** | {kind} | {fnum(q1_type.get(key, 0))} | {fnum(q1_ips.get(key, 0))} | {date_str(key)} |\n"
    md += f"| **Total** | **Unified Dataset** | **{fnum(total)}** | **—** | **{period}** |\n"

    md += """
---

### Geographic Distribution of Attacks (Top 10 Source Countries)

| Country | Total Attacks | Share | Visual Distribution |
|:---:|---:|---:|:---|
"""
    for item in data.get('q11_country_distribution', [])[:10]:
        p = item.get('pct', 0.0)
        md += f"| `{item.get('src_country')}` | {fnum(item.get('total_attacks', 0))} | {p}% | `{pbar(p)}` |\n"

    md += """
---

### Signal vs. Noise Ratio

- Actionable events by sensor (authentication attempts, commands, payloads):
"""
    for item in data.get('q2_useful_data', []):
        md += f"  - **{item['sensor_type'].capitalize()}**: {fnum(item['useful'])} actionable events ({item['useful_pct']}%).\n"

    md += """
- Noise events (connections without credentials or payload):

| Honeypot | Noise Events (`connection_established`) | Total Volume | Noise Ratio | Visual Noise Share |
|:---|---:|---:|---:|:---|
"""
    for item in data.get('q3_noise', []):
        p = item.get('noise_pct', 0.0)
        md += f"| **{item['sensor_type'].capitalize()}** | {fnum(item['noise_events'])} | {fnum(item['total'])} | **{p}%** | `{pbar(p)}` |\n"

    nulls = data.get('validation_nulls') or {}
    if nulls:
        md += "\n- Integrity: " + ", ".join(f"`{k}` = {fnum(v)}" for k, v in nulls.items()) + ".\n"
    return md + "\n---\n"

def section_behavior(data):
    md = """
## 2. Attacker Behavioral Dynamics & Session Intelligence

Five session-level metrics from the `sessions` table (`command_count`, `unique_command_count`, `session_duration`, `time_gap_mean`, `repetition_ratio`) describe how attackers interact with the shell.
"""
    cadence_data = data.get('q12_cadence_distribution', [])
    if cadence_data:
        md += """
### 2.1 Attacker Typing Cadence (Machine Script vs. Human Pace)

Mean time between commands (`time_gap_mean`) separates scripts from interactive operators:

| Cadence Tier | Share | Visual Share | Sessions | Avg Commands | Avg Duration | Typical Meaning |
|:---|---:|:---|---:|---:|---:|:---|
"""
        for item in cadence_data:
            p = item.get('pct_sessions', 0.0)
            tier = item.get('cadence_tier', '')
            md += f"| **{tier}** | **{p}%** | `{pbar(p, width=12)}` | {fnum(item.get('session_count', 0))} | {item.get('avg_commands', 0)} | {item.get('avg_duration_sec', 0)}s | {CADENCE_DESC.get(tier, '')} |\n"

        burst_item = next((x for x in cadence_data if '< 0.5s' in x.get('cadence_tier', '')), None)
        if burst_item:
            md += f"""
> [!NOTE]
> **{burst_item.get('pct_sessions', 0)}% of sessions with commands** ({fnum(burst_item.get('session_count', 0))} sessions) average less than 0.5 seconds between commands. No person types that fast, so these are scripts. Section 6.3 checks how much of this comes from non-command client events.
"""
    else:
        md += missing("Session cadence distribution")

    archetypes_data = data.get('q12_behavioral_archetypes', [])
    if archetypes_data:
        md += """
---

### 2.2 Attacker Behavioral Archetypes (Complexity vs. Redundancy)

Command volume, diversity and repetition ratio ($R = 1 - \\text{unique}/\\text{total}$) split sessions into five rule-based archetypes:

| Archetype | Share | Visual Share | Sessions | Avg Cmds | Unique Cmds | Avg Duration | Typical Meaning |
|:---|---:|:---|---:|---:|---:|---:|:---|
"""
        for item in archetypes_data:
            p = item.get('pct', 0.0)
            name = item.get('archetype', '')
            md += f"| **{name}** | **{p}%** | `{pbar(p, width=12)}` | {fnum(item.get('session_count', 0))} | {item.get('avg_cmds', 0)} | {item.get('avg_unique_cmds', 0)} | {item.get('avg_duration_sec', 0)}s | {ARCHETYPE_DESC.get(name, '')} |\n"

    md += """
---

### 2.3 Behavioral Decision Architecture

The rule-based decision workflow used for the cadence and archetype tables:

```mermaid
flowchart TD
    A["Attacker Session Established"] --> B{"Commands Executed?"}
    B -->|"N = 0"| C["Stateless Connection / Auth Probe"]
    B -->|"N >= 1"| D{"Mean Inter-Command Cadence (time_gap_mean)"}

    D -->|"< 0.5s"| E["Machine Script Burst"]
    D -->|"0.5s - 2.0s"| F["Automated SSH Recon Bot"]
    D -->|"2.0s - 5.0s"| G["Paced / Throttled Scanner"]
    D -->|">= 5.0s"| H{"Interactive Verification (Typos & Editors)"}

    H -->|"Typos Detected OR Nano/Vi"| I["Human Operator Candidate"]
    H -->|"No Errors / Standard Script"| J["Slow Rate-Limited Machine"]

    E --> K{"Command Repetition Ratio"}
    K -->|"Repetition <= 0.25"| L["Multi-Stage Malware Deployment Chain"]
    K -->|"Repetition >= 0.70"| M["Monotonous Redundant Looper / Poller"]
```
"""

    complex_sessions = data.get('q12_top_complex_sessions', [])
    if complex_sessions:
        md += """
---

### 2.4 Top Multi-Stage Complex Attack Sessions

Sessions with the highest number of distinct commands:

| Session ID | Sensor | Source IP | Country | Total Cmds | Unique Cmds | Repetition | Cadence | Duration | Archetype |
|:---|:---:|:---|:---:|---:|---:|---:|---:|---:|:---|
"""
        for item in complex_sessions:
            rep_val = item.get('repetition_ratio')
            rep_pct = f"{round(float(rep_val) * 100, 1)}%" if rep_val is not None else "N/A"
            md += f"| `{(item.get('session_id') or '')[:12]}` | `{item.get('sensor_type', '')}` | `{item.get('src_ip', '')}` | {item.get('src_country') or 'N/A'} | {item.get('command_count', 0)} | **{item.get('unique_command_count', 0)}** | {rep_pct} | {item.get('time_gap_mean', 0)}s | {item.get('session_duration', 0)}s | {session_label(item)} |\n"

    rapid_sessions = data.get('q12_rapid_fire_sessions', [])
    if rapid_sessions:
        md += """
---

### 2.5 High-Velocity Sub-Second Attack Bursts

Sessions that send at least five commands with less than 0.5 seconds between them:

| Session ID | Source IP | Country | Commands Executed | Total Duration | Mean Cadence | Archetype |
|:---|:---|:---:|---:|---:|---:|:---|
"""
        for item in rapid_sessions:
            md += f"| `{(item.get('session_id') or '')[:12]}` | `{item.get('src_ip', '')}` | {item.get('src_country') or 'N/A'} | {item.get('command_count', 0)} cmds | {item.get('session_duration', 0)}s | **{item.get('time_gap_mean', 0)}s** | {session_label(item)} |\n"
    return md

def section_human(data):
    human_sessions = data.get('q11_human_manual_sessions', [])
    md = """
---

## 3. Human / Manual Attack Verification

### Human Session Candidates

A multi-signal filter looks for real typing errors (`sudp`, `sl`, `cd /ect`, `whomi`, `gerp`), interactive editors (`nano`/`vi`) and quick corrections within 0.4 to 8 seconds. Confidence counts how many of these three signal types are present. A flag is a candidate for manual review, not proof of a human.

| Session ID | Source IP | Country | Duration | Mean Command Gap | Confidence | Signals |
|:---|:---|:---:|---:|---:|:---:|:---|
"""
    for item in human_sessions:
        gap = item.get('avg_delta_sec')
        gap_str = f"{gap}s" if gap is not None else "N/A"
        conf = item.get('confidence_score')
        conf_str = f"{conf} / 3" if conf is not None else "Flagged"
        dur = round(float(item.get('duration_sec') or 0))
        md += f"| `{(item.get('session_id') or '')[:12]}` | `{item.get('src_ip', '')}` | {item.get('src_country') or 'N/A'} | {dur}s | **{gap_str}** | `{conf_str}` | {cell(item.get('flag_reason', ''), 200)} |\n"

    for item in human_sessions[:10]:
        cmds = item.get('commands') or (item.get('cmd_sequence') or '').split(' | ')
        dur = round(float(item.get('duration_sec') or 0))
        gap = item.get('avg_delta_sec')
        gap_str = f"{gap}s" if gap is not None else "N/A"
        cmd_str = '\n'.join(cmds).replace('```', "'''")
        md += f"\n#### Session `{(item.get('session_id') or '')[:12]}` Timeline (`{item.get('src_ip', '')}`)\n"
        md += f"- **Duration:** {dur} seconds · **Average Gap:** {gap_str}\n"
        md += f"- **Raw Commands Executed:**\n```bash\n{cmd_str}\n```\n"
    if len(human_sessions) > 10:
        md += f"\n*{len(human_sessions) - 10} further flagged sessions are listed in analyzer_results.json.*\n"
    return md

def section_cross_sensor(data):
    md = """
---

## 4. Cross-Sensor Correlation

### Attacker Infrastructure Overlap

| Honeypot Sensors Hit | Number of Unique IPs | Infrastructure Breadth |
|:---:|---:|:---|
"""
    for item in data.get('q5_ip_sensor_distribution', []):
        md += f"| **{item['sensor_count']} sensors** | **{fnum(item['ip_count'])} IPs** | `{'Broad Multi-Vector Targeter' if item['sensor_count'] >= 3 else 'Specialized Scanner' if item['sensor_count'] == 1 else 'Dual-Vector Scanner'}` |\n"

    md += """
### Top Multi-Sensor Attackers

| Attacker Source IP | Country | Sensors Hit | Sensors | Total Events | First Seen | Last Seen |
|:---|:---:|:---:|:---|---:|:---|:---|
"""
    for item in data.get('q5_top_multi_sensor_ips', [])[:10]:
        md += f"| `{item['src_ip']}` | {item.get('src_country') or 'N/A'} | {item.get('sensor_count', '')} | `{item['sensors']}` | {fnum(item['total_events'])} | {day(item['first_seen'])} | {day(item['last_seen'])} |\n"
    return md

def section_mdrfckr(data):
    stats = data.get('q10_mdrfckr_stats', {}) or {}
    md = """
---

## 5. Signature Analysis: The `mdrfckr` Campaign

The most persistent SSH backdoor pattern in the dataset carries the string **`mdrfckr`** (the comment of an attacker SSH key written to `authorized_keys`):
"""
    md += f"- **Total Payload Hits:** **{fnum(stats.get('hits', 0))}**\n"
    md += f"- **Distinct Attacking IPs:** **{fnum(stats.get('unique_ips', 0))}**\n"
    if stats.get('first_seen'):
        md += f"- **Active:** {day(stats.get('first_seen'))} to {day(stats.get('last_seen'))}\n"
    examples = data.get('q10_mdrfckr_examples', [])
    if examples:
        md += "\n| Most Frequent Variants | Hits | IPs |\n|:---|---:|---:|\n"
        for ex in examples:
            md += f"| `{cell(ex['payload'], 160)}` | {fnum(ex['hits'])} | {fnum(ex['ips'])} |\n"
    top_ips = data.get('q10_mdrfckr_top_ips', [])
    if top_ips:
        md += "\n| Top Deploying IP | Hits | First | Last |\n|:---|---:|:---|:---|\n"
        for item in top_ips:
            md += f"| `{item['src_ip']}` | {fnum(item['hits'])} | {day(item.get('first'))} | {day(item.get('last'))} |\n"
    return md

def section_ml_readiness(data):
    md = """
---

## 6. ML Readiness & Data Quality (Innovation Lab 3)

The supervisor's criteria for good ML data are diversity, few duplicates and multiple attack vectors. This section measures exactly that for the planned unit of analysis: one Cowrie session with typed commands.
"""
    ds = data.get('q13_ml_dataset')
    div = data.get('q13_sequence_diversity')
    if not ds or not div:
        return md + missing("ML readiness data (Q13)")

    md += f"""
### 6.1 Dataset Size

| Measure | Value |
|:---|---:|
| Cowrie sessions in `sessions` table | {fnum(ds.get('cowrie_sessions_total'))} |
| Sessions without typed commands (excluded) | {fnum(ds.get('sessions_excluded_no_commands'))} |
| Sessions with >= 1 typed command | **{fnum(ds['sessions_with_commands'])}** |
| Sessions with >= 2 typed commands | **{fnum(ds['sessions_2plus_commands'])}** |
| Command events | {fnum(ds['command_events'])} |
| ... of type `cowrie.command.input` | {fnum(ds['command_input_events'])} ({ds['command_input_pct']}%) |
| `raw_data` truncated at 1,000 chars | {fnum(ds['raw_data_truncated_events'])} ({ds['raw_data_truncated_pct']}%) |

### 6.2 Diversity vs. Duplicates

| Measure | All command sessions | Sessions with >= 2 commands |
|:---|---:|---:|
| Sessions | {fnum(div['sessions'])} | {fnum(div['sessions_2plus'])} |
| Distinct exact command sequences | {fnum(div['distinct_exact_sequences'])} | {fnum(div['distinct_exact_sequences_2plus'])} |
| Distinct command families (templates) | {fnum(div['distinct_templates'])} | {fnum(div['distinct_templates_2plus'])} |
| Exact duplicate share | {div['exact_duplicate_pct']}% | — |
| Family duplicate share | {div['template_duplicate_pct']}% | — |
| Share covered by top 10 families | {div['top10_template_share_pct']}% | — |
| Families seen in only one session | {fnum(div['singleton_templates'])} | — |

> [!NOTE]
> A **command family** is a command sequence after masking URLs, IP addresses, quoted secrets, long random tokens and numbers. Exact matching corresponds to the Innovation Lab 2 method. Families are a transparent rule baseline that an ML clustering must beat to show added value.
"""

    clean = data.get('q14_clean_cadence', [])
    table = {x['cadence_tier']: x for x in data.get('q12_cadence_distribution', [])}
    if clean:
        if (ds.get('session_metrics_version') or 1) < 2:
            explanation = ("The `sessions` table was built with session metrics v1, which also counted `cowrie.client.*` events "
                           "(SSH version, key exchange, terminal size). These arrive within milliseconds at connection start "
                           "and push sessions into the burst tier. Re-running normalizer.py recomputes the table (v2). "
                           "The right column only uses typed commands:")
        else:
            explanation = ("Consistency check: the `sessions` table (session metrics v2, typed commands only) and the "
                           "analyzer's own per-session count should show nearly the same distribution:")
        md += f"""
### 6.3 Cadence Check: Sessions Table vs. Real Commands

{explanation}

| Cadence Tier | Sessions Table | Real Commands Only | Sessions (Real) | Avg Cmds (Real) |
|:---|---:|---:|---:|---:|
"""
        for item in clean:
            tier = item['cadence_tier']
            t = table.get(tier)
            md += f"| {tier} | {str(t['pct_sessions']) + '%' if t else '—'} | **{item['pct_sessions']}%** | {fnum(item['session_count'])} | {item['avg_commands']} |\n"
        if ds.get('sessions_table_with_commands') is not None:
            md += f"\n- Sessions table: {fnum(ds['sessions_table_with_commands'])} Cowrie sessions with `command_count > 0`. Real typed commands exist in {fnum(ds['sessions_with_commands'])}.\n"
    return md

def section_families(data):
    tpls = data.get('q13_top_templates')
    md = """
---

## 7. Command Families (Template Baseline)

The 15 most frequent command families. *Variants* shows how many different exact sequences were merged into one family. A high value means exact matching would split one bot script into many groups.
"""
    if not tpls:
        return md + missing("Command families (Q13)")
    md += """
| # | Command Family (masked) | Sessions | Share | IPs | Variants | Active Days | Cmds | Intent Profile | First | Last |
|---:|:---|---:|---:|---:|---:|---:|---:|:---|:---|:---|
"""
    for i, t in enumerate(tpls, start=1):
        md += f"| {i} | `{cell(t['template'], 110)}` | {fnum(t['sessions'])} | {t['session_pct']}% | {fnum(t['unique_ips'])} | {fnum(t['exact_variants'])} | {t['active_days']} | {t['commands']} | {t['intent_profile']} | {day(t['first_seen'])} | {day(t['last_seen'])} |\n"
    return md

def section_intents(data):
    tags = data.get('q14_intent_tags')
    md = """
---

## 8. Rule-Based Intent Baseline

Each session gets every intent tag whose indicator appears in its commands. A session can have several tags. These tags are heuristics for comparison with ML clusters, not ground truth labels.
"""
    if not tags:
        return md + missing("Intent tags (Q14)")
    md += """
| Intent | Sessions | Share | Visual Share | Indicators |
|:---|---:|---:|:---|:---|
"""
    for t in tags:
        md += f"| **{t['intent']}** | {fnum(t['sessions'])} | {t['pct']}% | `{pbar(t['pct'], width=12)}` | {cell(INTENT_DESC.get(t['intent'], ''), 200)} |\n"

    profiles = data.get('q14_intent_profiles', [])
    if profiles:
        md += """
### 8.1 Most Common Intent Combinations (Kill-Chain Profiles)

| Profile | Sessions | Share |
|:---|---:|---:|
"""
        for p in profiles:
            md += f"| `{p['profile']}` | {fnum(p['sessions'])} | {p['pct']}% |\n"
    return md

def section_temporal(data):
    monthly = data.get('q15_monthly_novelty')
    md = """
---

## 9. Temporal Novelty & Time-Based Split

*Novel sessions* use a command family that first appeared in that month. A falling novelty rate means the honeypots mostly collect repetitions of known behavior.
"""
    if not monthly:
        return md + missing("Monthly novelty (Q15)")
    md += """
| Month | Command Sessions | >= 2 Cmds | Families | New Families | Novel Sessions | Cumulative |
|:---|---:|---:|---:|---:|---:|---:|
"""
    for m in monthly:
        md += f"| {m['month']} | {fnum(m['sessions_with_cmds'])} | {fnum(m['sessions_2plus'])} | {fnum(m['distinct_templates'])} | {fnum(m['new_templates'])} | {m['novel_session_pct']}% | {m['cumulative_session_pct']}% |\n"

    split = data.get('q15_time_split')
    if split:
        train_pct = int(split['train_share'] * 100)
        md += f"""
### 9.1 Suggested Train / Test Split (chronological, no shuffling)

| Part | Sessions | Period |
|:---|---:|:---|
| Train (first {train_pct}%) | {fnum(split['train_sessions'])} | {day(split['train_period'][0])} to {day(split['train_period'][1])} |
| Test (last {100 - train_pct}%) | {fnum(split['test_sessions'])} | {day(split['test_period'][0])} to {day(split['test_period'][1])} |

- Cutoff: `{split['cutoff_timestamp']}`.
- **{fnum(split['test_sessions_unseen_template'])} test sessions ({split['test_unseen_template_pct']}%)** use one of {fnum(split['test_distinct_unseen_templates'])} families that never occur in the training period. A random split would hide this and make results look better than they are.
- The test part is also the "last 30% of the data" the supervisor suggested for a first clustering run on a laptop.
"""
    return md

def section_recurrence(data):
    rec = data.get('q16_ip_recurrence')
    md = """
---

## 10. Attacker Recurrence

Do the same source IPs come back, and do they always run the same script?
"""
    if not rec:
        return md + missing("Attacker recurrence (Q16)")
    md += f"\n{fnum(rec['ips_with_command_sessions'])} IPs ran at least one command session.\n"
    md += "\n| Active Days per IP | IPs | Share |\n|:---|---:|---:|\n"
    for b in rec['active_days_distribution']:
        md += f"| {b['bucket']} | {fnum(b['ips'])} | {b['pct']}% |\n"
    md += "\n| Command Families per IP | IPs | Share |\n|:---|---:|---:|\n"
    for b in rec['templates_per_ip_distribution']:
        md += f"| {b['bucket']} | {fnum(b['ips'])} | {b['pct']}% |\n"
    top = data.get('q16_top_recurring_ips', [])
    if top:
        md += """
### 10.1 Most Persistent IPs

| Source IP | Country | Active Days | Sessions | Families | First Seen | Last Seen |
|:---|:---:|---:|---:|---:|:---|:---|
"""
        for t in top:
            md += f"| `{t['src_ip']}` | {t.get('src_country') or 'N/A'} | {t['active_days']} | {fnum(t['sessions'])} | {t['distinct_templates']} | {day(t['first_seen'])} | {day(t['last_seen'])} |\n"
    return md

def section_funnel(data):
    funnel = data.get('q16_cowrie_funnel')
    md = """
---

## 11. Cowrie Login Funnel & SSH Client Fingerprints
"""
    if not funnel:
        return md + missing("Cowrie funnel (Q16)")
    md += "\n| Stage | Count |\n|:---|---:|\n"
    for s in funnel:
        md += f"| {s['stage']} | {fnum(s['value'])} |\n"

    creds = data.get('q16_top_successful_credentials', [])
    if creds:
        md += "\n### 11.1 Credentials That Led to a Shell\n\n| Credential | Successful Logins | Attempts | IPs |\n|:---|---:|---:|---:|\n"
        for cr in creds:
            md += f"| `{cell(cr['payload'], 60)}` | {fnum(cr['successes'])} | {fnum(cr['attempts'])} | {fnum(cr['ips'])} |\n"

    clients = data.get('q16_ssh_client_versions', [])
    if clients:
        md += """
### 11.2 SSH Client Versions (Bot Tooling)

The SSH client banner shows which libraries bots are built with (e.g. Go, libssh, paramiko) and is a useful clustering feature.

| Client Version | Connections | Share | IPs |
|:---|---:|---:|---:|
"""
        for cl in clients:
            md += f"| `{cell(cl['client_version'], 70)}` | {fnum(cl['connections'])} | {cl['pct']}% | {fnum(cl['ips'])} |\n"
    return md

def section_credentials(data):
    creds = data.get('q8_top_credentials', [])
    mirai = data.get('q10_mirai_credentials', [])
    if not creds and not mirai:
        return ""
    md = """
---

## 12. Brute-Force Credentials
"""
    if creds:
        md += "\n| Top Credential Pairs (all sensors) | Attempts | IPs | Sensors |\n|:---|---:|---:|:---|\n"
        for cr in creds:
            md += f"| `{cell(cr['payload'], 60)}` | {fnum(cr['cnt'])} | {fnum(cr['ips'])} | `{cr.get('sensors', '')}` |\n"
    if mirai:
        md += "\n| Mirai Default Credential | Attempts | IPs |\n|:---|---:|---:|\n"
        for m in mirai:
            md += f"| `{cell(m['payload'], 60)}` | {fnum(m['cnt'])} | {fnum(m['ips'])} |\n"
    return md

def section_methodology(data):
    meta = data.get('meta', {})
    md = """
---

## 13. Methodology & Limitations

- `attack_type`, archetypes, intent tags and human flags are **heuristics**. They are useful as a baseline but are not independent ground truth and must not be used as ML training labels.
- Honeypot traffic is dominated by bots. Similar behavior is **not** proof that the same person or group is behind it. No attribution is made.
- `raw_data` is truncated at 1,000 characters. Long payloads may be incomplete.
- `event_id` is a hash of timestamp, instance, IP, category and payload. Identical events in the same timestamp collapse into one row.
- For ML evaluation the data must be split **by time**, not randomly (see 9.1), so that near-duplicate sessions do not leak from training into testing.
"""
    if meta:
        md += f"\n*Analyzer v{meta.get('analyzer_version', '?')} · runtime {meta.get('runtime_sec', '?')}s · database {fnum(meta.get('db_size_bytes'))} bytes.*\n"
    return md

def build_report(data):
    parts = [
        section_header(data),
        section_key_findings(data),
        section_ingestion(data),
        section_behavior(data),
        section_human(data),
        section_cross_sensor(data),
        section_mdrfckr(data),
        section_ml_readiness(data),
        section_families(data),
        section_intents(data),
        section_temporal(data),
        section_recurrence(data),
        section_funnel(data),
        section_credentials(data),
        section_methodology(data),
    ]
    return ''.join(parts)

def main(json_path=JSON_PATH, md_path=MD_PATH):
    print(f"Reading analytical telemetry from: {json_path}")
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    md = build_report(data)

    # Persist output file
    Path(md_path).parent.mkdir(parents=True, exist_ok=True)
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)

    print(f"Markdown successfully rendered and saved to: {md_path}")

if __name__ == '__main__':
    if len(sys.argv) == 3:
        main(Path(sys.argv[1]), Path(sys.argv[2]))
    else:
        main()
