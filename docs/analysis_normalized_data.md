# Answers to Supervisor Questions

These answers were generated strictly from the normalized honeypot dataset stored in `honeypot_normalized.db` (21,407,714 events). No assumptions, memory, or sample data was used. 
This data was extracted using SQL and the analyzer.py generated a json file.

---

## Data Quality

### How much data do you currently have per honeypot?

| Honeypot | Total Events | Unique Source IPs | Active Period |
|----------|-------------|-------------------|---------------|
| **Cowrie** | 12,684,265 | 26,194 | 2026-01-07 to 2026-06-11 |
| **Heralding** | 8,684,631 | 27,319 | 2026-04-01 to 2026-06-12 |
| **Nginx** | 37,451 | 3,886 | 2026-04-08 to 2026-06-12 |
| **Endlessh** | 1,367 | 302 | 2026-03-29 to 2026-06-11 |
| **Total** | **21,407,714** | — | **Jan–June 2026** |

---

### Which honeypot currently produces the most useful data and why?

**Cowrie** produces the most useful data by a wide margin.
Out of its 12,684,265 total events, a significant portion are actionable.
Cowrie has 7,140,204 useful events (56.29%).
Heralding has 3,723,000 useful events (42.87%).

---

### Which honeypot produces mostly noise?

**Endlessh** produces 100% noise. It only records that a scanner connected and was held, but never captures credentials, commands, or payloads.

| Honeypot | Noise Events (`connection_established`) | Total | Noise % |
|----------|----------------------------------------|-------|---------|
| Endlessh | 1,367 | 1,367 | **100.0%** |
| Heralding | 4,961,631 | 8,684,631 | **57.13%** |
| Cowrie | 5,513,354 | 12,684,265 | **43.47%** |
| Nginx | 0 | 37,451 | **0.0%** |

---

## Correlation and Normalization

### Which IPs hit multiple honeypots?

| Sensors Hit | Number of Unique IPs |
|:-----------:|:-------------------:|
| 4 | **42** |
| 3 | **817** |
| 2 | **7,303** |
| 1 | **40,476** |

The IPs that hit all four honeypots are the most interesting. Top 10:

| Source IP | Country | Sensors | Total Events | First Seen | Last Seen |
|-----------|---------|---------|-------------|------------|-----------|
| `95.215.0.144` | RU | cowrie,endlessh,heralding,nginx | 465 | 2026-01-08 | 2026-06-11 |
| `80.94.95.221` | RO | cowrie,endlessh,heralding,nginx | 412 | 2026-01-18 | 2026-06-11 |
| `45.91.64.7` | RU | cowrie,endlessh,heralding,nginx | 349 | 2026-01-16 | 2026-05-30 |
| `176.32.193.16` | AM | cowrie,endlessh,heralding,nginx | 187 | 2026-03-27 | 2026-06-12 |
| `92.154.95.236` | FR | cowrie,endlessh,heralding,nginx | 171 | 2026-01-17 | 2026-06-10 |
| `92.63.197.22` | RU | cowrie,endlessh,heralding,nginx | 150 | 2026-03-16 | 2026-05-30 |
| `172.236.228.198` | US | cowrie,endlessh,heralding,nginx | 132 | 2026-01-08 | 2026-06-10 |
| `80.13.153.140` | FR | cowrie,endlessh,heralding,nginx | 130 | 2026-01-11 | 2026-06-10 |
| `172.105.128.12` | US | cowrie,endlessh,heralding,nginx | 129 | 2026-01-13 | 2026-06-06 |
| `45.91.64.6` | RU | cowrie,endlessh,heralding,nginx | 118 | 2026-01-09 | 2026-06-11 |

---

### Which events look automated?

**Signal: Repetition ratio** (total events / unique payloads)

| Source IP | Country | Sensor | Total Events | Unique Payloads |
|-----------|---------|--------|-------------|-----------------|
| `213.136.75.229` | DE | heralding | 182,021 | 43 |
| `176.123.4.65` | MD | heralding | 167,101 | 47 |
| `85.11.167.2` | BG | heralding | 152,275 | 152275 |
| `5.83.143.40` | DE | heralding | 132,481 | 2744 |
| `168.90.66.80` | BR | cowrie | 98,891 | 32944 |

---

### Which sessions look more interactive?

**Top interactive sessions (Cowrie):**

| Session ID | Source IP | Country | Unique Commands | Session Start |
|------------|-----------|---------|:--------------:|---------------|
| `1512297b5142` | `180.153.91.15` | CN | 22 | 2026-02-07T12:49:25 |
| `2ece44b957c9` | `219.151.181.185` | CN | 22 | 2026-01-22T05:13:29 |
| `c101c1b99c41` | `45.78.219.184` | SG | 22 | 2026-01-24T08:16:05 |
| `d483b75208ac` | `180.106.83.59` | CN | 22 | 2026-01-27T22:54:20 |
| `000f370ee9ad` | `45.78.217.45` | SG | 20 | 2026-01-29T12:41:51 |

---

### Human/Manual Attack Detection & Geolocation (NEW)

Based on timing irregularities, session duration, command sequences, and interactive-shell artifacts:

**Flagged Sessions:**

| Session ID | Source IP | Country | Duration (s) | Flag Reason |
|------------|-----------|---------|--------------|-------------|
| `2a78594317ba` | `64.181.175.157` | US | 232 | Timing/Interactive (Duration > 30s, Unique cmds > 3) + Interactive-shell artifacts (nano/vi/top/ping) |
| `a42bad2e2771` | `178.191.188.22` | AT | 215 | Timing/Interactive (Duration > 30s, Unique cmds > 3) + Interactive-shell artifacts (nano/vi/top/ping) |
| `0aa11b6f9b66` | `14.103.178.199` | CN | 206 | Timing/Interactive (Duration > 30s, Unique cmds > 3) + Interactive-shell artifacts (nano/vi/top/ping) |
| `e426f73a83b9` | `178.191.186.131` | AT | 156 | Timing/Interactive (Duration > 30s, Unique cmds > 3) + Interactive-shell artifacts (nano/vi/top/ping) |
| `59f49a947c79` | `45.78.198.194` | SG | 150 | Timing/Interactive (Duration > 30s, Unique cmds > 3) |
| `51cafab551a2` | `46.191.141.152` | RU | 147 | Timing/Interactive (Duration > 30s, Unique cmds > 3) + Interactive-shell artifacts (nano/vi/top/ping) |
| `91be50ea7477` | `172.178.16.179` | GB | 143 | Timing/Interactive (Duration > 30s, Unique cmds > 3) + Interactive-shell artifacts (nano/vi/top/ping) |
| `cd847ee07d5a` | `14.103.175.138` | CN | 139 | Timing/Interactive (Duration > 30s, Unique cmds > 3) |
| `3c915ca3b775` | `172.178.16.179` | GB | 135 | Timing/Interactive (Duration > 30s, Unique cmds > 3) + Interactive-shell artifacts (nano/vi/top/ping) |
| `084c43ee425a` | `46.191.141.152` | RU | 128 | Timing/Interactive (Duration > 30s, Unique cmds > 3) + Interactive-shell artifacts (nano/vi/top/ping) |

**Top Attack Source Countries:**

| Country | Total Attacks | Percentage |
|---------|--------------:|-----------:|
| US | 7,856,017 | 36.81% |
| DE | 2,813,104 | 13.18% |
| CN | 1,172,415 | 5.49% |
| SG | 763,361 | 3.58% |
| RO | 645,259 | 3.02% |
| ID | 579,584 | 2.72% |
| BR | 541,831 | 2.54% |
| BG | 498,144 | 2.33% |
| VN | 433,188 | 2.03% |
| NL | 419,919 | 1.97% |

---

## Analysis Maturity

### What is your most interesting finding so far?

Our most interesting finding is the **mdrfckr SSH backdoor campaign**.
The exact shell command was executed **63,977 times** from **5,617 unique IP addresses**.