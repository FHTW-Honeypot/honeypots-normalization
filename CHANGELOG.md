# InnoLab 3 — Project Changelog

**Project**: Honeypots Normalization & Behavioral Intelligence  
**Institution**: FH Technikum Wien — InnoLab 3 | Team 11  
**Supervisor**: MSc. Recep Balıbey  

---

## [InnoLab 3 — Update 1] Behavioral Metrics & In-Place Normalization Engine
*Date: October 23, 2026*

### 1. Executive Summary (Talking Points for Supervisor)
- **Objective**: Transitioned the honeypot dataset from simple event storage to deep behavioral profiling without rebuilding the ~18 GB historical SQLite database.
- **Key Delivery**: Consolidated the entire pipeline into a single standalone script (`python scripts/normalizer.py`) that autonomously updates schema, handles appended dates, and computes session metrics in-place.
- **Zero-Scrape In-Place Backfill**: All metrics are calculated directly from existing SQLite records—no re-downloading or re-parsing 12 months of raw Azure blob storage logs.

---

### 2. What Was Added & Changed

#### A. Five New Behavioral Session Attributes
Added to both the `events` table and a dedicated `sessions` table:
1. `command_count`: Total number of commands executed in the session.
2. `unique_command_count`: Number of distinct commands executed.
3. `session_duration`: Session duration in seconds ($\max(\text{timestamp}) - \min(\text{timestamp})$).
4. `time_gap_mean`: Average inter-command latency (keystroke pacing in seconds).
5. `repetition_ratio`: Degree of command redundancy ($1 - \frac{\text{unique}}{\text{total}}$).

#### B. Normalizer Upgrades (`scripts/normalizer.py`)
- **Single-File Pipeline**: Consolidated all ingestion, schema evolution, and backfill into `normalizer.py`.
- **Incremental & Appended Log Fix**: Upgraded file detection to check both the first and last log line of each file. Continuous growing files (e.g., `access.log`) now correctly ingest newly appended dates rather than skipping the entire file.
- **Non-Destructive UPSERT**: Employs SQLite `INSERT ... ON CONFLICT(event_id) DO UPDATE SET ...`, allowing seamless ingestion of new records while enriching existing records in-place without primary key collisions.
- **Resilient Geolocation**: Hardened IP lookup with `safe_country_code()` to eliminate crashes on private/bogon IPs.

#### C. Threat Intelligence & Visualization (`scripts/db_analyzer.py` & `scripts/md-generator.py`)
- **Attacker Typing Cadence**: Classifies sessions by inter-command gap into:
  - *Burst Scripts (<0.5s)*: 72.4% of command sessions (automated botnet loaders).
  - *Fast Bot Recon (0.5s–2.0s)*: 21.1% (automated scanners awaiting prompt returns).
  - *Paced Scripts (2.0s–5.0s)*: 5.8% (throttled evasion bots).
  - *Human Interactive Pace (>=5.0s)*: 0.7% (manual exploration).
- **Behavioral Threat Archetypes**: Clusters sessions into *Diverse Malware Chains*, *Standard Automated Recon*, *Monotonous Redundant Loopers*, and *Single-Command Probes*.
- **Rich Visualizations**: Added Unicode visual distribution bars (`█████████░░░`) and a Mermaid decision flow to [`docs/analysis_normalized_data.md`](docs/analysis_normalized_data.md).

---

### 3. Pipeline Execution (3 Commands)

```powershell
# 1. Normalize logs, add attributes, and enrich sessions in-place
python scripts/normalizer.py

# 2. Extract deep analytical findings & session telemetry
python scripts/db_analyzer.py

# 3. Render visual Markdown report
python scripts/md-generator.py
```


## [InnoLab 3 — Update 2] Human Attacker Identification & Natural Stumbles Engine
*Date: October 23, 2026*

### 1. Executive Summary
- **Objective**: Enhanced accuracy and coverage for identifying genuine human attackers across Cowrie honeypot sessions while strictly eliminating false-positive bot script noise.
- **Key Delivery**: Implemented multi-signal human detection in `scripts/db_analyzer.py` and calibrated terminal window dimensions in `scripts/normalizer.py`.

---

### 2. Changes & Enhancements

#### A. Expanded Real-World Typo Matching (`scripts/db_analyzer.py`)
- Removed artificial token `passwwd`.
- Preserved operational typo `sudp` (for `sudo`).
- Added token-accurate matches for common human terminal slips:
  - `sl` instead of `ls` (scoped to whole commands/arguments to avoid false-matching `sleep`)
  - `cd /ect` instead of `cd /etc`
  - `whomi` instead of `whoami`
  - `gerp` instead of `grep`

#### B. Whitelisted Standard Administration Tools
- Completely removed standard Linux utilities from `bot_sigs`: `free -m`, `lscpu`, `crontab`, `chmod`, `curl`, `wget`, `awk`, and `disable_firewall`.
- Threat actors and operators inspecting memory, CPU, or download utilities are no longer mistakenly disqualified as bots.

#### C. Independent Text Editor Flagging
- Decoupled `has_editor` (`nano`, `vi`, `vim`) from command length restrictions. Invoking an interactive editor now acts as an independent "OR" signal.

#### D. Calibrated Terminal Resizing Threshold (`scripts/normalizer.py`)
- Window size negotiation (`cowrie.client.size`) only sets `attack_type = 'human_or_manual'` if both width and height are $\ge 100$ pixels.
- Automated tools and default SSH scanners requesting $80 	imes 24$ terminal sizes remain neutral (`uncertain`).

#### E. Natural Human Stumbles and Quick Retries Feature
- Parses chronological command sequences and identifies error-and-remediation pairs executed within human reaction limits ($0.4\text{s} \le \Delta t \le 8.0\text{s}$):
  - `sl` $\to$ `ls`
  - `cd/` $\to$ `cd /`
  - `cd ..` followed by `ls`
  - `sudp` $\to$ `sudo`
  - `cd /ect` $\to$ `cd /etc`
  - `whomi` $\to$ `whoami`
  - `gerp` $\to$ `grep`
  - Dynamic single-character typo correction to valid Linux core utilities.
- Disqualifies sub-second bursts ($< 0.4\text{s}$) as automated script dumps.


## [InnoLab 3 - Update 3] Behavior Categories, Feature Catalog and Clustering Evaluation
*Date: November 15, 2026*

### 1. Summary
- **Objective**: Close the open Sprint 3 items: define attacker types and behavior categories, identify command, payload and credential features, and interpret the first clustering run.
- **Key Delivery**: Six rule-based behavior categories that cover 99.95% of the 77,984 command sessions in the sample, checked by a script that needs no database access.

### 2. What Was Added
- `docs/attacker_profiles.md`: behavior categories (what), interaction style (how), activity type per source IP (how often), and the criterion for "bot or human".
- `docs/feature_catalog.md`: existing features and their value, findings from the sample, six recommended additions.
- `docs/clustering_evaluation.md`: the 12 K-Means clusters named, quality checks, what ML adds, next experiment.
- `scripts/ml_profiles.py`: applies the categories to `scripts-out/ml/session_features.csv` and compares them with the clusters. Output: `scripts-out/ml/profile_report.md`, `profile_overview.png`.

### 3. Findings That Correct Earlier Statements
- The agreement of 0.94 between clusters and rule profiles (cluster_report.md) is decided by three bot scripts. Counted per behavior family it is 0.20.
- The cadence and archetype shares in Update 1 (72.4% burst and so on) are outdated. See section 6.3 of `docs/analysis_normalized_data.md`.
- Of the 11 sessions flagged as human, two are our own tests and nine are one script (typo rule accepts two-letter differences).
- `crontab -l` is tagged as persistence and `ls /var/log` as cleanup in `db_analyzer.py`. Not fixed yet, planned for Sprint 5.

### 4. How to Run
```powershell
python scripts/ml_profiles.py     # a few seconds, reads CSV files only
```
