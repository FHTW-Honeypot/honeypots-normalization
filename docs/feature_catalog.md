# Feature Catalog: Commands, Payloads and Credentials

InnoLab 3, Sprint 3. This document lists which features describe a Cowrie session, which ones we already have, how useful they turned out to be, and which few we should add. It follows the supervisor's path: decide which features can be used for attacker profiling, then build a clean feature data set.

- Feature export: `scripts/ml_features.py` (reads the database), output `scripts-out/ml/session_features.csv`
- Checks in this document: on the sample of 77,984 command sessions (2026-02-17 to 2026-03-31)

## 1. Short answer

- We have 26 columns per session. **Four features carry almost all the information:** the masked command text, the number of commands, the time between commands and the intent tags.
- **Two existing features are useless and one is misnamed** (section 3).
- **Credentials are the gap.** They are the only information we have for the 93% of sessions without commands, and for all of Heralding, but none of it is in the feature set.
- We recommend adding **six features**, not thirty (section 5).

## 2. Features we have

| Group | Feature | Meaning | Verdict |
|:---|:---|:---|:---|
| Command | `behavior` | Commands with URLs, IPs, numbers and secrets masked and download tools unified | Most useful single feature. 77,984 sessions reduce to 306 values. |
| Command | `family`, `exact_seq` | Same without tool unification, and a hash of the exact commands | Needed to measure duplicates. |
| Command | `n_commands`, `n_unique_commands` | How many commands, how many different ones | Useful. Separates one-line probes (1) from scripts (3 to 5) and takeover chains (20). |
| Command | `repetition_ratio` | Share of repeated commands | Weak. Almost always 0 once only typed commands are counted. |
| Command | `max_cmd_len` | Length of the longest command | Useful in a limited way: long one-liners are scripts. |
| Command | `intent_*` (7 flags), `intent_profile` | Rule-based tags: recon, download, execute, persistence, cleanup_evasion, cryptomining, iot_botnet_probe | Useful for the categories. Must not be clustering input and comparison target at the same time. Two tags have known errors. |
| Timing | `duration_s`, `mean_gap_s` | Session length and time between commands | Useful. Separates burst scripts from paced scripts. |
| Timing | `start`, `end` | Timestamps | Needed for the time-based split and for active days per IP. |
| Tooling | `client` | SSH client library from the banner (go, libssh, paramiko, putty, openssh, ...) | Useful as description. As clustering input it dominates: clusters formed by client instead of behavior. |
| Source | `src_ip`, `src_country` | Source address and country | Needed for the IP level. Country is not a behavior feature. |
| Login | `n_auth`, `n_auth_success` | Login attempts and successes in the session | No information, see section 3. |
| Payload | `n_file_downloads` | Cowrie `file_download` events in the session | Misleading name, see section 3. |

## 3. What the check on the sample showed

| Finding | Evidence | Consequence |
|:---|:---|:---|
| `n_auth` and `n_auth_success` are constants | `n_auth` is 1 in 99.9% of the sessions (maximum 2). `n_auth_success` is never 0. | A session with commands always has exactly one successful login. Remove both from the clustering input. Login behavior has to be measured per IP, not per session. |
| `n_file_downloads` does not count downloads | It is above 0 in 12,229 SSH key backdoor sessions and only 209 malware sessions. | Probably Cowrie logs the written `authorized_keys` file as a file event (to be confirmed in a raw log). Rename it to "files written" or split it by whether a URL is involved. |
| The persistence tag is too broad | `crontab -l` only lists cron jobs but sets the tag. 137 recon sessions carry the tag. | Fix in `db_analyzer.py`: only count `crontab` when it writes. |
| The cleanup tag is too broad | `ls /var/log` sets it because of the path `/var/log`. | Fix in `db_analyzer.py`: require a deleting or stopping command. |
| Exact matching creates false variety | One bot picks 8 look-around commands from a pool of about 22 in every session, in random order. It produces 207 families from one IP. | Sorting the commands would not help, because the sets differ too. Compare sessions by the command words they share (bag of words, section 5). |
| Long commands are cut | `behavior` is cut at 400 characters (20,929 sessions), `raw_data` in the database at 1,000 characters (18% of command events). | Keyword features only see the beginning. Document it, do not try to repair it. |

## 4. Features by the three areas of the sprint goal

### 4.1 Command features

| Feature | Have it? | Why it matters |
|:---|:---|:---|
| Masked command sequence (`behavior`) | yes | Identifies the bot script. |
| Command words without order (bag of words) | **no** | Lets a similarity measure group scripts that shuffle or vary their commands. |
| Number of commands, unique commands | yes | Size of the script. |
| First command of the session | **no** | Cheap and readable: `echo` (login check), `export` or `uname` (recon) and `cd` (SSH key backdoor) already separate the three biggest categories. |
| Intent tags | yes | Building blocks of the categories. |
| Time between commands | yes | Interaction style. |

### 4.2 Payload features

"Payload" here means what the attacker brings onto the machine: a downloaded file, an uploaded file or an injected SSH key.

| Feature | Have it? | Why it matters |
|:---|:---|:---|
| Download or execute happened (`intent_download`, `intent_execute`) | yes | Separates malware delivery from recon. |
| Download host | **no** (masked as `<URL>`) | The same host behind many source IPs links them to one campaign. This is the strongest campaign indicator we could add. |
| Download host equals source IP | **no** | Shows whether the bot serves its own malware (worm-like) or uses a central server. |
| File name of the payload (`bins.sh`, `sshbins.sh`, `x86`) | partly (inside `behavior`) | Readable name of the loader family. |
| Comment of the injected SSH key (`mdrfckr`, `rsa-key-...`) | partly (inside `behavior`) | Identifies the campaign directly. |
| File hash (`shasum`) | in the database, not in the features | Exact identity of the malware. Only useful with an external lookup, so low priority. |

### 4.3 Credential features

Credentials belong to the IP level: a brute-force source tries many passwords over many sessions, and a command session has exactly one successful login.

| Feature (per source IP) | Have it? | Why it matters |
|:---|:---|:---|
| Number of login attempts, number of different passwords and user names | **no** | Separates one-password bots from dictionary brute force. |
| The credential that succeeded | **no** (only in the report) | One credential (`root:3245gs5662d34`) was used by 5,308 IPs for 60,948 successful logins. The SSH key campaign has a similar size (63,977 key injections from 5,617 IPs). If the two belong together, the credential identifies the campaign already at login. This link is not measured yet. |
| Share of attempts from known default lists (Mirai) | **no** (list exists in `db_analyzer.py`) | Shows IoT botnets. |
| Empty password, user name equals password | **no** | Typical for device defaults. |
| Attempts until the first success | **no** | Blind guessing against targeted use of a known credential. |

One caution for the credential tables in the report: the top "credentials" on Heralding include `enable:system`, `system:shell`, `shell:sh` and `enable:linuxshell`. The words `enable`, `system`, `shell` and `sh` are commands that the Mirai bot sends after a Telnet login (they are in the published Mirai source code). It is likely that Heralding logged these command lines as user name and password. This has to be checked in the raw Heralding log before the numbers are used.

## 5. Recommendation: what to add, and what not

Add these six. Each one answers a question that the current features cannot.

| # | New feature | Level | Effort | Answers |
|---:|:---|:---|:---|:---|
| 1 | Command words without order (bag of words) | session | low, text processing in `ml_features.py` | Is this session built from the same commands as a known script? |
| 2 | First command | session | low | Quick, readable grouping. |
| 3 | Download host (before masking) and "host equals source IP" | session | low to medium | Which IPs share one malware server? |
| 4 | Successful credential of the session | session | low, the login event is already read | Which campaign does the session belong to? |
| 5 | Login attempts and different passwords per IP | IP | medium, one query on Cowrie and Heralding | Brute-force style of the source. |
| 6 | Active days and sessions per active day | IP | done in `ml_profiles.py` | Activity type (low-and-slow, high-volume). |

Do not add:

| Idea | Why not |
|:---|:---|
| Country, ASN, time of day | They describe where bots are hosted, not what they do. They would split identical behavior into many groups. |
| Terminal size, key exchange details | Only relevant for telling humans from bots, and we have no human sessions to tell apart. |
| Command entropy, character statistics | Hard to explain and not needed while 306 families cover the whole sample. |
| File hashes with VirusTotal lookup | Needs an external service and accounts. Out of scope for this semester. |
| Embeddings or neural language models of commands | No labels, little variety, and no one could explain the result in the review. |

## 6. Which features go into the clustering

| Use | Features |
|:---|:---|
| Clustering input (Sprint 4 experiment) | command words without order (bag of words, weighted with TF-IDF). Nothing else. |
| Describing the clusters afterwards | number of commands, time between commands, client, intent tags, category, successful credential |
| Comparison target | behavior category from `attacker_profiles.md` |

Reason for the strict separation: if the tags and the client are input, the clusters repeat them, and the comparison with the rules proves nothing (see [clustering_evaluation.md](clustering_evaluation.md), section 4).
