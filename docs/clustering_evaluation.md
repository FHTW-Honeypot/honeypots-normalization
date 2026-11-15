# Clustering Prototype: What the Clusters Mean and What They Do Not Show

InnoLab 3, Sprint 3. This document interprets the first clustering run (`scripts/ml_cluster.py`, output in `scripts-out/ml/cluster_report.md`) and compares it with the rule-based behavior categories from [attacker_profiles.md](attacker_profiles.md).

All numbers come from `scripts-out/ml/` and can be reproduced without the database:

```powershell
python scripts/ml_profiles.py     # reads the two CSV files, writes scripts-out/ml/profile_report.md
```

## 1. Short answer

1. The 12 K-Means clusters can all be named. In 10 of them more than 92% of the sessions belong to one behavior category. The exceptions are clusters 3 and 11.
2. The clustering found nothing that the rules do not already find. The largest group that the old intent tags left "unclassified" (the `echo` login checks, 51% of the sample) is found by the clustering, but a single rule finds it as well.
3. The reported agreement of 0.94 between clusters and rules is too optimistic. It is decided by three bot scripts. When every behavior family counts once, the agreement is 0.20 with the old intent profiles and 0.40 with the new categories.
4. The cluster quality score is weak (silhouette 0.13, negative for most values of k). With only 71 distinct behaviors in the training part there is very little to cluster.
5. One place where a similarity measure should help: a recon bot that picks 8 commands from a pool of about 22 in every session. Template matching sees 207 different "families" from one IP. Testing this is the experiment for Sprint 4.

## 2. What was done

| Step | Choice | Reason |
|:---|:---|:---|
| Unit | One Cowrie session with at least one typed command | Only these sessions contain behavior. 3.4 million Cowrie sessions have no command. |
| Sample | Last 30% of command sessions by time: 77,984 sessions, 2026-02-17 to 2026-03-31 | Supervisor: start small, take a time-based part, not random rows. |
| Split | First 70% of the sample for training (54,588 sessions), last 30% for testing (23,396) | Random splits leak near-duplicates from the future into training. |
| De-duplication | Models are fitted on 71 behavior families, weighted by their number of sessions | 98% of sessions are exact duplicates. Without this, one bot script decides everything. |
| Features | 9 numbers (commands, duration, gap, repetition, logins, downloads), 7 intent flags, 10 SSH client shares, 15 text components (TF-IDF + SVD) | First attempt: everything that was available. |
| Algorithms | K-Means (k from 2 to 12, picked by silhouette) and DBSCAN | The supervisor asked for two well-known algorithms and named K-Means. DBSCAN is our second choice because it needs no k and marks rare behavior as outliers. |

## 3. The 12 clusters, named

Names were given by reading every family in `scripts-out/ml/family_clusters.csv`. "Category" is the rule-based category from `attacker_profiles.md`. Session counts are train and test together.

| Cluster | Sessions | Families | Name | Main category | Remark |
|---:|---:|---:|:---|:---|:---|
| 0 | 12,290 | 25 | SSH key injection (`mdrfckr` key) | SSH key backdoor | 99.6% one category. |
| 1 | 39,640 | 6 | `echo` login check, Go client | Login check | 99.8% one category. 51% of all sessions, from very few IPs. |
| 2 | 20,126 | 26 | Scripted system fingerprint (5 commands, `export PATH ...`) | System reconnaissance | Clean. |
| 3 | 775 | 19 | Key injection plus password change and inventory | Full takeover chain | Also contains one unrelated binary dropper family (87 sessions). |
| 4 | 76 | 3 | MikroTik, Telegram and SMS modem search | Targeted device and data search | Clean. |
| 5 | 378 | 6 | `uname -a` probe | System reconnaissance | Also contains five download-and-execute sessions. |
| 6 | 2,307 | 7 | One-command `uname` and `ssh -V` probes | System reconnaissance | Clean. |
| 7 | 163 | 12 | Download-and-execute loaders (`bins.sh`, `sshbins.sh`) | Malware download or execution | Clean. Most of it only appears in the test period. |
| 8 | 13 | 4 | Sessions from an OpenSSH client | System reconnaissance | Grouped by client, not by behavior. Contains our own manual test session. |
| 9 | 226 | 3 | `echo -n login_success`, paramiko client | Login check | Same behavior as cluster 1, split off because of the client. |
| 10 | 12 | 3 | Installer script pasted through PuTTY, 26 s between commands | Malware download or execution | Grouped by client and pace. |
| 11 | 1,978 | 192 | Everything else from Go clients | System reconnaissance (86%) | Catch-all: one-command probes, the shuffled recon script, installers and payload starters. |

Two observations:

- **Three small clusters are separated by the SSH client, not by the behavior.** Clusters 1 and 9 are the same behavior with a different client library. Clusters 8 and 10 collect sessions from OpenSSH and PuTTY clients. Together the three are 251 sessions. In the big clusters client and behavior go together, so we cannot say which one decided. We did not test this by removing the client columns. The Sprint 4 experiment does.
- **Cluster 11 is not a behavior.** It holds 192 of the 306 families, four categories, and both harmless probes and malware starters.

## 4. How good is the clustering?

| Check | Result | Meaning |
|:---|:---|:---|
| Silhouette at k = 12 | 0.13 | Weak. Values near 0 mean clusters overlap. |
| Silhouette for k = 3 to 9 | negative (-0.17 to 0.00) | For most k, families sit closer to another cluster than to their own. |
| Chosen k | 12, which is the upper limit of the search | The best score is at the edge of the search range, and larger k were never tried. 12 is where the search stopped, not a proven optimum. |
| DBSCAN | 8 clusters, but one of them contains K-Means clusters 0, 1, 2, 6 and 11 | With the automatic `eps` (11.3) DBSCAN merges the big groups. It is only useful as an outlier list (9 rare families). |
| PCA plot | Almost all families lie on one point, a few outliers stretch the axes | Not readable. `profile_overview.png` uses two real axes instead. |

Agreement with the rules (Adjusted Rand Index, 1 = same grouping, 0 = random):

| Comparison | ARI |
|:---|---:|
| Train sessions, K-Means vs. intent profiles (the value in `cluster_report.md`) | 0.94 |
| Train sessions, K-Means vs. behavior categories | 0.96 |
| Train families (71, each counted once), K-Means vs. intent profiles | 0.20 |
| Train families (71, each counted once), K-Means vs. behavior categories | 0.40 |

Why the first two numbers are misleading:

- Three families hold 48,874 of the 54,588 train sessions (89.5%). If these three land in three different clusters, the session-level score is already high.
- The 7 intent flags are part of the clustering input. Comparing the clusters with the same flags afterwards is partly circular.

## 5. What ML adds here, honestly

| Question | Answer from this run |
|:---|:---|
| Does clustering find the same groups as the rules? | For the big scripts yes, for the many small ones no (family-level ARI 0.20 to 0.40). |
| Does it find groups the rules miss? | No. No cluster contains a behavior that the six categories do not cover. |
| Does it flag new behavior over time? | 459 test sessions (2.0%) use a family not seen in training, 6 are far from every cluster. 207 of the 235 "new" families are the one recon bot that recombines known commands, so the real amount of new behavior is smaller. |
| Is the data suitable for more advanced ML? | Not as it is. 77,984 sessions reduce to 306 families, and 24 source IPs produce 55.6% of the sessions. |

This matches the supervisor's expectation from the meeting on 2026-10-23: the data has too many duplicates, and what was found so far can be classified with traditional analysis. It is a result, not a failure: the rule baseline covers 99.95% of the sample with six categories.

## 6. Known weaknesses of the prototype

1. The sample is 6 weeks. The full command data set (259,946 sessions, 767 families, 2026-01-07 to 2026-03-31) has not been clustered yet.
2. Rule tags and SSH client are part of the features (see section 4).
3. The family key needs an exact match of the masked commands. The recon bot from one IP that recombines its commands in every session creates 207 families.
4. The k search stops at 12 and the silhouette is computed without the session weights.
5. Two errors in the intent tags of `db_analyzer.py` affect the comparison: `crontab -l` (listing cron jobs) counts as persistence, and `ls /var/log` counts as cleanup. `ml_profiles.py` works around the first one.

## 7. Next experiment (Sprint 4)

One focused change instead of many: **cluster on the command words only (bag of words), without rule tags or client.**

- Input: bag of command words per family (TF-IDF), nothing else.
- Run K-Means with k from 2 to 30 and DBSCAN on the same input.
- Report on family level: silhouette, ARI against the behavior categories, purity per cluster, and how many of the "new" test families are close to a known cluster.
- One readable plot of the new clusters, colored by category.

Possible outcomes, both are usable results:

- The text-only clusters match the categories: the rules are confirmed by a method that did not know them.
- They do not match: clustering groups by tool or script, not by intent, and is a second view next to the rules.

*Clusters are groups of similar behavior. They are not proof that the same actor is behind them.*
