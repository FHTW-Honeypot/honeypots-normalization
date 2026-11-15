"""
Behavior Profiles (InnoLab 3, Sprint 3)
=======================================
Applies the documented behavior categories (docs/attacker_profiles.md) to the sessions exported by
ml_features.py and compares them with the K-Means clusters from ml_cluster.py.

This script only reads the two CSV files in scripts-out/ml/. It does NOT touch the database,
so it runs in a few seconds.

What it does:
  1. assigns exactly one behavior category to every command session (ordered rules, first match wins)
  2. assigns an interaction style (how fast the commands arrive)
  3. aggregates sessions per source IP (which categories does one IP show?)
  4. compares categories with the K-Means clusters (purity, Adjusted Rand Index on session and family level)

Usage:
    python scripts/ml_profiles.py

Output: scripts-out/ml/profile_report.md
"""
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ML_DIR = Path(__file__).resolve().parent.parent / "scripts-out" / "ml"

# Order of the categories = order of the rules below (first match wins)
CATEGORIES = [
    ("targeted_search", "Targeted device and data search"),
    ("takeover_chain", "Full takeover chain"),
    ("backdoor_key", "SSH key backdoor"),
    ("malware_execution", "Malware download or execution"),
    ("login_check", "Login check (echo probe)"),
    ("system_recon", "System reconnaissance"),
    ("other", "Other / not covered"),
]
LABEL = dict(CATEGORIES)

# Markers of scripts that look for one specific device type or data set
TARGET_MARKERS = ("/ip cloud print", "telegramdesktop", "/var/spool/sms", "ttygsm")
# First words of commands that only look around but are not tagged as recon by db_analyzer.py
DISCOVERY_CMDS = {"pwd", "ls", "mount", "env", "history", "ssh", "cat", "df", "locate", "find", "which"}


# Persistence only counts if the session changes access: writes a key or sets a password / user.
# Reason: db_analyzer.py also tags `crontab -l` (only LISTS cron jobs) as persistence, which turns
# pure recon scripts into "persistence" sessions. See docs/attacker_profiles.md, section 6.
ACCESS_CHANGE_MARKERS = ("authorized_keys", "chpasswd", "passwd", "useradd", "adduser")


def category(row):
    text = row["behavior"].lower()
    recon, download, execute = row["intent_recon"], row["intent_download"], row["intent_execute"]
    persistence = row["intent_persistence"] and any(m in text for m in ACCESS_CHANGE_MARKERS)
    any_intent = recon or download or execute or row["intent_persistence"] or row["intent_cleanup_evasion"] \
        or row["intent_cryptomining"] or row["intent_iot_botnet_probe"]
    first_word = text.split(" ", 1)[0].rsplit("/", 1)[-1]

    if any(m in text for m in TARGET_MARKERS):
        return "targeted_search"
    if persistence and (execute or recon):
        return "takeover_chain"
    if persistence:
        return "backdoor_key"
    if download or execute:
        return "malware_execution"
    if not any_intent and first_word == "echo":
        return "login_check"
    if recon:
        return "system_recon"
    if not any_intent and first_word in DISCOVERY_CMDS:
        return "system_recon"
    return "other"


def style(row):
    if row["n_commands"] < 2:
        return "single command"
    gap = row["mean_gap_s"]
    if gap < 0.5:
        return "burst (< 0.5 s)"
    if gap < 2:
        return "fast (0.5 - 2 s)"
    if gap < 5:
        return "paced (2 - 5 s)"
    return "slow (>= 5 s)"


# Activity type per source IP (first proposal, to be re-checked on the full data set)
HIGH_VOLUME_SESSIONS = 100
LOW_SLOW_DAYS = 8
LOW_SLOW_PER_DAY = 5

STYLES = ["single command", "burst (< 0.5 s)", "fast (0.5 - 2 s)", "paced (2 - 5 s)", "slow (>= 5 s)"]


def adjusted_rand_index(a, b):
    """Adjusted Rand Index without scikit-learn (1 = same grouping, 0 = random agreement)."""
    def pairs(n):
        return n * (n - 1) / 2
    table = Counter(zip(a, b))
    sum_cells = sum(pairs(n) for n in table.values())
    sum_a = sum(pairs(n) for n in Counter(a).values())
    sum_b = sum(pairs(n) for n in Counter(b).values())
    expected = sum_a * sum_b / pairs(len(a))
    maximum = (sum_a + sum_b) / 2
    return (sum_cells - expected) / (maximum - expected) if maximum != expected else 1.0


def md_table(header, rows, align=None):
    align = align or ["---"] * len(header)
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(align) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return lines


def short(text, n=100):
    text = str(text).replace("|", "\\|")
    return text if len(text) <= n else text[:n] + "..."


def plot_overview(df, names):
    """One dot per behavior family on two readable axes (commands, pace); colour = category, size = sessions."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed - skipping profile_overview.png")
        return
    fam = df.groupby("behavior").agg(cmds=("n_commands", "median"), gap=("mean_gap_s", "median"),
                                     sessions=("category", "size"), category=("category", "first"))
    colors = dict(zip(names, ["#7b3294", "#d7191c", "#fdae61", "#000000", "#2c7bb6", "#1a9641", "#999999"]))
    fig, ax = plt.subplots(figsize=(9, 6))
    for c in names:
        f = fam[fam.category == c]
        if f.empty:
            continue
        # gap 0 (single command) is drawn at 0.0005 s so that it is visible on the log axis
        ax.scatter(f.cmds, f.gap.clip(lower=0.0005), s=12 + 22 * np.log1p(f.sessions), c=colors[c], alpha=0.6,
                   edgecolors="none", label=f"{LABEL[c]} ({int(f.sessions.sum()):,} sessions, {len(f)} families)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.axhline(5, ls="--", c="grey", lw=0.8)
    ax.text(ax.get_xlim()[0] * 1.1, 5.6, "5 s: typing pace of a person", fontsize=8, color="grey")
    ax.set(xlabel="Commands per session (median of the family)",
           ylabel="Seconds between commands (median, 0 drawn at 0.0005)",
           title="Cowrie behavior families by category (dot size = sessions)")
    ax.legend(fontsize=8, loc="center left", bbox_to_anchor=(1.01, 0.5), markerscale=0.6)
    fig.tight_layout()
    fig.savefig(ML_DIR / "profile_overview.png", dpi=150)
    plt.close(fig)


def main():
    feats = ML_DIR / "session_features.csv"
    clus = ML_DIR / "session_clusters.csv"
    if not feats.exists() or not clus.exists():
        sys.exit("Run ml_features.py and ml_cluster.py first (missing CSV files in scripts-out/ml/).")
    key = ["session_id", "src_ip"]
    df = pd.read_csv(feats, keep_default_na=False, dtype={"session_id": str, "src_ip": str})
    cl = pd.read_csv(clus, keep_default_na=False, dtype={"session_id": str, "src_ip": str},
                     usecols=key + ["split", "kmeans"])
    df = df.merge(cl, on=key, how="left", validate="one_to_one")
    if df["kmeans"].isna().any():
        sys.exit("session_clusters.csv does not match session_features.csv - run ml_cluster.py again.")
    df["kmeans"] = df["kmeans"].astype(int)
    df["category"] = df.apply(category, axis=1)
    df["style"] = df.apply(style, axis=1)
    df["day"] = df["start"].str[:10]
    n = len(df)
    names = [c for c, _ in CATEGORIES]

    L = ["# Behavior Profiles - Check Against the Session Sample", "",
         f"- Input: {n:,} Cowrie command sessions ({df.start.min()[:10]} to {df.start.max()[:10]}), "
         f"{df.src_ip.nunique():,} source IPs, {df.behavior.nunique():,} behavior families",
         "- Rules: `category()` in scripts/ml_profiles.py, definitions in docs/attacker_profiles.md",
         "- Generated by `python scripts/ml_profiles.py` (reads CSV files only, no database access)", ""]

    # ---------- 1. categories ----------
    L += ["## 1. Behavior categories", ""]
    rows = []
    for c in names:
        s = df[df.category == c]
        if s.empty:
            rows.append([LABEL[c], 0, "0.00%", 0, 0, "-", "-", "-", "-"])
            continue
        top_client = ", ".join(f"{k} {v:.0%}" for k, v in s.client.value_counts(normalize=True).head(2).items())
        rows.append([LABEL[c], f"{len(s):,}", f"{len(s) / n:.2%}", f"{s.src_ip.nunique():,}",
                     f"{s.behavior.nunique():,}", f"{s.n_commands.median():g}", f"{s.mean_gap_s.median():g}",
                     top_client, f"`{short(s.behavior.value_counts().index[0], 70)}`"])
    L += md_table(["Category", "Sessions", "Share", "IPs", "Families", "Med. cmds", "Med. gap s", "Top clients",
                   "Biggest family"], rows,
                  [":---", "---:", "---:", "---:", "---:", "---:", "---:", ":---", ":---"])
    other = df[df.category == "other"]
    L += ["", f"Not covered by any rule: {len(other):,} sessions ({len(other) / n:.2%}). Their families:", ""]
    for b, cnt in other.behavior.value_counts().head(12).items():
        L.append(f"- {cnt:,} sessions: `{short(b, 120)}`")

    # ---------- 2. interaction style ----------
    L += ["", "## 2. Interaction style per category (share of the category's sessions)", ""]
    ct = pd.crosstab(df.category, df["style"]).reindex(index=names, columns=STYLES, fill_value=0)
    rows = [[LABEL[c]] + [f"{ct.loc[c, s] / max(1, ct.loc[c].sum()):.1%}" for s in STYLES] + [f"{ct.loc[c].sum():,}"]
            for c in names]
    L += md_table(["Category"] + STYLES + ["Sessions"], rows, [":---"] + ["---:"] * (len(STYLES) + 1))

    # ---------- 3. per source IP ----------
    L += ["", "## 3. Source IPs: how many categories does one IP show?", ""]
    per_ip = df.groupby("src_ip").agg(sessions=("category", "size"), days=("day", "nunique"),
                                      cats=("category", lambda s: "+".join(c for c in names if c in set(s))))
    per_ip["n_cats"] = per_ip.cats.str.count(r"\+") + 1
    total_ips = len(per_ip)
    rows = [[k, f"{v:,}", f"{v / total_ips:.2%}"] for k, v in per_ip.n_cats.value_counts().sort_index().items()]
    L += md_table(["Categories per IP", "IPs", "Share"], rows, ["---:", "---:", "---:"])
    L += ["", "Most common combinations:", ""]
    combo = per_ip.groupby("cats").agg(ips=("sessions", "size"), sessions=("sessions", "sum"),
                                       med_days=("days", "median")).sort_values("ips", ascending=False)
    rows = [[" + ".join(LABEL[c] for c in k.split("+")), f"{int(r.ips):,}", f"{r.ips / total_ips:.2%}",
             f"{int(r.sessions):,}", f"{r.med_days:g}"] for k, r in combo.head(12).iterrows()]
    L += md_table(["Categories seen from the IP", "IPs", "Share of IPs", "Sessions", "Median active days"], rows,
                  [":---", "---:", "---:", "---:", "---:"])
    # Activity type per IP. Thresholds are a first proposal (docs/attacker_profiles.md, section 4).
    per_ip["per_day"] = per_ip.sessions / per_ip.days

    def activity(r):
        if r.sessions >= HIGH_VOLUME_SESSIONS:
            return "High-volume automation"
        if r.days >= LOW_SLOW_DAYS and r.per_day <= LOW_SLOW_PER_DAY:
            return "Low-and-slow"
        return "One-day visitor" if r.days == 1 else "Recurring bot node"

    per_ip["activity"] = per_ip.apply(activity, axis=1)
    L += ["", f"Activity type per IP (high-volume: >= {HIGH_VOLUME_SESSIONS} command sessions; low-and-slow: active on "
          f">= {LOW_SLOW_DAYS} days with <= {LOW_SLOW_PER_DAY} sessions per active day; otherwise by active days):", ""]
    act = per_ip.groupby("activity").agg(ips=("sessions", "size"), sessions=("sessions", "sum"),
                                         med_days=("days", "median"), med_per_day=("per_day", "median"))
    rows = [[a, f"{int(r.ips):,}", f"{r.ips / total_ips:.2%}", f"{int(r.sessions):,}", f"{r.sessions / n:.2%}",
             f"{r.med_days:g}", f"{r.med_per_day:.1f}"]
            for a, r in act.reindex(["One-day visitor", "Recurring bot node", "Low-and-slow",
                                     "High-volume automation"]).dropna().iterrows()]
    L += md_table(["Activity type", "IPs", "Share of IPs", "Sessions", "Share of sessions", "Median active days",
                   "Median sessions per active day"], rows, [":---"] + ["---:"] * 6)
    one_session = int((per_ip.sessions == 1).sum())
    L += ["", f"- {one_session:,} of {total_ips:,} IPs ({one_session / total_ips:.1%}) appear with exactly one command session.",
          f"- {int((per_ip.days >= 8).sum()):,} IPs are active on 8 or more days of the {df.day.nunique()} days in the sample."]

    # ---------- 4. categories vs. K-Means ----------
    L += ["", "## 4. Categories vs. K-Means clusters (all sessions, train and test)", ""]
    ks = sorted(df.kmeans.unique())
    ct = pd.crosstab(df.category, df.kmeans).reindex(index=names, columns=ks, fill_value=0)
    rows = [[LABEL[c]] + [f"{ct.loc[c, k]:,}" if ct.loc[c, k] else "." for k in ks] for c in names]
    L += md_table(["Category \\ Cluster"] + [str(k) for k in ks], rows, [":---"] + ["---:"] * len(ks))
    L += ["", "Purity = share of the cluster's sessions (or families) that belong to its biggest category:", ""]
    fam = df.drop_duplicates("behavior")
    rows = []
    for k in ks:
        s, f = df[df.kmeans == k], fam[fam.kmeans == k]
        vs, vf = s.category.value_counts(), f.category.value_counts()
        rows.append([k, f"{len(s):,}", len(f), LABEL[vs.index[0]], f"{vs.iloc[0] / len(s):.1%}",
                     f"{vf.iloc[0] / len(f):.1%}", f.category.nunique()])
    L += md_table(["Cluster", "Sessions", "Families", "Biggest category", "Session purity", "Family purity",
                   "Categories in cluster"], rows, ["---:", "---:", "---:", ":---", "---:", "---:", "---:"])
    tr = df[df.split == "train"]
    ftr = tr.drop_duplicates("behavior")
    L += ["", "Agreement (Adjusted Rand Index, 1 = same grouping, 0 = random):", ""]
    rows = [
        ["Train sessions: K-Means vs. intent profiles (value in cluster_report.md)",
         f"{adjusted_rand_index(tr.intent_profile, tr.kmeans):.2f}"],
        ["Train sessions: K-Means vs. behavior categories", f"{adjusted_rand_index(tr.category, tr.kmeans):.2f}"],
        [f"Train families ({len(ftr)} families, each counted once): K-Means vs. intent profiles",
         f"{adjusted_rand_index(ftr.intent_profile, ftr.kmeans):.2f}"],
        [f"Train families ({len(ftr)} families, each counted once): K-Means vs. behavior categories",
         f"{adjusted_rand_index(ftr.category, ftr.kmeans):.2f}"],
    ]
    L += md_table(["Comparison", "ARI"], rows, [":---", "---:"])
    top3 = tr.behavior.value_counts().head(3).sum()
    L += ["", f"- The three biggest families hold {top3:,} of {len(tr):,} train sessions ({top3 / len(tr):.1%}). "
          "Session-level agreement is therefore decided by three bot scripts.",
          "", "*Categories are transparent rules, not ground truth. Similar behavior does not prove the same actor.*"]

    plot_overview(df, names)
    out = ML_DIR / "profile_report.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    print(f"\nWritten: {out}")


if __name__ == "__main__":
    main()
