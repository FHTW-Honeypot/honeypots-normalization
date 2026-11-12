"""
ML Feature Export (InnoLab 3, Sprint 2)
=======================================
Builds one row per Cowrie command session (session_id + src_ip) for clustering.

Reuses the logic of db_analyzer.py so ML and the rule-based analysis use the same definitions:
  - same database path resolution (C:\\honeypots-normalization\\... or repo root)
  - same unit as q13: Cowrie sessions with typed commands (payload not empty)
  - same command families (command_template) and intent tags (command_intents)

New on top of db_analyzer.py:
  - "behavior family": the command family with tool names unified, so that
    `wget <URL>` and `curl <URL>` or `/bin/./uname` and `uname` count as the same behavior
  - login attempts / successes, real file downloads and the SSH client of each session
    (taken from raw_data, because cowrie.session.file_download is not a payload_delivery event)
  - time-based sample: the LAST share (default 30 %) of command sessions, not random rows

Usage:
    python scripts/ml_features.py              # last 30 % of command sessions
    python scripts/ml_features.py --share 0.1  # smaller test run

Output: scripts-out/ml/session_features.csv
"""
import argparse
import csv
import hashlib
import re
import sqlite3
import sys
from collections import Counter
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_analyzer import DB_PATH, OUT_PATH, INTENT_ORDER, command_template, command_intents, parse_ts  # noqa: E402

ML_DIR = Path(OUT_PATH).parent / "ml"

# ------------------------------------------------------------
# Behavior family = command family + unified tool names
# ------------------------------------------------------------
_DL_RE = re.compile(r"\b(?:wget|curl|tftp|ftpget|lwp-download|fetch)\b(?:\s+-{1,2}[A-Za-z][\w-]*)*", re.I)
_CHMOD_RE = re.compile(r"\bchmod\s+(?:-R\s+)?(?:\+x|u\+x|a\+x|<N>)", re.I)
_BINPATH_RE = re.compile(r"(?<![\w/.])/(?:usr/)?s?bin/(?:\./)?(?=[A-Za-z])")
_SEP_RE = re.compile(r"\s*;\s*")


def behavior_template(template_text):
    """Makes command families that do the same thing look the same (Recep's wget/curl example)."""
    t = _DL_RE.sub("<DL>", template_text)
    t = _CHMOD_RE.sub("<CHMOD_X>", t)
    t = _BINPATH_RE.sub("", t)
    t = _SEP_RE.sub(" ; ", t)
    return re.sub(r"\s+", " ", t).strip()


# ------------------------------------------------------------
# SSH client banner -> small set of client families
# ------------------------------------------------------------
_VERSION_RE = re.compile(r'"version"\s*:\s*"([^"]*)"')
CLIENT_FAMILIES = [("ssh-2.0-go", "go"), ("libssh", "libssh"), ("paramiko", "paramiko"),
                   ("asyncssh", "asyncssh"), ("jsch", "jsch"), ("putty", "putty"),
                   ("dropbear", "dropbear"), ("openssh", "openssh")]


def client_family(raw):
    m = _VERSION_RE.search(raw or "")
    if not m:
        return "unknown"
    v = m.group(1).lower()
    for needle, name in CLIENT_FAMILIES:
        if needle in v:
            return name
    return "other"


def ts_str(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def build_sessions(conn):
    """One pass over Cowrie command events, same query as db_analyzer (q13)."""
    print("[1/3] Grouping Cowrie commands per session (same unit as db_analyzer q13)...")
    cur = conn.execute("""
        SELECT session_id, src_ip, MAX(src_country) AS src_country,
               GROUP_CONCAT(timestamp || char(31) || payload, char(30)) AS timed
        FROM events
        WHERE sensor_type = 'cowrie' AND event_category = 'command_execution' AND payload != ''
        GROUP BY session_id, src_ip
    """)
    sessions = []
    for sid, ip, country, timed in cur:
        events = []
        for item in (timed or "").split("\x1e"):
            ts, sep, payload = item.partition("\x1f")
            if sep:
                events.append((ts, payload))
        if not events:
            continue
        events.sort(key=lambda e: e[0])
        cmds = [p for _, p in events]
        start, end = events[0][0], events[-1][0]
        t1, t2 = parse_ts(start), parse_ts(end)
        duration = max(0.0, (t2 - t1).total_seconds()) if (t1 and t2) else 0.0
        n, uniq = len(cmds), len(set(cmds))
        template = " ; ".join(command_template(c) for c in cmds)
        tags = frozenset().union(*(command_intents(c) for c in set(cmds)))
        row = {
            "session_id": sid or "", "src_ip": ip, "src_country": country or "",
            "start": start, "end": end,
            "n_commands": n, "n_unique_commands": uniq,
            "duration_s": round(duration, 3),
            "mean_gap_s": round(duration / (n - 1), 3) if n >= 2 else 0.0,
            "repetition_ratio": round(1 - uniq / n, 4),
            "max_cmd_len": max(len(c) for c in cmds),
            "intent_profile": "+".join(t for t in INTENT_ORDER if t in tags) or "unclassified",
            "family": template[:400],
            "behavior": behavior_template(template)[:400],
            "exact_seq": hashlib.blake2b("\n".join(cmds).encode("utf-8", "ignore"), digest_size=8).hexdigest(),
        }
        for t in INTENT_ORDER:
            row[f"intent_{t}"] = int(t in tags)
        sessions.append(row)
    sessions.sort(key=lambda r: r["start"])
    return sessions


def add_context(conn, sample):
    """Logins, file downloads and SSH client, only for the sample period (uses idx_timestamp)."""
    t_first = parse_ts(sample[0]["start"])
    t_last = parse_ts(max(r["end"] for r in sample))
    lo, hi = ts_str(t_first - timedelta(hours=1)), ts_str(t_last + timedelta(hours=1))
    print(f"[2/3] Adding logins, downloads and SSH client for {lo} .. {hi}...")
    by_key = {(r["session_id"], r["src_ip"]): r for r in sample}
    for r in sample:
        r.update(n_auth=0, n_auth_success=0, n_file_downloads=0, client="unknown")
    cur = conn.execute("""
        SELECT session_id, src_ip,
               SUM(CASE WHEN event_category = 'authentication_attempt' THEN 1 ELSE 0 END) AS n_auth,
               SUM(CASE WHEN event_category = 'authentication_attempt'
                         AND instr(raw_data, 'cowrie.login.success') > 0 THEN 1 ELSE 0 END) AS n_auth_success,
               SUM(CASE WHEN instr(raw_data, 'cowrie.session.file_download') > 0 THEN 1 ELSE 0 END) AS n_downloads,
               MAX(CASE WHEN instr(raw_data, 'cowrie.client.version') > 0 THEN raw_data END) AS client_raw
        FROM events
        WHERE sensor_type = 'cowrie' AND timestamp >= ? AND timestamp <= ?
          AND session_id IS NOT NULL AND session_id != ''
        GROUP BY session_id, src_ip
    """, (lo, hi))
    for sid, ip, n_auth, n_ok, n_dl, client_raw in cur:
        r = by_key.get((sid, ip))
        if r:
            r.update(n_auth=n_auth or 0, n_auth_success=n_ok or 0,
                     n_file_downloads=n_dl or 0, client=client_family(client_raw))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DB_PATH, help=f"SQLite database (default: {DB_PATH})")
    ap.add_argument("--share", type=float, default=0.3, help="last share of command sessions to export (default 0.3)")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.execute("PRAGMA query_only = ON;")
    conn.execute("PRAGMA cache_size = -1000000;")

    sessions = build_sessions(conn)
    if not sessions:
        sys.exit("No Cowrie command sessions found.")
    cut = int(len(sessions) * (1 - args.share))
    sample = sessions[cut:]
    add_context(conn, sample)
    conn.close()

    ML_DIR.mkdir(parents=True, exist_ok=True)
    out = ML_DIR / "session_features.csv"
    print(f"[3/3] Writing {out} ...")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(sample[0].keys()))
        w.writeheader()
        w.writerows(sample)

    months = Counter(r["start"][:7] for r in sessions)
    n = len(sample)
    fam, beh, exact = (len({r[k] for r in sample}) for k in ("family", "behavior", "exact_seq"))
    print("\n=== Summary ===")
    print(f"Command sessions in DB      : {len(sessions):,}  (months: {dict(sorted(months.items()))})")
    print(f"Sample (last {args.share:.0%}, by time) : {n:,} sessions, {sample[0]['start'][:19]} .. {sample[-1]['start'][:19]}")
    print(f"Distinct exact sequences    : {exact:,}  -> duplicate share {1 - exact / n:.2%}")
    print(f"Command families (analyzer) : {fam:,}")
    print(f"Behavior families (unified) : {beh:,}  ({fam - beh:,} families merged by tool unification)")
    print(f"Sessions with file download : {sum(1 for r in sample if r['n_file_downloads']):,}")
    print("SSH clients                 :", dict(Counter(r["client"] for r in sample).most_common()))


if __name__ == "__main__":
    main()
