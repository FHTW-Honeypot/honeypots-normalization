"""
Deep Analyzer for Honeypot Normalized Data
Runs queries against honeypot_normalized.db to answer
interesting questions.

Performance: the events table is scanned only a few times. Results that used to need their own
full-table scan are derived from shared aggregates that are computed once:
  - per (sensor_type, sensor_instance, event_category)  -> volume, noise, validation
  - per (src_ip, sensor_type)                            -> IP, country, cross-sensor, mdrfckr
  - per payload (streamed)                               -> payload recurrence, credentials
  - per Cowrie session (streamed)                        -> interactive/human sessions, ML readiness

InnoLab 3 additions (Q13-Q16) prepare the session clustering work: dataset size, duplicate and
diversity metrics, command families (template baseline), rule-based intent baseline, temporal
novelty with a time-based split suggestion, attacker recurrence and the Cowrie login funnel.
"""
import sqlite3
import json
import re
import hashlib
import heapq
import itertools
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache

import os
import sys
import time
from pathlib import Path

# Dynamic path resolution: prefer C:\honeypots-normalization if exists, else repo root
C_PATH_DB = Path(r"C:\honeypots-normalization\honeypot_normalized.db")
C_PATH_OUT = Path(r"C:\honeypots-normalization\scripts-out\analyzer_results.json")

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_DB = REPO_ROOT / "honeypot_normalized.db"
REPO_OUT = REPO_ROOT / "scripts-out" / "analyzer_results.json"

if C_PATH_DB.exists():
    DB_PATH = str(C_PATH_DB)
    OUT_PATH = str(C_PATH_OUT)
else:
    DB_PATH = str(REPO_DB)
    OUT_PATH = str(REPO_OUT)

ANALYZER_VERSION = "3.0"

USEFUL_CATEGORIES = ('authentication_attempt', 'command_execution', 'payload_delivery')

MIRAI_CREDENTIALS = {
    'root:xc3511', 'root:vizxv', 'root:admin', 'admin:admin', 'root:default',
    'root:root', 'root:1234', 'root:12345', 'root:password', 'root:123456',
    '345gs5662d34:345gs5662d34', 'root:54321', 'root:888888',
}

# Share of the (time-ordered) command sessions used for training in the suggested split
TRAIN_SHARE = 0.7

class AnalyzerProgress:
    """
    Modular, clean progress manager for db_analyzer.
    Displays a persistent global progress bar showing overall progression across all
    analytical parts, plus in-place sub-step status without polluting terminal output.
    """
    def __init__(self, total_sections=12, bar_width=20):
        self.total_sections = total_sections
        self.bar_width = bar_width
        self.current_step = 0
        self.current_title = ""
        self.current_qid = ""
        self.step_start_time = None
        self.start_time = time.time()
        self.timings = {}

    def start_section(self, q_id, title):
        """Starts a new top-level analytical section."""
        self.current_step += 1
        self.current_qid = q_id
        self.current_title = title
        self.step_start_time = time.time()

        # Render global header line
        pct = (self.current_step / self.total_sections) * 100.0
        filled = int(self.bar_width * self.current_step // self.total_sections)
        bar = "█" * filled + "░" * (self.bar_width - filled)

        print(f"\n[Global {self.current_step:02d}/{self.total_sections:02d}] [{bar}] {pct:5.1f}% | {q_id}: {title}")
        sys.stdout.flush()

    def update_sub(self, current, total, detail=""):
        """In-place sub-step progression with carriage return."""
        sub_pct = (current / total * 100.0) if total > 0 else 100.0
        msg = f"  └─ [{sub_pct:5.1f}%] ({current:,}/{total:,}) {detail}"
        padded = msg[:110].ljust(110)
        sys.stdout.write(f"\r{padded}")
        sys.stdout.flush()

    def finish_section(self, summary=""):
        """Concludes the active section and clears any in-place line."""
        elapsed = time.time() - (self.step_start_time or self.start_time)
        self.timings[self.current_qid] = round(elapsed, 2)
        note = f" - {summary}" if summary else ""
        sys.stdout.write(f"\r  └─ ✓ Completed in {elapsed:.2f}s{note}".ljust(110) + "\n")
        sys.stdout.flush()

    def finish_all(self):
        """Prints overall completion summary."""
        total_elapsed = time.time() - self.start_time
        print(f"\n{'='*70}")
        print(f"✓ All {self.total_sections} analytical sections completed in {total_elapsed:.2f}s")
        print(f"{'='*70}\n")
        sys.stdout.flush()
        return round(total_elapsed, 2)

class TopN:
    """Keeps the n items with the largest key while streaming (ties keep the first seen)."""
    def __init__(self, n):
        self.n = n
        self.heap = []
        self.counter = itertools.count()

    def push(self, key, item):
        entry = (key, -next(self.counter), item)
        if len(self.heap) < self.n:
            heapq.heappush(self.heap, entry)
        elif entry > self.heap[0]:
            heapq.heapreplace(self.heap, entry)

    def items(self):
        return [item for _, _, item in sorted(self.heap, reverse=True)]

def parse_ts(ts_str):
    if not ts_str: return None
    clean = ts_str.strip().replace('Z', '+00:00')
    try:
        return datetime.fromisoformat(clean)
    except Exception:
        try:
            if '.' in clean:
                base, rest = clean.split('.', 1)
                if '+' in rest: frac, tz = rest.split('+', 1); tz = '+' + tz
                elif '-' in rest: frac, tz = rest.split('-', 1); tz = '-' + tz
                else: frac, tz = rest, ''
                frac = (frac + '000000')[:6]
                return datetime.fromisoformat(f"{base}.{frac}{tz}")
        except Exception:
            pass
    return None

def pct(part, total, digits=2):
    return round(100.0 * part / total, digits) if total else 0.0

def cadence_tier(command_count, time_gap_mean):
    """Same tiers as the Q12 SQL so sessions-table and clean cadence are comparable."""
    if command_count <= 1:
        return 'Single Command / No Gap'
    if time_gap_mean < 0.5:
        return 'Burst Script (< 0.5s)'
    if time_gap_mean < 2.0:
        return 'Fast Bot Recon (0.5s - 2.0s)'
    if time_gap_mean < 5.0:
        return 'Paced Script (2.0s - 5.0s)'
    return 'Human Interactive Pace (>= 5.0s)'

CADENCE_ORDER = [
    'Burst Script (< 0.5s)', 'Fast Bot Recon (0.5s - 2.0s)', 'Paced Script (2.0s - 5.0s)',
    'Human Interactive Pace (>= 5.0s)', 'Single Command / No Gap',
]

# ------------------------------------------------------------
# Command templates (exact-match vs. template baseline for clustering)
# ------------------------------------------------------------
_URL_RE = re.compile(r'\b(?:https?|ftp|tftp)://\S+', re.I)
_IP_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b')
# Quoted tokens without whitespace (passwords, keys); quoted scripts with spaces stay readable
_QUOTED_RE = re.compile(r'(["\'])[^"\'\s]{6,}\1')
# Long mixed letter+digit tokens (base64 blobs, random names); plain paths have no digits mostly
_B64_RE = re.compile(r'(?<![\w/+])(?=[A-Za-z0-9+/]*\d)(?=[A-Za-z0-9+/]*[A-Za-z])[A-Za-z0-9+/]{20,}={0,2}')
_HEX_RE = re.compile(r'\b[0-9a-fA-F]{8,}\b')
_NUM_RE = re.compile(r'\b\d+\b')
_WS_RE = re.compile(r'\s+')

@lru_cache(maxsize=500_000)
def command_template(cmd):
    """Replaces volatile parts (URLs, IPs, secrets, blobs, numbers) so variants of one bot script match."""
    t = _URL_RE.sub('<URL>', cmd)
    t = _IP_RE.sub('<IP>', t)
    t = _QUOTED_RE.sub('<STR>', t)
    t = _B64_RE.sub('<B64>', t)
    t = _HEX_RE.sub('<HEX>', t)
    t = _NUM_RE.sub('<N>', t)
    return _WS_RE.sub(' ', t).strip()

# ------------------------------------------------------------
# Rule-based intent tags (baseline to compare ML clusters against, not ground truth)
# ------------------------------------------------------------
_SPLIT_RE = re.compile(r'\s*(?:;|&&|\|\||\||\n)\s*')
_BUSYBOX_PROBE_RE = re.compile(r'busybox\s+[A-Z]{4,}\b')
_CMD_PREFIXES = {'sudo', 'nohup', 'exec', 'command', 'time'}

RECON_CMDS = {
    'uname', 'whoami', 'id', 'nproc', 'lscpu', 'free', 'uptime', 'hostname', 'ifconfig', 'lspci',
    'df', 'w', 'who', 'last', 'ps', 'top', 'getconf', 'dmidecode', 'arch', 'lsb_release', 'netstat',
}
DOWNLOAD_CMDS = {'wget', 'curl', 'tftp', 'ftpget', 'scp', 'sftp', 'lwp-download', 'fetch'}
PERSISTENCE_CMDS = {'passwd', 'chpasswd', 'useradd', 'adduser', 'crontab'}

INTENT_SUBSTRINGS = {
    'recon': ('/proc/cpuinfo', '/proc/meminfo', '/proc/version', '/etc/os-release', '/etc/issue'),
    'download': ('/dev/tcp/', 'busybox wget', 'busybox tftp'),
    'execute': ('chmod +x', 'chmod 777', 'chmod 755', '| sh', '|sh', '| bash', '|bash', 'sh -c', 'bash -c'),
    'persistence': ('authorized_keys', 'crontab', '/etc/rc.local', 'systemctl enable', '/etc/init.d/',
                    '.bashrc', 'chpasswd', 'useradd', 'adduser'),
    'cleanup_evasion': ('history -c', 'unset histfile', 'chattr', 'iptables', 'pkill', 'killall',
                        'kill -9', 'ufw disable', '/var/log', 'rm -rf'),
    'cryptomining': ('xmrig', 'minerd', 'cpuminer', 'stratum+tcp', 'monero', 'c3pool', 'nicehash',
                     'kdevtmpfsi', 'kinsing', 'xmr'),
}

INTENT_ORDER = ['recon', 'download', 'execute', 'persistence', 'cleanup_evasion',
                'cryptomining', 'iot_botnet_probe']

@lru_cache(maxsize=500_000)
def command_intents(cmd):
    low = cmd.lower()
    tags = set()
    for part in _SPLIT_RE.split(low):
        tokens = part.split()
        while tokens and tokens[0] in _CMD_PREFIXES:
            tokens = tokens[1:]
        if not tokens:
            continue
        first = tokens[0].rsplit('/', 1)[-1]
        if first in RECON_CMDS:
            tags.add('recon')
        if first in DOWNLOAD_CMDS:
            tags.add('download')
        if first in PERSISTENCE_CMDS:
            tags.add('persistence')
        if tokens[0].startswith('./') or (first in ('sh', 'bash') and len(tokens) > 1 and not tokens[1].startswith('-')):
            tags.add('execute')
    for intent, needles in INTENT_SUBSTRINGS.items():
        if any(n in low for n in needles):
            tags.add(intent)
    # Mirai-style check whether a real busybox exists ("/bin/busybox ECCHI")
    if _BUSYBOX_PROBE_RE.search(cmd):
        tags.add('iot_botnet_probe')
    return frozenset(tags)

# ------------------------------------------------------------
# Human signal heuristics (Q11)
# ------------------------------------------------------------
BOT_SIGNATURES = ['mdrfckr', 'lockr', 'echo "root:', '/ip cloud print', 'chattr', '/bin/skhqwensw']
COMMON_CMDS = {'ls', 'cd', 'cat', 'pwd', 'whoami', 'uname', 'grep', 'sudo', 'touch', 'mkdir', 'tail', 'head',
               'nano', 'vi', 'vim', 'chmod', 'cp', 'mv', 'rm', 'find', 'ps', 'top', 'id', 'exit'}

def _lev(s1, s2):
    if abs(len(s1) - len(s2)) > 2: return 99
    dp = [[0]*(len(s2)+1) for _ in range(len(s1)+1)]
    for i in range(len(s1)+1): dp[i][0] = i
    for j in range(len(s2)+1): dp[0][j] = j
    for i in range(1, len(s1)+1):
        for j in range(1, len(s2)+1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
    return dp[len(s1)][len(s2)]

def _stumble(c1, c2, delta_sec):
    """Returns a description if c1 -> c2 looks like a human correcting a mistake, else None."""
    d = f"({round(delta_sec, 1)}s)"
    if (c1 == 'sl' or c1.startswith('sl ')) and (c2 == 'ls' or c2.startswith('ls ')):
        return f"'{c1}' -> '{c2}' {d}"
    if c1.startswith('cd/') and c2.startswith('cd /'):
        return f"'{c1}' -> '{c2}' {d}"
    if c1 == 'cd ..' and (c2 == 'ls' or c2.startswith('ls ')):
        return f"'cd ..' followed by '{c2}' {d}"
    for typo, fix in (('sudp', 'sudo'), ('whomi', 'whoami'), ('gerp', 'grep')):
        if c1.startswith(typo) and c2.startswith(fix):
            return f"'{c1}' -> '{c2}' {d}"
    if 'cd /ect' in c1 and 'cd /etc' in c2:
        return f"'{c1}' -> '{c2}' {d}"
    if len(c1) > 1 and len(c2) > 1 and c1 != c2:
        cmd1_base = c1.split()[0]
        cmd2_base = c2.split()[0]
        if cmd2_base in COMMON_CMDS and cmd1_base not in COMMON_CMDS and _lev(cmd1_base, cmd2_base) <= 2:
            return f"'{c1}' -> '{c2}' {d}"
    return None

def detect_human_signals(cmds, timed_events):
    """
    Multi-signal human filter: typos, interactive editors, and quick corrections (0.4s - 8s).
    Works on command lists, so commands that contain '|' are no longer split apart.
    Returns None for sessions that should not be flagged.
    """
    seq = '\n'.join(cmds)
    if any(sig in seq for sig in BOT_SIGNATURES):
        return None
    if max((len(c) for c in cmds), default=0) > 100:
        return None

    has_editor = any(c.startswith(('nano ', 'vi ', 'vim ')) or c.strip() in ('nano', 'vi', 'vim') for c in cmds)
    has_typo = (
        'sudp' in seq or 'cd /ect' in seq or 'whomi' in seq or 'gerp' in seq or
        any(c.strip() == 'sl' or c.strip().startswith('sl ') for c in cmds)
    )

    stumbles = []
    deltas = []
    for (t1, c1), (t2, c2) in zip(timed_events, timed_events[1:]):
        if not t1 or not t2:
            continue
        delta_sec = (t2 - t1).total_seconds()
        deltas.append(delta_sec)
        if 0.4 <= delta_sec <= 8.0:
            desc = _stumble(c1, c2, delta_sec)
            if desc:
                stumbles.append(desc)

    if not (has_typo or has_editor or stumbles):
        return None

    reason = []
    if has_typo:
        reason.append("Human Typos Detected")
    if has_editor:
        reason.append("Interactive Editor Usage")
    if stumbles:
        reason.append("Natural Stumbles & Quick Retries (" + ", ".join(stumbles[:2]) + ")")
    return {
        'flag_reason': " + ".join(reason),
        'confidence_score': int(has_typo) + int(has_editor) + int(bool(stumbles)),
        'avg_delta_sec': round(sum(deltas) / len(deltas), 2) if deltas else None,
    }

# ------------------------------------------------------------
# Streaming Cowrie session analysis (one pass over Cowrie command events)
# ------------------------------------------------------------
class CowrieSessionStats:
    def __init__(self):
        self.sessions_with_cmds = 0
        self.sessions_2plus = 0
        self.command_events = 0
        self.input_events = 0
        self.truncated_raw = 0
        self.exact_seqs = set()
        self.exact_seqs_2plus = set()
        self.templates = {}
        self.templates_2plus = set()
        self.timeline = []
        self.monthly = defaultdict(lambda: {'sessions_with_cmds': 0, 'sessions_2plus': 0})
        self.intent_counts = Counter()
        self.profile_counts = Counter()
        self.clean_cadence = defaultdict(lambda: [0, 0, 0.0])
        self.ips = {}
        self.interactive = TopN(15)
        self.human = []
        self.human_candidates = 0

    def add(self, row):
        events = []
        for item in (row['timed'] or '').split('\x1e'):
            ts, sep, payload = item.partition('\x1f')
            if sep:
                events.append((ts, payload))
        if not events:
            return
        events.sort(key=lambda e: e[0])
        cmds = [p for _, p in events]
        n = len(cmds)
        start, end = events[0][0], events[-1][0]
        sid, ip = row['session_id'] or '', row['src_ip']

        self.sessions_with_cmds += 1
        self.command_events += n
        self.input_events += row['input_events'] or 0
        self.truncated_raw += row['truncated_raw'] or 0

        exact_key = hash(tuple(cmds))
        template_text = ' ; '.join(command_template(c) for c in cmds)
        template_key = hashlib.blake2b(template_text.encode('utf-8', 'ignore'), digest_size=12).digest()
        self.exact_seqs.add(exact_key)
        if n >= 2:
            self.sessions_2plus += 1
            self.exact_seqs_2plus.add(exact_key)
            self.templates_2plus.add(template_key)

        tags = frozenset().union(*(command_intents(c) for c in set(cmds)))
        profile = '+'.join(t for t in INTENT_ORDER if t in tags) or 'unclassified'
        for t in tags:
            self.intent_counts[t] += 1
        self.profile_counts[profile] += 1

        day = start[:10]
        tpl = self.templates.get(template_key)
        if tpl is None:
            tpl = self.templates[template_key] = {
                'template': template_text[:400], 'example': ' ; '.join(cmds)[:400],
                'commands': n, 'profile': profile, 'sessions': 0, 'ips': set(),
                'variants': set(), 'days': set(), 'first_seen': start, 'last_seen': end,
            }
        tpl['sessions'] += 1
        tpl['ips'].add(ip)
        tpl['variants'].add(exact_key)
        tpl['days'].add(day)
        tpl['first_seen'] = min(tpl['first_seen'], start)
        tpl['last_seen'] = max(tpl['last_seen'], end)

        ip_stats = self.ips.get(ip)
        if ip_stats is None:
            ip_stats = self.ips[ip] = {'country': row['src_country'], 'sessions': 0, 'days': set(),
                                       'templates': set(), 'first_seen': start, 'last_seen': end}
        ip_stats['sessions'] += 1
        ip_stats['days'].add(day)
        ip_stats['templates'].add(template_key)
        ip_stats['first_seen'] = min(ip_stats['first_seen'], start)
        ip_stats['last_seen'] = max(ip_stats['last_seen'], end)

        self.timeline.append((start, template_key))
        month = self.monthly[start[:7]]
        month['sessions_with_cmds'] += 1
        if n >= 2:
            month['sessions_2plus'] += 1

        # Cadence from real typed commands only (sessions table also counts cowrie.client.* events)
        t_first, t_last = parse_ts(start), parse_ts(end)
        duration = max(0.0, (t_last - t_first).total_seconds()) if (t_first and t_last) else 0.0
        gap = duration / (n - 1) if n >= 2 else 0.0
        tier = self.clean_cadence[cadence_tier(n, gap)]
        tier[0] += 1
        tier[1] += n
        tier[2] += duration

        unique_cmds = len(set(cmds))
        if unique_cmds > 5:
            self.interactive.push(unique_cmds, {
                'session_id': sid, 'src_ip': ip, 'src_country': row['src_country'],
                'total_cmds': n, 'unique_cmds': unique_cmds,
                'session_start': start, 'session_end': end,
                '_commands': [{'timestamp': ts, 'payload': p} for ts, p in events[:30]],
            })

        if unique_cmds > 3:
            self.human_candidates += 1
            timed = [(parse_ts(ts), p.strip()) for ts, p in events]
            signals = detect_human_signals(cmds, timed)
            if signals:
                self.human.append({
                    'session_id': sid, 'src_ip': ip, 'src_country': row['src_country'],
                    'sensor_type': 'cowrie', 'unique_cmds': unique_cmds, 'total_cmds': n,
                    'duration_sec': round(duration, 2), **signals,
                    'commands': cmds, 'cmd_sequence': ' | '.join(cmds),
                })

    def results(self):
        res = {}
        n_with = self.sessions_with_cmds

        interactive = self.interactive.items()
        res['q7_top_session_commands'] = interactive[0]['_commands'] if interactive else []
        for item in interactive:
            item.pop('_commands', None)
        res['q7_interactive_sessions'] = interactive

        self.human.sort(key=lambda x: x['duration_sec'] or 0, reverse=True)
        res['q11_human_manual_sessions'] = self.human

        res['q13_ml_dataset'] = {
            'unit': 'Cowrie session (session_id + src_ip) with typed commands (payload not empty)',
            'sessions_with_commands': n_with,
            'sessions_2plus_commands': self.sessions_2plus,
            'sessions_single_command': n_with - self.sessions_2plus,
            'command_events': self.command_events,
            'command_input_events': self.input_events,
            'command_input_pct': pct(self.input_events, self.command_events),
            'raw_data_truncated_events': self.truncated_raw,
            'raw_data_truncated_pct': pct(self.truncated_raw, self.command_events),
            'human_candidate_sessions': self.human_candidates,
            'human_flagged_sessions': len(self.human),
        }

        def top10_share(counter_values, total):
            return pct(sum(sorted(counter_values, reverse=True)[:10]), total)

        template_sessions = [t['sessions'] for t in self.templates.values()]
        res['q13_sequence_diversity'] = {
            'scope': 'sessions with >= 1 typed command',
            'sessions': n_with,
            'distinct_exact_sequences': len(self.exact_seqs),
            'distinct_templates': len(self.templates),
            'exact_duplicate_pct': pct(n_with - len(self.exact_seqs), n_with),
            'template_duplicate_pct': pct(n_with - len(self.templates), n_with),
            'top10_template_share_pct': top10_share(template_sessions, n_with),
            'singleton_templates': sum(1 for s in template_sessions if s == 1),
            'sessions_2plus': self.sessions_2plus,
            'distinct_exact_sequences_2plus': len(self.exact_seqs_2plus),
            'distinct_templates_2plus': len(self.templates_2plus),
        }

        top_templates = sorted(self.templates.values(), key=lambda t: t['sessions'], reverse=True)[:15]
        res['q13_top_templates'] = [{
            'template': t['template'], 'example': t['example'], 'commands': t['commands'],
            'intent_profile': t['profile'], 'sessions': t['sessions'],
            'session_pct': pct(t['sessions'], n_with), 'unique_ips': len(t['ips']),
            'exact_variants': len(t['variants']), 'active_days': len(t['days']),
            'first_seen': t['first_seen'], 'last_seen': t['last_seen'],
        } for t in top_templates]

        res['q14_intent_tags'] = [{
            'intent': i, 'sessions': self.intent_counts.get(i, 0),
            'pct': pct(self.intent_counts.get(i, 0), n_with),
        } for i in INTENT_ORDER]
        res['q14_intent_profiles'] = [{
            'profile': p, 'sessions': c, 'pct': pct(c, n_with),
        } for p, c in self.profile_counts.most_common(12)]

        res['q14_clean_cadence'] = [{
            'cadence_tier': tier, 'session_count': self.clean_cadence[tier][0],
            'pct_sessions': pct(self.clean_cadence[tier][0], n_with),
            'avg_commands': round(self.clean_cadence[tier][1] / self.clean_cadence[tier][0], 2),
            'avg_duration_sec': round(self.clean_cadence[tier][2] / self.clean_cadence[tier][0], 2),
        } for tier in CADENCE_ORDER if self.clean_cadence[tier][0]]

        # Temporal novelty: how much behavior per month was never seen before?
        self.timeline.sort(key=lambda e: e[0])
        first_month = {}
        month_templates = defaultdict(set)
        month_new_templates = Counter()
        month_new_sessions = Counter()
        for start, tkey in self.timeline:
            m = start[:7]
            month_templates[m].add(tkey)
            if tkey not in first_month:
                first_month[tkey] = m
                month_new_templates[m] += 1
            # A session counts as novel when its template first appeared in this month
            if first_month[tkey] == m:
                month_new_sessions[m] += 1
        monthly = []
        cumulative = 0
        for m in sorted(self.monthly):
            stats = self.monthly[m]
            cumulative += stats['sessions_with_cmds']
            monthly.append({
                'month': m, 'sessions_with_cmds': stats['sessions_with_cmds'],
                'sessions_2plus': stats['sessions_2plus'],
                'distinct_templates': len(month_templates[m]),
                'new_templates': month_new_templates[m],
                'novel_session_pct': pct(month_new_sessions[m], stats['sessions_with_cmds']),
                'cumulative_session_pct': pct(cumulative, n_with),
            })
        res['q15_monthly_novelty'] = monthly

        # Time-based split (no random shuffling): first TRAIN_SHARE of sessions vs. the rest
        split = {}
        if len(self.timeline) >= 10:
            cut = int(len(self.timeline) * TRAIN_SHARE)
            train, test = self.timeline[:cut], self.timeline[cut:]
            train_templates = {t for _, t in train}
            unseen = [t for _, t in test if t not in train_templates]
            split = {
                'train_share': TRAIN_SHARE,
                'train_sessions': len(train), 'test_sessions': len(test),
                'train_period': [train[0][0], train[-1][0]],
                'test_period': [test[0][0], test[-1][0]],
                'cutoff_timestamp': test[0][0],
                'test_sessions_unseen_template': len(unseen),
                'test_unseen_template_pct': pct(len(unseen), len(test)),
                'test_distinct_unseen_templates': len(set(unseen)),
            }
        res['q15_time_split'] = split

        # Attacker recurrence: do the same IPs come back, and with how many different scripts?
        day_buckets = Counter()
        template_buckets = Counter()
        for s in self.ips.values():
            d = len(s['days'])
            day_buckets['1 day' if d == 1 else '2-7 days' if d <= 7 else '8-30 days' if d <= 30 else '> 30 days'] += 1
            k = len(s['templates'])
            template_buckets['1 template' if k == 1 else '2-3 templates' if k <= 3 else '4+ templates'] += 1
        n_ips = len(self.ips)
        res['q16_ip_recurrence'] = {
            'ips_with_command_sessions': n_ips,
            'active_days_distribution': [{'bucket': b, 'ips': day_buckets[b], 'pct': pct(day_buckets[b], n_ips)}
                                         for b in ('1 day', '2-7 days', '8-30 days', '> 30 days')],
            'templates_per_ip_distribution': [{'bucket': b, 'ips': template_buckets[b], 'pct': pct(template_buckets[b], n_ips)}
                                              for b in ('1 template', '2-3 templates', '4+ templates')],
        }
        top_recurring = sorted(self.ips.items(), key=lambda kv: (len(kv[1]['days']), kv[1]['sessions']), reverse=True)[:10]
        res['q16_top_recurring_ips'] = [{
            'src_ip': ip, 'src_country': s['country'], 'active_days': len(s['days']),
            'sessions': s['sessions'], 'distinct_templates': len(s['templates']),
            'first_seen': s['first_seen'], 'last_seen': s['last_seen'],
        } for ip, s in top_recurring]
        return res

def run(db_path=DB_PATH, out_path=OUT_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Accelerate read performance and in-memory sorting on large SQLite database
    conn.execute("PRAGMA cache_size = -2000000;")     # ~2GB RAM cache
    conn.execute("PRAGMA mmap_size = 30000000000;")   # Memory-mapped I/O (~30GB)
    conn.execute("PRAGMA temp_store = MEMORY;")       # Keep temporary sorting/grouping in RAM
    conn.execute("PRAGMA threads = 4;")               # Parallel sorter threads (ignored if unsupported)
    conn.execute("PRAGMA query_only = ON;")           # Bypass write-lock overhead for read analysis
    c = conn.cursor()
    results = {}

    progress = AnalyzerProgress(total_sections=9, bar_width=20)

    # ============================================================
    # Q1-Q3 + VALIDATION: one scan grouped by sensor, instance and category
    # ============================================================
    progress.start_section("Q1-Q3", "Event inventory, noise ratios and integrity checks")
    progress.update_sub(1, 1, "Scanning events grouped by sensor / instance / category...")
    c.execute("""
        SELECT sensor_type, sensor_instance, event_category, COUNT(*) AS cnt,
               MIN(timestamp) AS earliest, MAX(timestamp) AS latest,
               SUM(CASE WHEN src_ip IS NULL OR src_ip = '' THEN 1 ELSE 0 END) AS null_src_ip,
               SUM(CASE WHEN timestamp IS NULL OR timestamp = '' THEN 1 ELSE 0 END) AS null_timestamp
        FROM events
        GROUP BY sensor_type, sensor_instance, event_category
    """)
    base_rows = [dict(r) for r in c.fetchall()]

    per_type = Counter()
    per_instance = Counter()
    per_type_cat = Counter()
    dates = {}
    nulls = Counter()
    for r in base_rows:
        stype, cat, cnt = r['sensor_type'], r['event_category'], r['cnt']
        per_type[stype] += cnt
        per_instance[(r['sensor_instance'], stype)] += cnt
        per_type_cat[(stype, cat)] += cnt
        nulls['null_src_ip'] += r['null_src_ip'] or 0
        nulls['null_timestamp'] += r['null_timestamp'] or 0
        if not stype:
            nulls['null_sensor_type'] += cnt
        if not cat:
            nulls['null_category'] += cnt
        d = dates.setdefault(stype, {'sensor_type': stype, 'earliest': None, 'latest': None})
        if r['earliest'] is not None and (d['earliest'] is None or r['earliest'] < d['earliest']):
            d['earliest'] = r['earliest']
        if r['latest'] is not None and (d['latest'] is None or r['latest'] > d['latest']):
            d['latest'] = r['latest']

    by_cnt = lambda x: -x[1]
    results['q1_total_per_type'] = [{'sensor_type': t, 'cnt': n} for t, n in sorted(per_type.items(), key=by_cnt)]
    results['q1_per_instance'] = [{'sensor_instance': i, 'sensor_type': t, 'cnt': n}
                                  for (i, t), n in sorted(per_instance.items(), key=by_cnt)]
    results['q1_date_ranges'] = [dates[t] for t in sorted(dates, key=lambda x: x or '')]
    results['q1_category_breakdown'] = [{'sensor_type': t, 'event_category': cat, 'cnt': n}
                                        for (t, cat), n in sorted(per_type_cat.items(), key=lambda x: (x[0][0] or '', -x[1]))]

    useful = []
    noise = []
    for stype, total in per_type.items():
        u = sum(per_type_cat[(stype, cat)] for cat in USEFUL_CATEGORIES)
        ne = per_type_cat[(stype, 'connection_established')]
        useful.append({'sensor_type': stype, 'total': total, 'useful': u, 'useful_pct': pct(u, total)})
        noise.append({'sensor_type': stype, 'noise_events': ne, 'total': total, 'noise_pct': pct(ne, total)})
    results['q2_useful_data'] = sorted(useful, key=lambda x: -x['useful'])
    results['q3_noise'] = sorted(noise, key=lambda x: -x['noise_pct'])
    results['q3_other_category'] = [{'sensor_type': t, 'event_category': 'other', 'cnt': n}
                                    for (t, cat), n in per_type_cat.items() if cat == 'other']

    results['validation_total_records'] = sum(per_type.values())
    results['validation_nulls'] = {k: nulls[k] for k in ('null_src_ip', 'null_timestamp', 'null_sensor_type', 'null_category')}
    sort_nulls_first = lambda x: (x is not None, x or '')
    results['validation_categories'] = sorted({cat for _, cat in per_type_cat}, key=sort_nulls_first)
    results['validation_sensor_types'] = sorted(set(per_type), key=sort_nulls_first)
    progress.finish_section(f"{len(base_rows)} groups aggregated in a single scan")

    # ============================================================
    # Q5, Q6, Q9, Q10, Q11: one scan into a per (IP, sensor) temp table
    # ============================================================
    progress.start_section("IP", "IP / sensor profiles, countries, cross-sensor and mdrfckr")
    progress.update_sub(1, 3, "Building per IP+sensor aggregate (single scan)...")
    # query_only also blocks TEMP tables; the main database is never written
    conn.execute("PRAGMA query_only = OFF;")
    c.execute("""
        CREATE TEMP TABLE ip_sensor AS
        SELECT src_ip, sensor_type,
               MAX(src_country) AS src_country,
               COUNT(*) AS cnt,
               SUM(CASE WHEN src_country IS NOT NULL THEN 1 ELSE 0 END) AS geo_events,
               MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen,
               GROUP_CONCAT(DISTINCT event_category) AS categories,
               SUM(CASE WHEN payload IS NOT NULL AND payload != '' THEN 1 ELSE 0 END) AS payload_events,
               COUNT(DISTINCT NULLIF(payload, '')) AS unique_payloads,
               MIN(CASE WHEN payload != '' THEN timestamp END) AS payload_first,
               MAX(CASE WHEN payload != '' THEN timestamp END) AS payload_last,
               SUM(CASE WHEN payload LIKE '%mdrfckr%' THEN 1 ELSE 0 END) AS mdr_hits,
               MIN(CASE WHEN payload LIKE '%mdrfckr%' THEN timestamp END) AS mdr_first,
               MAX(CASE WHEN payload LIKE '%mdrfckr%' THEN timestamp END) AS mdr_last
        FROM events
        GROUP BY src_ip, sensor_type
    """)
    c.execute("CREATE INDEX temp.idx_ip_sensor_ip ON ip_sensor(src_ip)")
    conn.execute("PRAGMA query_only = ON;")

    progress.update_sub(2, 3, "Deriving per-sensor, per-IP and country views...")
    c.execute("SELECT sensor_type, COUNT(*) AS unique_ips FROM ip_sensor GROUP BY sensor_type ORDER BY unique_ips DESC")
    results['q1_unique_ips_per_sensor'] = [dict(r) for r in c.fetchall()]

    c.execute("""
        SELECT src_country, SUM(geo_events) AS total_attacks
        FROM ip_sensor
        WHERE src_country IS NOT NULL
        GROUP BY src_country
        ORDER BY total_attacks DESC
    """)
    country_rows = [dict(r) for r in c.fetchall()]
    total_country_count = sum(r['total_attacks'] for r in country_rows) or 1
    for cr in country_rows:
        cr['pct'] = pct(cr['total_attacks'], total_country_count)
    results['q11_country_distribution'] = country_rows[:15]

    # (ip, sensor) rows are unique, so COUNT(*) per IP is the number of sensors hit
    ip_profile_sql = """
        SELECT src_ip, MAX(src_country) AS src_country, COUNT(*) AS sensor_count,
               GROUP_CONCAT(sensor_type) AS sensors, SUM(cnt) AS total_events,
               GROUP_CONCAT(categories) AS categories,
               MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
        FROM ip_sensor
        GROUP BY src_ip
    """
    c.execute(f"SELECT sensor_count, COUNT(*) AS ip_count FROM ({ip_profile_sql}) GROUP BY sensor_count ORDER BY sensor_count DESC")
    results['q5_ip_sensor_distribution'] = [dict(r) for r in c.fetchall()]

    c.execute(f"""
        SELECT src_ip, src_country, sensor_count, sensors, total_events, first_seen, last_seen
        FROM ({ip_profile_sql})
        WHERE sensor_count > 1
        ORDER BY sensor_count DESC, total_events DESC
        LIMIT 30
    """)
    results['q5_top_multi_sensor_ips'] = [dict(r) for r in c.fetchall()]

    c.execute(f"""
        SELECT src_ip, sensor_count AS sensors_hit, sensors AS sensor_list, categories,
               total_events, first_seen, last_seen
        FROM ({ip_profile_sql})
        WHERE sensor_count >= 3
        ORDER BY sensor_count DESC, total_events DESC
        LIMIT 20
    """)
    multi_vector = []
    for r in c.fetchall():
        d = dict(r)
        # Per-sensor category lists are concatenated; keep each category once
        d['categories'] = ','.join(dict.fromkeys((d['categories'] or '').split(',')))
        multi_vector.append(d)
    results['q9_multi_vector_attackers'] = multi_vector

    c.execute("""
        SELECT src_ip, src_country, sensor_type, payload_events AS total_events,
               unique_payloads, payload_first AS first_seen, payload_last AS last_seen
        FROM ip_sensor
        WHERE payload_events > 1000
        ORDER BY total_events DESC
        LIMIT 15
    """)
    results['q6_high_volume_ips'] = [dict(r) for r in c.fetchall()]

    c.execute("""
        SELECT src_ip, sensor_type, payload_events AS total, unique_payloads,
               ROUND(1.0 * payload_events / MAX(unique_payloads, 1), 1) AS repetition_ratio
        FROM ip_sensor
        WHERE payload_events > 500 AND 1.0 * payload_events / MAX(unique_payloads, 1) > 100
        ORDER BY repetition_ratio DESC
        LIMIT 10
    """)
    results['q6_high_repetition_ratio'] = [dict(r) for r in c.fetchall()]

    progress.update_sub(3, 3, "Summarising mdrfckr campaign per IP...")
    c.execute("""
        SELECT SUM(mdr_hits) AS hits, COUNT(DISTINCT src_ip) AS unique_ips,
               MIN(mdr_first) AS first_seen, MAX(mdr_last) AS last_seen
        FROM ip_sensor WHERE mdr_hits > 0
    """)
    mdr = dict(c.fetchone())
    mdr['hits'] = mdr['hits'] or 0
    results['q10_mdrfckr_stats'] = mdr
    c.execute("""
        SELECT src_ip, SUM(mdr_hits) AS hits, MIN(mdr_first) AS first, MAX(mdr_last) AS last
        FROM ip_sensor WHERE mdr_hits > 0
        GROUP BY src_ip
        ORDER BY hits DESC
        LIMIT 5
    """)
    results['q10_mdrfckr_top_ips'] = [dict(r) for r in c.fetchall()]
    progress.finish_section("IP-level views derived from one aggregate")

    # ============================================================
    # Q5 / Q9 detail lookups (indexed by src_ip, cheap)
    # ============================================================
    progress.start_section("Q5/Q9", "Cross-sensor attacker breakdowns and timelines")
    progress.update_sub(1, 2, "Analyzing top 5 cross-sensor attacker breakdowns...")
    top4_ips = [
        item['src_ip'] for item in results['q5_top_multi_sensor_ips']
        if item.get('sensor_count') == 4
    ][:5]
    if not top4_ips and results['q5_top_multi_sensor_ips']:
        top4_ips = [item['src_ip'] for item in results['q5_top_multi_sensor_ips'][:5]]

    if top4_ips:
        placeholders = ','.join('?' * len(top4_ips))
        c.execute(f"""
            SELECT src_ip, sensor_type, event_category, COUNT(*) as cnt
            FROM events
            WHERE src_ip IN ({placeholders})
            GROUP BY src_ip, sensor_type, event_category
            ORDER BY src_ip, sensor_type
        """, top4_ips)
        results['q5_top5_detail'] = [dict(r) for r in c.fetchall()]
    else:
        results['q5_top5_detail'] = []

    progress.update_sub(2, 2, "Building multi-vector attacker timeline...")
    if results['q9_multi_vector_attackers']:
        top_ip = results['q9_multi_vector_attackers'][0]['src_ip']
        c.execute("""
            SELECT sensor_type, event_category, COUNT(*) as cnt,
                   MIN(timestamp) as first_event, MAX(timestamp) as last_event
            FROM events
            WHERE src_ip = ?
            GROUP BY sensor_type, event_category
            ORDER BY first_event
        """, (top_ip,))
        results['q9_top_ip_timeline'] = [dict(r) for r in c.fetchall()]
    else:
        results['q9_top_ip_timeline'] = []
    progress.finish_section("Detail lookups complete")

    # ============================================================
    # Q8 + Q10 (credentials): one streamed GROUP BY payload
    # ============================================================
    progress.start_section("Q8", "Payload recurrence, credentials and Mirai defaults")
    c.execute("""
        SELECT payload, COUNT(*) AS total_hits, COUNT(DISTINCT src_ip) AS unique_ips,
               COUNT(DISTINCT sensor_type) AS sensor_count, GROUP_CONCAT(DISTINCT sensor_type) AS sensors,
               MAX(event_category) AS event_category,
               SUM(CASE WHEN event_category = 'authentication_attempt' THEN 1 ELSE 0 END) AS auth_hits,
               MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
        FROM events
        WHERE payload IS NOT NULL AND payload != ''
        GROUP BY payload
    """)
    top_payloads = TopN(20)
    cross_sensor = TopN(15)
    top_creds = TopN(15)
    mdr_examples = TopN(3)
    mirai = []
    distinct_payloads = 0
    for r in c:
        distinct_payloads += 1
        if distinct_payloads % 200000 == 0:
            progress.update_sub(distinct_payloads, distinct_payloads, "Streaming distinct payloads...")
        total = r['total_hits']
        if total > 50:
            top_payloads.push(total, dict(r))
        if r['sensor_count'] > 1:
            cross_sensor.push(total, {'payload': r['payload'], 'sensor_count': r['sensor_count'],
                                      'sensors': r['sensors'], 'total': total, 'ips': r['unique_ips']})
        # ips/sensors are counted over all events with this payload; for "user:pass" strings these
        # are practically always authentication attempts
        if r['auth_hits'] and ':' in r['payload']:
            top_creds.push(r['auth_hits'], {'payload': r['payload'], 'cnt': r['auth_hits'],
                                            'ips': r['unique_ips'], 'sensors': r['sensors']})
            if r['payload'] in MIRAI_CREDENTIALS:
                mirai.append({'payload': r['payload'], 'cnt': r['auth_hits'], 'ips': r['unique_ips']})
        if 'mdrfckr' in r['payload']:
            mdr_examples.push(total, {'payload': r['payload'][:500], 'hits': total, 'ips': r['unique_ips']})

    results['q8_top_payloads'] = [
        {k: p[k] for k in ('payload', 'event_category', 'total_hits', 'unique_ips', 'sensor_count',
                           'sensors', 'first_seen', 'last_seen')}
        for p in top_payloads.items()
    ]
    results['q8_top_credentials'] = top_creds.items()
    results['q8_cross_sensor_payloads'] = cross_sensor.items()
    results['q8_distinct_payloads'] = distinct_payloads
    results['q10_mirai_credentials'] = sorted(mirai, key=lambda x: -x['cnt'])
    results['q10_mdrfckr_examples'] = mdr_examples.items()
    progress.finish_section(f"{distinct_payloads:,} distinct payloads streamed")

    # ============================================================
    # Q6: high-frequency repeated payloads per IP
    # ============================================================
    progress.start_section("Q6", "Automation profiling (repeated payloads per IP)")
    progress.update_sub(1, 2, "Scanning Heralding interactive credential sessions...")
    c.execute("""
        SELECT session_id, src_ip,
               COUNT(*) as auth_attempts,
               COUNT(DISTINCT payload) as unique_creds,
               MIN(timestamp) as first_attempt,
               MAX(timestamp) as last_attempt
        FROM events
        WHERE sensor_type = 'heralding' AND event_category = 'authentication_attempt'
        GROUP BY session_id
        HAVING auth_attempts > 5
        ORDER BY unique_creds DESC
        LIMIT 10
    """)
    results['q7_heralding_interactive'] = [dict(r) for r in c.fetchall()]

    progress.update_sub(2, 2, "Scanning high-frequency repeated payloads...")
    c.execute("""
        SELECT src_ip, sensor_type, payload, COUNT(*) as freq,
               MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
        FROM events
        WHERE payload != '' AND payload IS NOT NULL
        GROUP BY src_ip, sensor_type, payload
        HAVING freq > 100
        ORDER BY freq DESC
        LIMIT 15
    """)
    results['q6_automated_by_frequency'] = [dict(r) for r in c.fetchall()]
    progress.finish_section("Automation profiles generated")

    # ============================================================
    # Q2, Q7, Q11, Q13-Q16: one streamed pass over Cowrie command sessions
    # ============================================================
    progress.start_section("COWRIE", "Cowrie sessions: interactive, human, ML readiness")
    progress.update_sub(1, 3, "Extracting top Cowrie command payloads...")
    c.execute("""
        SELECT payload, COUNT(*) as cnt, COUNT(DISTINCT src_ip) as ips
        FROM events
        WHERE sensor_type = 'cowrie' AND event_category = 'command_execution' AND payload != ''
        GROUP BY payload
        ORDER BY cnt DESC
        LIMIT 10
    """)
    results['q2_cowrie_top_commands'] = [dict(r) for r in c.fetchall()]

    progress.update_sub(2, 3, "Grouping Cowrie commands per session...")
    # char(30)/char(31) as separators: shell commands often contain ' | ' themselves
    c.execute("""
        SELECT session_id, src_ip, MAX(src_country) AS src_country,
               SUM(CASE WHEN instr(raw_data, 'cowrie.command.input') > 0 THEN 1 ELSE 0 END) AS input_events,
               SUM(CASE WHEN length(raw_data) >= 1000 THEN 1 ELSE 0 END) AS truncated_raw,
               GROUP_CONCAT(timestamp || char(31) || payload, char(30)) AS timed
        FROM events
        WHERE sensor_type = 'cowrie' AND event_category = 'command_execution' AND payload != ''
        GROUP BY session_id, src_ip
    """)
    stats = CowrieSessionStats()
    for idx, r in enumerate(c, start=1):
        stats.add(r)
        if idx % 5000 == 0:
            progress.update_sub(idx, idx, f"Sessions analysed | human flagged: {len(stats.human)}")
    results.update(stats.results())

    progress.update_sub(3, 3, "Comparing with sessions table...")
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
    has_sessions = c.fetchone() is not None
    if has_sessions:
        c.execute("""
            SELECT COUNT(*) AS total, SUM(CASE WHEN command_count > 0 THEN 1 ELSE 0 END) AS with_cmds,
                   SUM(CASE WHEN command_count >= 2 THEN 1 ELSE 0 END) AS two_plus
            FROM sessions WHERE sensor_type = 'cowrie'
        """)
        st = dict(c.fetchone())
        ds = results['q13_ml_dataset']
        ds['cowrie_sessions_total'] = st['total'] or 0
        ds['sessions_excluded_no_commands'] = max(0, (st['total'] or 0) - ds['sessions_with_commands'])
        # Before session metrics v2 the normalizer also counted cowrie.client.* events (version, kex, size)
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pipeline_meta'")
        if c.fetchone():
            c.execute("SELECT value FROM pipeline_meta WHERE key = 'session_metrics_version'")
            row = c.fetchone()
            ds['session_metrics_version'] = int(row[0]) if row else 1
        else:
            ds['session_metrics_version'] = 1
        ds['sessions_table_with_commands'] = st['with_cmds'] or 0
        ds['sessions_table_2plus'] = st['two_plus'] or 0
    progress.finish_section(f"{stats.sessions_with_cmds:,} command sessions ({len(stats.human)} human-flagged)")

    # ============================================================
    # Q16: Cowrie login funnel and SSH client fingerprints
    # ============================================================
    progress.start_section("Q16", "Cowrie login funnel and SSH client fingerprints")
    progress.update_sub(1, 1, "Aggregating logins and client versions...")
    auth_rows = []
    client_rows = []
    try:
        c.execute("""
            SELECT event_category,
                   CASE WHEN event_category = 'authentication_attempt' THEN payload
                        WHEN json_valid(raw_data) THEN json_extract(raw_data, '$.version') END AS k,
                   COUNT(*) AS cnt,
                   SUM(CASE WHEN instr(raw_data, 'cowrie.login.success') > 0 THEN 1 ELSE 0 END) AS successes,
                   COUNT(DISTINCT src_ip) AS ips
            FROM events
            WHERE sensor_type = 'cowrie'
              AND (event_category = 'authentication_attempt'
                   OR (event_category = 'command_execution' AND instr(raw_data, 'cowrie.client.version') > 0))
            GROUP BY event_category, k
        """)
        for r in c:
            (auth_rows if r['event_category'] == 'authentication_attempt' else client_rows).append(dict(r))
    except sqlite3.OperationalError:
        # SQLite without JSON functions: logins only
        c.execute("""
            SELECT 'authentication_attempt' AS event_category, payload AS k, COUNT(*) AS cnt,
                   SUM(CASE WHEN instr(raw_data, 'cowrie.login.success') > 0 THEN 1 ELSE 0 END) AS successes,
                   COUNT(DISTINCT src_ip) AS ips
            FROM events
            WHERE sensor_type = 'cowrie' AND event_category = 'authentication_attempt'
            GROUP BY payload
        """)
        auth_rows = [dict(r) for r in c.fetchall()]

    attempts = sum(r['cnt'] for r in auth_rows)
    successes = sum(r['successes'] or 0 for r in auth_rows)
    intents = {i['intent']: i['sessions'] for i in results['q14_intent_tags']}
    ds = results['q13_ml_dataset']
    results['q16_cowrie_funnel'] = [
        {'stage': 'Cowrie sessions (any)', 'value': ds.get('cowrie_sessions_total')},
        {'stage': 'Login attempts', 'value': attempts},
        {'stage': 'Successful logins', 'value': successes},
        {'stage': 'Sessions with typed commands', 'value': ds['sessions_with_commands']},
        {'stage': 'Sessions with >= 2 commands', 'value': ds['sessions_2plus_commands']},
        {'stage': 'Sessions with download attempt', 'value': intents.get('download', 0)},
        {'stage': 'Sessions with execute attempt', 'value': intents.get('execute', 0)},
        {'stage': 'Sessions flagged human', 'value': ds['human_flagged_sessions']},
    ]
    results['q16_login_success_pct'] = pct(successes, attempts)
    results['q16_top_successful_credentials'] = [
        {'payload': r['k'], 'successes': r['successes'], 'attempts': r['cnt'], 'ips': r['ips']}
        for r in sorted(auth_rows, key=lambda x: -(x['successes'] or 0))[:10] if r['successes']
    ]
    total_clients = sum(r['cnt'] for r in client_rows)
    results['q16_ssh_client_versions'] = [
        {'client_version': r['k'] or '(unknown)', 'connections': r['cnt'], 'ips': r['ips'],
         'pct': pct(r['cnt'], total_clients)}
        for r in sorted(client_rows, key=lambda x: -x['cnt'])[:15]
    ]
    progress.finish_section(f"{attempts:,} login attempts, {len(client_rows)} client versions")

    # ============================================================
    # Q12: Session Behavioral Metrics & Cadence Profiling
    # ============================================================
    progress.start_section("Q12", "Session behavioral metrics & cadence analysis")
    if has_sessions:
        progress.update_sub(1, 6, "Aggregating session metrics summary...")
        c.execute("""
            SELECT
                sensor_type,
                COUNT(*) as total_sessions,
                ROUND(AVG(session_duration), 2) as avg_duration_sec,
                ROUND(AVG(command_count), 2) as avg_commands,
                ROUND(AVG(unique_command_count), 2) as avg_unique_commands,
                ROUND(AVG(time_gap_mean), 2) as avg_time_gap_sec,
                ROUND(AVG(repetition_ratio), 4) as avg_repetition_ratio
            FROM sessions
            GROUP BY sensor_type
            ORDER BY total_sessions DESC
        """)
        results['q12_session_metrics_summary'] = [dict(r) for r in c.fetchall()]

        progress.update_sub(2, 6, "Profiling inter-command cadence distribution...")
        c.execute("""
            SELECT
                CASE
                    WHEN command_count <= 1 THEN 'Single Command / No Gap'
                    WHEN time_gap_mean < 0.5 THEN 'Burst Script (< 0.5s)'
                    WHEN time_gap_mean >= 0.5 AND time_gap_mean < 2.0 THEN 'Fast Bot Recon (0.5s - 2.0s)'
                    WHEN time_gap_mean >= 2.0 AND time_gap_mean < 5.0 THEN 'Paced Script (2.0s - 5.0s)'
                    ELSE 'Human Interactive Pace (>= 5.0s)'
                END AS cadence_tier,
                COUNT(*) AS session_count,
                ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM sessions WHERE command_count > 0), 2) AS pct_sessions,
                ROUND(AVG(command_count), 2) AS avg_commands,
                ROUND(AVG(session_duration), 2) AS avg_duration_sec,
                ROUND(AVG(repetition_ratio), 4) AS avg_repetition_ratio
            FROM sessions
            WHERE command_count > 0
            GROUP BY cadence_tier
            ORDER BY
                CASE cadence_tier
                    WHEN 'Burst Script (< 0.5s)' THEN 1
                    WHEN 'Fast Bot Recon (0.5s - 2.0s)' THEN 2
                    WHEN 'Paced Script (2.0s - 5.0s)' THEN 3
                    WHEN 'Human Interactive Pace (>= 5.0s)' THEN 4
                    ELSE 5
                END
        """)
        results['q12_cadence_distribution'] = [dict(r) for r in c.fetchall()]

        progress.update_sub(3, 6, "Clustering behavioral archetypes...")
        c.execute("""
            SELECT
                CASE
                    WHEN command_count = 1 THEN '1. Single-Command Probe'
                    WHEN command_count >= 5 AND repetition_ratio <= 0.25 THEN '2. Multi-Stage Diverse Malware Chain'
                    WHEN command_count >= 5 AND repetition_ratio >= 0.70 THEN '3. Monotonous Redundant Looper'
                    WHEN command_count >= 2 AND repetition_ratio BETWEEN 0.26 AND 0.69 THEN '4. Standard Automated Recon'
                    ELSE '5. Brief Interaction (2-4 Cmds)'
                END AS archetype,
                COUNT(*) AS session_count,
                ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM sessions WHERE command_count > 0), 2) AS pct,
                ROUND(AVG(command_count), 2) AS avg_cmds,
                ROUND(AVG(unique_command_count), 2) AS avg_unique_cmds,
                ROUND(AVG(session_duration), 2) AS avg_duration_sec,
                ROUND(AVG(time_gap_mean), 2) AS avg_gap_sec
            FROM sessions
            WHERE command_count > 0
            GROUP BY archetype
            ORDER BY archetype ASC
        """)
        results['q12_behavioral_archetypes'] = [dict(r) for r in c.fetchall()]

        progress.update_sub(4, 6, "Extracting top 10 complex multi-stage sessions...")
        c.execute("""
            SELECT session_id, sensor_type, src_ip, src_country,
                   command_count, unique_command_count, repetition_ratio,
                   time_gap_mean, session_duration
            FROM sessions
            ORDER BY unique_command_count DESC, session_duration DESC
            LIMIT 10
        """)
        results['q12_top_complex_sessions'] = [dict(r) for r in c.fetchall()]

        progress.update_sub(5, 6, "Extracting top 10 rapid-fire burst sessions...")
        c.execute("""
            SELECT session_id, sensor_type, src_ip, src_country,
                   command_count, unique_command_count, time_gap_mean, session_duration, repetition_ratio
            FROM sessions
            WHERE command_count >= 5 AND time_gap_mean > 0 AND time_gap_mean < 0.5
            ORDER BY time_gap_mean ASC, command_count DESC
            LIMIT 10
        """)
        results['q12_rapid_fire_sessions'] = [dict(r) for r in c.fetchall()]

        progress.update_sub(6, 6, "Extracting top 10 repetitive loopers...")
        c.execute("""
            SELECT session_id, sensor_type, src_ip, src_country,
                   command_count, unique_command_count, repetition_ratio,
                   time_gap_mean, session_duration
            FROM sessions
            WHERE command_count >= 10 AND repetition_ratio >= 0.75
            ORDER BY repetition_ratio DESC, command_count DESC
            LIMIT 10
        """)
        results['q12_top_repetitive_sessions'] = [dict(r) for r in c.fetchall()]
        progress.finish_section("Session metrics profiling complete")
    else:
        results['q12_session_metrics_summary'] = []
        results['q12_cadence_distribution'] = []
        results['q12_behavioral_archetypes'] = []
        results['q12_top_complex_sessions'] = []
        results['q12_rapid_fire_sessions'] = []
        results['q12_top_repetitive_sessions'] = []
        progress.finish_section("sessions table unpopulated (skipped)")

    conn.close()

    total_elapsed = progress.finish_all()
    results['meta'] = {
        'analyzer_version': ANALYZER_VERSION,
        'generated_at': datetime.now().isoformat(timespec='seconds'),
        'db_path': db_path,
        'db_size_bytes': os.path.getsize(db_path) if os.path.exists(db_path) else None,
        'runtime_sec': total_elapsed,
        'section_runtime_sec': progress.timings,
    }

    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Deep analysis complete. Results written to {out_path}")

if __name__ == '__main__':
    run()
