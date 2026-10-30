import os
import json
import csv
import sqlite3
import hashlib
import re
import gzip
import sys
from pathlib import Path
from datetime import datetime
try:
    from iptocc import country_code
except ImportError:
    try:
        from iptocc import get_country_code as country_code
    except ImportError:
        def country_code(ip): return None

def safe_country_code(ip):
    """Safely resolve country code without crashing on bogons or private IPs."""
    if not ip:
        return None
    try:
        return country_code(ip)
    except Exception:
        return None

DB_PATH = r"C:\honeypots-normalization\honeypot_normalized.db"
ROOT_DIR = r"C:\honeypots-normalization\blob"

# Bump when the session metric definition changes; existing sessions are then recomputed once.
# v2: only typed commands count (cowrie.client.* events with empty payload are excluded)
SESSION_METRICS_VERSION = 2

def setup_db(conn):
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            sensor_type TEXT NOT NULL,
            sensor_instance TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            event_category TEXT NOT NULL,
            payload TEXT,
            session_id TEXT,
            raw_data TEXT,
            src_country TEXT,
            attack_type TEXT,
            command_count INTEGER DEFAULT 0,
            unique_command_count INTEGER DEFAULT 0,
            session_duration REAL DEFAULT 0.0,
            time_gap_mean REAL DEFAULT 0.0,
            repetition_ratio REAL DEFAULT 0.0
        )
    """)
    cursor.execute("PRAGMA table_info(events)")
    columns = [col[1] for col in cursor.fetchall()]
    schema_additions = [
        ('src_country', 'TEXT'),
        ('attack_type', "TEXT DEFAULT 'uncertain'"),
        ('command_count', 'INTEGER DEFAULT 0'),
        ('unique_command_count', 'INTEGER DEFAULT 0'),
        ('session_duration', 'REAL DEFAULT 0.0'),
        ('time_gap_mean', 'REAL DEFAULT 0.0'),
        ('repetition_ratio', 'REAL DEFAULT 0.0')
    ]
    for col_name, col_def in schema_additions:
        if col_name not in columns:
            print(f"Schema update: Adding {col_name} to events table.")
            cursor.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_def}")

    # Sessions table for fast aggregated lookups
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            sensor_type TEXT NOT NULL,
            sensor_instance TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_country TEXT,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            session_duration REAL NOT NULL,
            command_count INTEGER DEFAULT 0,
            unique_command_count INTEGER DEFAULT 0,
            time_gap_mean REAL DEFAULT 0.0,
            repetition_ratio REAL DEFAULT 0.0
        )
    """)

    # Small key/value store for pipeline state (e.g. session metrics version)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pipeline_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # File registry: lets unchanged raw files be skipped by size + mtime without re-reading them
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_files (
            file_path TEXT PRIMARY KEY,
            file_size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            processed_at TEXT NOT NULL
        )
    """)

    # Indexes for fast analytical queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON events(src_ip)")
    # Composite index serves per-sensor MAX(timestamp) lookups; it also covers sensor_type-only filters
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensor_inst_ts ON events(sensor_type, sensor_instance, timestamp)")
    cursor.execute("DROP INDEX IF EXISTS idx_sensor_type")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON events(event_category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_id ON events(session_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_sensor ON sessions(sensor_type)")

    # Analytical view combining events with session metrics
    cursor.execute("""
        CREATE VIEW IF NOT EXISTS v_events_enriched AS
        SELECT 
            e.event_id,
            e.timestamp,
            e.sensor_type,
            e.sensor_instance,
            e.src_ip,
            e.src_port,
            e.dst_port,
            e.event_category,
            e.payload,
            e.session_id,
            e.raw_data,
            e.src_country,
            e.attack_type,
            COALESCE(s.command_count, e.command_count, 0) AS session_command_count,
            COALESCE(s.unique_command_count, e.unique_command_count, 0) AS session_unique_command_count,
            COALESCE(s.session_duration, e.session_duration, 0.0) AS session_duration,
            COALESCE(s.time_gap_mean, e.time_gap_mean, 0.0) AS session_time_gap_mean,
            COALESCE(s.repetition_ratio, e.repetition_ratio, 0.0) AS session_repetition_ratio
        FROM events e
        LEFT JOIN sessions s ON e.session_id = s.session_id
    """)
    conn.commit()

def parse_iso_ts(ts_str):
    """Safely parse ISO8601 timestamp string to datetime object."""
    if not ts_str:
        return None
    try:
        clean = ts_str.replace(' ', 'T').replace('Z', '+00:00').strip()
        if 'T' not in clean:
            return None
        return datetime.fromisoformat(clean)
    except Exception:
        return None

def calculate_metrics_for_session(commands_list, min_ts, max_ts):
    """Calculate behavioral session metrics for a single session."""
    duration = 0.0
    if min_ts and max_ts:
        duration = max(0.0, (max_ts - min_ts).total_seconds())

    cmd_count = len(commands_list)
    unique_cmds = set(payload for _, payload in commands_list if payload is not None)
    unique_cmd_count = len(unique_cmds)

    repetition_ratio = round(1.0 - (unique_cmd_count / cmd_count), 4) if cmd_count > 0 else 0.0

    if cmd_count >= 2:
        valid_cmd_dts = sorted([dt for dt, _ in commands_list if dt is not None])
        if len(valid_cmd_dts) >= 2:
            span = (valid_cmd_dts[-1] - valid_cmd_dts[0]).total_seconds()
            time_gap_mean = round(span / (len(valid_cmd_dts) - 1), 4)
        else:
            time_gap_mean = 0.0
    else:
        time_gap_mean = 0.0

    return cmd_count, unique_cmd_count, duration, time_gap_mean, repetition_ratio

def backfill_session_metrics(conn, batch_size=10000):
    """
    Computes and populates session behavioral metrics in-place directly in SQLite.
    Updates both 'sessions' table and 'events' columns without touching raw logs.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM pipeline_meta WHERE key = 'session_metrics_version'")
    row = cursor.fetchone()
    stored_version = int(row[0]) if row else 0
    if stored_version < SESSION_METRICS_VERSION:
        # Clearing 'sessions' makes every session "missing", so the code below recomputes all of them.
        # Version and delete commit together: an interrupted recompute resumes on the next run.
        print(f"Session metric definition changed (v{stored_version} -> v{SESSION_METRICS_VERSION}). "
              "Recomputing all session metrics once...")
        cursor.execute("DELETE FROM sessions")
        cursor.execute("""
            INSERT INTO pipeline_meta (key, value) VALUES ('session_metrics_version', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (str(SESSION_METRICS_VERSION),))
        conn.commit()

    # A session needs computing when it has events but no row in 'sessions' yet.
    # (command_count = 0 is a valid result for sessions without commands, so it cannot be used as a marker.)
    cursor.execute("""
        SELECT e.session_id FROM events e
        WHERE e.session_id IS NOT NULL AND e.session_id != ''
          AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = e.session_id)
        LIMIT 1
    """)
    if not cursor.fetchone():
        print("All session metrics are already up to date.")
        return

    print("Computing behavioral session metrics from existing database records...")
    cursor.execute("""
        SELECT 
            session_id,
            sensor_type,
            sensor_instance,
            src_ip,
            src_country,
            MIN(timestamp) AS start_ts,
            MAX(timestamp) AS end_ts
        FROM events e
        WHERE e.session_id IS NOT NULL AND e.session_id != ''
          AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = e.session_id)
        GROUP BY e.session_id
    """)
    session_rows = cursor.fetchall()
    total_sessions = len(session_rows)
    print(f"Found {total_sessions} unpopulated sessions to compute...")

    if total_sessions == 0:
        return

    sessions_data = {}
    for sid, stype, sinst, ip, country, start_ts, end_ts in session_rows:
        sessions_data[sid] = {
            'sensor_type': stype,
            'sensor_instance': sinst,
            'src_ip': ip,
            'src_country': country,
            'start_time': start_ts,
            'end_time': end_ts,
            'min_dt': parse_iso_ts(start_ts),
            'max_dt': parse_iso_ts(end_ts),
            'commands': []
        }

    session_id_set = set(sessions_data.keys())
    print("Loading command events for target sessions...")
    cmd_cursor = conn.cursor()
    # Only typed commands: cowrie.client.* events (version, kex, size) share the category but have no payload
    cmd_cursor.execute("""
        SELECT session_id, timestamp, payload
        FROM events
        WHERE session_id IS NOT NULL AND session_id != ''
          AND event_category = 'command_execution'
          AND payload IS NOT NULL AND payload != ''
        ORDER BY timestamp ASC
    """)
    for sid, ts_str, payload in cmd_cursor:
        if sid in session_id_set:
            dt = parse_iso_ts(ts_str)
            sessions_data[sid]['commands'].append((dt, payload))

    session_inserts = []
    events_updates = []
    processed = 0

    for sid, data in sessions_data.items():
        cmd_count, uniq_cmd, duration, gap_mean, rep_ratio = calculate_metrics_for_session(
            data['commands'], data['min_dt'], data['max_dt']
        )
        session_inserts.append((
            sid, data['sensor_type'], data['sensor_instance'],
            data['src_ip'], data['src_country'],
            data['start_time'], data['end_time'],
            duration, cmd_count, uniq_cmd, gap_mean, rep_ratio
        ))
        events_updates.append((
            cmd_count, uniq_cmd, duration, gap_mean, rep_ratio, sid
        ))

        if len(session_inserts) >= batch_size:
            cursor.executemany("""
                INSERT INTO sessions (
                    session_id, sensor_type, sensor_instance, src_ip, src_country,
                    start_time, end_time, session_duration, command_count,
                    unique_command_count, time_gap_mean, repetition_ratio
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id) DO UPDATE SET
                    start_time = excluded.start_time,
                    end_time = excluded.end_time,
                    session_duration = excluded.session_duration,
                    command_count = excluded.command_count,
                    unique_command_count = excluded.unique_command_count,
                    time_gap_mean = excluded.time_gap_mean,
                    repetition_ratio = excluded.repetition_ratio
            """, session_inserts)

            cursor.executemany("""
                UPDATE events
                SET command_count = ?,
                    unique_command_count = ?,
                    session_duration = ?,
                    time_gap_mean = ?,
                    repetition_ratio = ?
                WHERE session_id = ?
            """, events_updates)
            conn.commit()
            processed += len(session_inserts)
            pct = (processed / total_sessions * 100.0) if total_sessions > 0 else 100.0
            sys.stdout.write(f"\r[Metrics] Persisting session metrics: {processed}/{total_sessions} ({pct:.1f}%) complete   ")
            sys.stdout.flush()
            session_inserts = []
            events_updates = []

    if session_inserts:
        cursor.executemany("""
            INSERT INTO sessions (
                session_id, sensor_type, sensor_instance, src_ip, src_country,
                start_time, end_time, session_duration, command_count,
                unique_command_count, time_gap_mean, repetition_ratio
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(session_id) DO UPDATE SET
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                session_duration = excluded.session_duration,
                command_count = excluded.command_count,
                unique_command_count = excluded.unique_command_count,
                time_gap_mean = excluded.time_gap_mean,
                repetition_ratio = excluded.repetition_ratio
        """, session_inserts)

        cursor.executemany("""
            UPDATE events
            SET command_count = ?,
                unique_command_count = ?,
                session_duration = ?,
                time_gap_mean = ?,
                repetition_ratio = ?
            WHERE session_id = ?
        """, events_updates)
        conn.commit()
        processed += len(session_inserts)
        pct = (processed / total_sessions * 100.0) if total_sessions > 0 else 100.0
        sys.stdout.write(f"\r[Metrics] Persisting session metrics: {processed}/{total_sessions} ({pct:.1f}%) complete   ")
        sys.stdout.flush()

    sys.stdout.write("\n")
    sys.stdout.flush()
    print(f"Session metrics backfill complete. Total sessions enriched: {processed}")

def backfill_countries(conn):
    print("Checking for missing country data...")
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT src_ip FROM events WHERE src_country IS NULL")
    ips = [row[0] for row in cursor.fetchall() if row[0]]
    if not ips:
        print("No backfilling needed.")
        return
    print(f"Backfilling countries for {len(ips)} distinct IPs...")
    updates = []
    for ip in ips:
        try:
            country = safe_country_code(ip)
        except Exception:
            country = None
        updates.append((country, ip))
    cursor.executemany("UPDATE events SET src_country = ? WHERE src_ip = ?", updates)
    conn.commit()
    print("Backfill complete.")

def generate_id(ts, instance, ip, cat, payload):
    s = f"{ts}|{instance}|{ip}|{cat}|{payload}".encode('utf-8')
    return hashlib.sha256(s).hexdigest()

def normalize_cowrie(line, instance, session_state):
    try:
        data = json.loads(line)
    except:
        return None
    
    ts = data.get('timestamp')
    src_ip = data.get('src_ip')
    if not ts or not src_ip: return None
    
    eventid = data.get('eventid', '')
    category = 'other'
    payload = ''
    attack_type = 'uncertain'
    
    if eventid.startswith('cowrie.login'):
        category = 'authentication_attempt'
        payload = f"{data.get('username','')}:{data.get('password','')}"
        if eventid == 'cowrie.login.success':
            session_state[data.get('session')] = ts
    elif eventid.startswith('cowrie.command') or eventid.startswith('cowrie.client'):
        category = 'command_execution'
        payload = data.get('input', data.get('ttylog', ''))
        
        if eventid == 'cowrie.client.version':
            version_str = data.get('version', '')
            if 'SSH-2.0-Go' in version_str or 'libssh' in version_str.lower() or 'paramiko' in version_str.lower():
                attack_type = 'automated'
                
        if eventid == 'cowrie.client.size':
            try:
                width = int(data.get('width', 0) or 0)
                height = int(data.get('height', 0) or 0)
                if width >= 100 and height >= 100:
                    attack_type = 'human_or_manual'
            except (ValueError, TypeError):
                pass
        
        if eventid == 'cowrie.command.input':
            login_ts_str = session_state.get(data.get('session'))
            if login_ts_str:
                try:
                    t1 = datetime.fromisoformat(login_ts_str.replace('Z', '+00:00'))
                    t2 = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    delta = (t2 - t1).total_seconds()
                    if delta < 2.0 or len(payload) > 200:
                        attack_type = 'automated'
                    elif delta >= 2.0 and payload.strip() in ['nano', 'vi', 'top', 'ping']:
                        attack_type = 'human_or_manual'
                except: pass
                
    elif eventid.startswith('cowrie.session'):
        category = 'connection_established'
        if eventid == 'cowrie.session.file_upload':
            category = 'payload_delivery'
            payload = data.get('url', data.get('shasum'))
            login_ts_str = session_state.get(data.get('session'))
            if login_ts_str:
                try:
                    t1 = datetime.fromisoformat(login_ts_str.replace('Z', '+00:00'))
                    t2 = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    if (t2 - t1).total_seconds() < 2.0: attack_type = 'automated'
                except: pass
        elif eventid == 'cowrie.session.closed':
            try:
                if float(data.get('duration', 99)) < 1.0:
                    attack_type = 'automated'
            except: pass
    elif 'shasum' in data:
        category = 'payload_delivery'
        payload = data.get('url', data.get('shasum'))

    return (
        generate_id(ts, instance, src_ip, category, payload),
        ts, 'cowrie', instance, src_ip,
        data.get('src_port'), data.get('dst_port'),
        category, payload, data.get('session'),
        line if len(line) < 1000 else line[:1000], # truncate raw if too big
        safe_country_code(src_ip),
        attack_type
    )

def normalize_endlessh(line, instance):
    # endlessh format: ... endlessh[1197286]: 2026-03-29T19:38:26.039Z ACCEPT host=::ffff:77.119.162.162 port=13562 ...
    match = re.search(r'(?P<ts>\d{4}-\d{2}-\d{2}T.*?Z)\s+(?P<action>\S+)\s+host=::ffff:(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port=(?P<port>\d+)', line)
    if match:
        ts = match.group('ts')
        src_ip = match.group('ip')
        src_port = int(match.group('port'))
        category = 'connection_established'
        
        attack_type = 'uncertain'
        match_close = re.search(r'CLOSE.*?time=([\d\.]+)', line)
        if match_close:
            try:
                if float(match_close.group(1)) > 10.0:
                    attack_type = 'automated'
            except: pass
            
        return (
            generate_id(ts, instance, src_ip, category, ''),
            ts, 'endlessh', instance, src_ip,
            src_port, 22, category, '', '', line,
            safe_country_code(src_ip),
            attack_type
        )
    return None

def normalize_heralding_auth(row, instance):
    if len(row) < 10: return None
    ts, auth_id, sess_id, src_ip, src_port, dst_ip, dst_port, proto, user, pwd = row[:10]
    # some timestamps might not be iso8601 strict if they lack T or Z, let's just use as is or replace space with T
    ts = ts.replace(' ', 'T') + 'Z' if 'T' not in ts else ts
    category = 'authentication_attempt'
    payload = f"{user}:{pwd}"
    return (
        generate_id(ts, instance, src_ip, category, payload),
        ts, 'heralding', instance, src_ip,
        int(src_port) if src_port.isdigit() else None,
        int(dst_port) if dst_port.isdigit() else None,
        category, payload, sess_id, ",".join(row),
        safe_country_code(src_ip),
        'uncertain'
    )

def normalize_heralding_session(line, instance):
    try:
        data = json.loads(line)
    except:
        return None
    ts = data.get('timestamp')
    if ts: ts = ts.replace(' ', 'T') + 'Z' if 'T' not in ts else ts
    src_ip = data.get('source_ip')
    if not ts or not src_ip: return None
    
    category = 'connection_established'
    
    attack_type = 'uncertain'
    try:
        dur = float(data.get('duration', 0))
        auths = float(data.get('num_auth_attempts', 0))
        cv = data.get('auxiliary_data', {}).get('client_version', '')
        
        if dur > 0 and (auths / dur) > 2.0:
            attack_type = 'automated'
        elif cv and ('SSH-2.0-Go' in cv or 'libssh' in cv.lower()):
            attack_type = 'automated'
    except: pass

    return (
        generate_id(ts, instance, src_ip, category, ''),
        ts, 'heralding', instance, src_ip,
        data.get('source_port'), data.get('destination_port'),
        category, '', data.get('session_id'), line,
        safe_country_code(src_ip),
        attack_type
    )

def normalize_nginx(line, instance):
    try:
        data = json.loads(line)
    except:
        return None
    ts = data.get('ts')
    src_ip = data.get('src_ip')
    if not ts or not src_ip: return None
    
    category = 'payload_delivery'
    payload = f"{data.get('method','')} {data.get('uri','')} {data.get('http_version','')}"
    
    attack_type = 'uncertain'
    ua = data.get('user_agent', '').lower()
    uri = data.get('uri', '').lower()
    
    automated_uas = ['go-http-client', 'zgrab', 'masscan', 'nuclei', 'curl', 'wget', 'python', 'libredtail']
    automated_uris = ['phpunit', '.env', 'thinkphp', '.git', 'autodiscover', 'invokefunction']
    
    if any(x in ua for x in automated_uas):
        attack_type = 'automated'
    elif any(x in uri for x in automated_uris) or data.get('method') == 'PROPFIND':
        attack_type = 'automated'

    return (
        generate_id(ts, instance, src_ip, category, payload),
        ts, 'nginx', instance, src_ip,
        data.get('src_port'), data.get('dst_port'),
        category, payload, '', line,
        safe_country_code(src_ip),
        attack_type
    )

def backfill_attack_types(conn):
    print("Backfilling attack_type using SQL heuristics for older records...")
    cursor = conn.cursor()
    # Nginx
    cursor.execute("""
        UPDATE events SET attack_type = 'automated'
        WHERE sensor_type = 'nginx' AND attack_type = 'uncertain'
        AND (
            LOWER(raw_data) LIKE '%go-http-client%' OR
            LOWER(raw_data) LIKE '%zgrab%' OR
            LOWER(raw_data) LIKE '%masscan%' OR
            LOWER(raw_data) LIKE '%nuclei%' OR
            LOWER(raw_data) LIKE '%curl%' OR
            LOWER(raw_data) LIKE '%wget%' OR
            LOWER(raw_data) LIKE '%python%' OR
            LOWER(raw_data) LIKE '%libredtail%' OR
            LOWER(raw_data) LIKE '%phpunit%' OR
            LOWER(raw_data) LIKE '%env%' OR
            LOWER(raw_data) LIKE '%thinkphp%' OR
            LOWER(raw_data) LIKE '%propfind%' OR
            LOWER(raw_data) LIKE '%invokefunction%'
        )
    """)
    # Cowrie Automated
    cursor.execute("""
        UPDATE events SET attack_type = 'automated'
        WHERE sensor_type = 'cowrie' AND attack_type = 'uncertain'
        AND (
            raw_data LIKE '%SSH-2.0-Go%' OR
            LOWER(raw_data) LIKE '%libssh%' OR
            LOWER(raw_data) LIKE '%paramiko%'
        )
    """)
    # Cowrie Human (only terminal sizes >= 100 in both x and y axis)
    cursor.execute("""
        SELECT event_id, raw_data FROM events 
        WHERE sensor_type = 'cowrie' AND attack_type = 'uncertain' 
        AND raw_data LIKE '%cowrie.client.size%'
    """)
    for eid, raw in cursor.fetchall():
        try:
            d = json.loads(raw)
            w = int(d.get('width', 0) or 0)
            h = int(d.get('height', 0) or 0)
            if w >= 100 and h >= 100:
                cursor.execute("UPDATE events SET attack_type = 'human_or_manual' WHERE event_id = ?", (eid,))
        except Exception:
            pass
    # Heralding Automated
    cursor.execute("""
        UPDATE events SET attack_type = 'automated'
        WHERE sensor_type = 'heralding' AND attack_type = 'uncertain'
        AND (
            raw_data LIKE '%SSH-2.0-Go%' OR
            LOWER(raw_data) LIKE '%libssh%'
        )
    """)
    conn.commit()
    print("Backfill for attack_type complete.")

def open_log(filepath, mode='rt'):
    if filepath.name.endswith('.gz'):
        return gzip.open(filepath, mode, encoding='utf-8', errors='ignore')
    return open(filepath, mode, encoding='utf-8', errors='ignore')

def is_file_processed(filepath, agent, instance, cursor):
    """
    Checks if a file has already been fully imported into SQLite.
    Validates both the first valid event AND the last valid event:
      - If first event is missing, the file is new -> return False (process it).
      - If first event exists, check the last event:
        - If last event also exists -> file was already fully imported -> return True (skip).
        - If last event is missing -> new records were appended to the file -> return False (process it).
    """
    first_rec = None
    last_rec = None
    try:
        with open_log(filepath) as f:
            if agent == 'heralding' and 'log_auth.csv' in filepath.name:
                reader = csv.reader((x.replace('\0', '') for x in f))
                for row in reader:
                    rec = normalize_heralding_auth(row, instance)
                    if rec:
                        if first_rec is None:
                            first_rec = rec
                            cursor.execute("SELECT 1 FROM events WHERE event_id = ?", (first_rec[0],))
                            if cursor.fetchone() is None:
                                return False # First record not in DB; new file
                        last_rec = rec
            else:
                for line in f:
                    line = line.strip().replace('\0', '')
                    if not line: continue
                    rec = None
                    if agent == 'cowrie': rec = normalize_cowrie(line, instance, {})
                    elif agent == 'endlessh': rec = normalize_endlessh(line, instance)
                    elif agent == 'heralding' and 'log_session.json' in filepath.name: rec = normalize_heralding_session(line, instance)
                    elif agent == 'nginx': rec = normalize_nginx(line, instance)

                    if rec:
                        if first_rec is None:
                            first_rec = rec
                            cursor.execute("SELECT 1 FROM events WHERE event_id = ?", (first_rec[0],))
                            if cursor.fetchone() is None:
                                return False # First record not in DB; new file
                        last_rec = rec

        if not first_rec:
            return False

        # If first record is present, verify last record exists
        if last_rec and last_rec[0] != first_rec[0]:
            cursor.execute("SELECT 1 FROM events WHERE event_id = ?", (last_rec[0],))
            if cursor.fetchone() is None:
                return False # New entries were appended to this file

        return True
    except Exception:
        pass
    return False

def register_files(cursor, entries):
    """
    Records (file_path, file_size, mtime_ns) entries in processed_files.
    Must run in the same transaction as the commit of those files' events, so a crash
    never leaves a file registered whose records are missing.
    """
    now = datetime.now().isoformat(timespec='seconds')
    cursor.executemany("""
        INSERT INTO processed_files (file_path, file_size, mtime_ns, processed_at)
        VALUES (?,?,?,?)
        ON CONFLICT(file_path) DO UPDATE SET
            file_size = excluded.file_size,
            mtime_ns = excluded.mtime_ns,
            processed_at = excluded.processed_at
    """, [(path, size, mtime_ns, now) for path, size, mtime_ns in entries])

def process_file(filepath, agent, instance, session_state, batch_size=20000):
    records = []
    rs, er = 0, 0
    
    try:
        with open_log(filepath) as f:
            if agent == 'heralding' and 'log_auth.csv' in filepath.name:
                reader = csv.reader((x.replace('\0', '') for x in f))
                for row in reader:
                    rs += 1
                    rec = normalize_heralding_auth(row, instance)
                    if rec: records.append(rec)
                    else: er += 1
            else:
                for line in f:
                    rs += 1
                    line = line.strip()
                    if not line:
                        er += 1
                        continue
                        
                    rec = None
                    if agent == 'cowrie':
                        rec = normalize_cowrie(line, instance, session_state)
                    elif agent == 'endlessh':
                        rec = normalize_endlessh(line, instance)
                    elif agent == 'heralding' and 'log_session.json' in filepath.name:
                        rec = normalize_heralding_session(line, instance)
                    elif agent == 'nginx':
                        rec = normalize_nginx(line, instance)
                    else:
                        er += 1 # skip unhandled types like log_session.csv
                        continue

                    if rec: records.append(rec)
                    else: er += 1

    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        er += rs # assume failed entirely if crash

    return records, rs, er

def detect_agent_type(filepath):
    name = filepath.name.lower()
    if 'cowrie' in name:
        return 'cowrie'
    elif 'endlessh' in name:
        return 'endlessh'
    elif 'log_auth.csv' in name or 'log_session.csv' in name or 'log_session.json' in name:
        return 'heralding'
    elif 'access.log' in name or name.startswith('honeypot_'):
        return 'nginx'
    return None

def get_agent_and_instance(filepath, root_dir):
    try:
        rel_path = filepath.relative_to(root_dir)
        parts = rel_path.parts
        if len(parts) >= 2:
            first = parts[0]
            if first in ('cowrie', 'endlessh', 'heralding', 'nginx'):
                agent = first
                instance = parts[1]
                return agent, instance
            else:
                agent = detect_agent_type(filepath)
                if agent:
                    return agent, first
    except Exception:
        pass
    return None, None

def extract_file_date(filepath):
    """Extract YYYY-MM-DD date from file path or file name."""
    # Match YYYY-MM-DD in filename (e.g. log_auth.csv.2026-04-01 or endlessh-2026-03-29.log)
    m = re.search(r'(\d{4}-\d{2}-\d{2})', filepath.name)
    if m:
        return m.group(1)
    # Match YYYY/MM/DD in path parts
    parts = filepath.parts
    for i in range(len(parts) - 2):
        if re.fullmatch(r'\d{4}', parts[i]) and re.fullmatch(r'\d{2}', parts[i+1]) and re.fullmatch(r'\d{2}', parts[i+2]):
            return f"{parts[i]}-{parts[i+1]}-{parts[i+2]}"
    return None

def run():
    print("Initializing Database...")
    conn = sqlite3.connect(DB_PATH)
    # Use WAL mode for better performance on large inserts
    conn.execute('PRAGMA journal_mode = WAL')
    setup_db(conn)
    cursor = conn.cursor()
    
    total_rs = 0
    total_er = 0
    total_inserted = 0
    files_skipped = 0
    
    cowrie_sessions = {}
    base_dir = Path(ROOT_DIR)

    # Pre-collect valid target files grouped by (agent, instance)
    sensor_files = {}
    for filepath in sorted(base_dir.rglob("*")):
        if filepath.is_file():
            agent, instance = get_agent_and_instance(filepath, base_dir)
            if not agent or not instance:
                continue
            if agent == 'heralding' and 'log_session.csv' in filepath.name:
                continue
            if filepath.name.lower().endswith('.gz') and filepath.with_suffix('').is_file():
                continue
            sensor_files.setdefault((agent, instance), []).append(filepath)

    batch = []
    pending_registrations = []

    for (agent, instance), file_list in sensor_files.items():
        # Query latest timestamp already in the database for this specific sensor
        # substr() outside MAX() lets SQLite answer from idx_sensor_inst_ts instead of scanning all rows
        cursor.execute("""
            SELECT substr(MAX(timestamp), 1, 10)
            FROM events
            WHERE sensor_type = ? AND sensor_instance = ?
        """, (agent, instance))
        row = cursor.fetchone()
        db_max_date = row[0] if (row and row[0]) else None

        # Group sensor files by extracted date (YYYY-MM-DD)
        days_map = {}
        for fp in file_list:
            d = extract_file_date(fp) or "unknown"
            days_map.setdefault(d, []).append(fp)

        sorted_days = sorted([d for d in days_map.keys() if d != "unknown"])
        if "unknown" in days_map:
            sorted_days.append("unknown")

        # Determine which days need checking/importing
        if db_max_date:
            days_to_process = [d for d in sorted_days if d >= db_max_date or d == "unknown"]
        else:
            days_to_process = list(sorted_days)

        first_data_date = sorted_days[0] if sorted_days else "None"
        last_data_date = sorted_days[-1] if sorted_days else "None"
        total_days = len(days_to_process)
        completed_days = 0

        print(f"Processing {agent}/{instance} | Range on disk: {first_data_date} to {last_data_date} | In DB: {db_max_date or 'None'} | Days to process: {total_days}")

        for day in sorted_days:
            # Skip earlier days completely if we already have data past this day
            if db_max_date and day != "unknown" and day < db_max_date:
                continue

            fps = days_map[day]
            day_records = 0

            for filepath in fps:
                # Stat before reading: if the file grows during the read, the next run sees a new size
                try:
                    st = filepath.stat()
                except OSError:
                    continue
                file_key = filepath.relative_to(base_dir).as_posix()
                file_sig = (file_key, st.st_size, st.st_mtime_ns)

                cursor.execute("SELECT file_size, mtime_ns FROM processed_files WHERE file_path = ?", (file_key,))
                reg = cursor.fetchone()
                if reg and reg[0] == st.st_size and reg[1] == st.st_mtime_ns:
                    files_skipped += 1
                    continue

                # Not registered yet (e.g. imported before the registry existed) or only mtime changed:
                # fall back to the content check before re-importing. A changed size always means new data.
                if (reg is None or reg[0] == st.st_size) and is_file_processed(filepath, agent, instance, cursor):
                    pending_registrations.append(file_sig)
                    files_skipped += 1
                    continue

                recs, rs, er = process_file(filepath, agent, instance, cowrie_sessions)
                total_rs += rs
                total_er += er
                day_records += len(recs)
                batch.extend(recs)
                # process_file sets er >= rs on a read error; leave such files unregistered so they are retried
                if rs == 0 or er < rs:
                    pending_registrations.append(file_sig)

                if len(batch) >= 50000:
                    cursor.executemany("""
                        INSERT INTO events (
                            event_id, timestamp, sensor_type, sensor_instance, src_ip,
                            src_port, dst_port, event_category, payload, session_id,
                            raw_data, src_country, attack_type
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(event_id) DO UPDATE SET
                            src_country = COALESCE(events.src_country, excluded.src_country),
                            attack_type = CASE 
                                WHEN events.attack_type IS NULL OR events.attack_type = 'uncertain' 
                                THEN excluded.attack_type 
                                ELSE events.attack_type 
                            END
                    """, batch)
                    total_inserted += cursor.rowcount
                    register_files(cursor, pending_registrations)
                    conn.commit()
                    batch = []
                    pending_registrations = []

            completed_days += 1
            pct = (completed_days / total_days * 100.0) if total_days > 0 else 100.0
            sys.stdout.write(f"\r[{agent}/{instance}] Day: {day} ({completed_days}/{total_days}) -> {pct:.1f}% complete   ")
            sys.stdout.flush()

        # Print newline after sensor completes to retain progress line
        sys.stdout.write("\n")
        sys.stdout.flush()

    # Insert remaining records
    if batch:
        cursor.executemany("""
            INSERT INTO events (
                event_id, timestamp, sensor_type, sensor_instance, src_ip,
                src_port, dst_port, event_category, payload, session_id,
                raw_data, src_country, attack_type
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(event_id) DO UPDATE SET
                src_country = COALESCE(events.src_country, excluded.src_country),
                attack_type = CASE 
                    WHEN events.attack_type IS NULL OR events.attack_type = 'uncertain' 
                    THEN excluded.attack_type 
                    ELSE events.attack_type 
                END
        """, batch)
        total_inserted += cursor.rowcount
        conn.commit()
        batch = []

    # Register remaining files (their events, if any, were committed just above)
    if pending_registrations:
        register_files(cursor, pending_registrations)
        conn.commit()
        pending_registrations = []

    # Self-healing backfills: session behavioral metrics, countries, and attack types.
    # Session metrics check is cheap. The other two scan the whole table, so they only run
    # when this run wrote events (or on demand, e.g. after a run crashed before reaching them).
    backfill_session_metrics(conn)
    if total_inserted > 0 or '--force-backfill' in sys.argv:
        backfill_countries(conn)
        backfill_attack_types(conn)
    else:
        print("No new events inserted. Skipping country and attack_type backfills (use --force-backfill to run them).")

    conn.close()
    print("=== Normalization Complete ===")
    print(f"Total Raw Lines Processed (Rs): {total_rs}")
    print(f"Total Inserted Events (Ne): {total_inserted}")
    print(f"Total Errors/Skipped (Er): {total_er}")
    print(f"Files completely skipped (unmodified): {files_skipped}")
    print(f"Rs == Ne + Er : {total_rs == (total_inserted + total_er)} (Note: INSERT OR IGNORE skips dupes, so Ne is distinct count)")

if __name__ == '__main__':
    run()
