import os
import json
import csv
import sqlite3
import hashlib
import re
from pathlib import Path
from datetime import datetime
from iptocc import country_code

DB_PATH = r"C:\honeypots-normalization\honeypot_normalized.db"
ROOT_DIR = r"C:\honeypots-normalization\blob"

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
            attack_type TEXT
        )
    """)
    cursor.execute("PRAGMA table_info(events)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'src_country' not in columns:
        print("Schema update: Adding src_country to events table.")
        cursor.execute("ALTER TABLE events ADD COLUMN src_country TEXT")
    if 'attack_type' not in columns:
        print("Schema update: Adding attack_type to events table.")
        cursor.execute("ALTER TABLE events ADD COLUMN attack_type TEXT DEFAULT 'uncertain'")

    # Indexes for fast analytical queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON events(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensor_type ON events(sensor_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON events(event_category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
    conn.commit()

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
            country = country_code(ip)
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
            attack_type = 'human_or_manual'
        
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
        country_code(src_ip) if src_ip else None,
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
            country_code(src_ip) if src_ip else None,
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
        country_code(src_ip) if src_ip else None,
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
        country_code(src_ip) if src_ip else None,
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
        country_code(src_ip) if src_ip else None,
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
    # Cowrie Human
    cursor.execute("""
        UPDATE events SET attack_type = 'human_or_manual'
        WHERE sensor_type = 'cowrie' AND attack_type = 'uncertain'
        AND raw_data LIKE '%cowrie.client.size%'
    """)
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

def is_file_processed(filepath, agent, instance, cursor):
    """
    Clever SQL approach: read the first valid event from the file and query its event_id 
    against the database. If it exists, the file has already been imported.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if agent == 'heralding' and 'log_auth.csv' in filepath.name:
                reader = csv.reader(f)
                for row in reader:
                    rec = normalize_heralding_auth(row, instance)
                    if rec:
                        cursor.execute("SELECT 1 FROM events WHERE event_id = ?", (rec[0],))
                        return cursor.fetchone() is not None
            else:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    rec = None
                    if agent == 'cowrie': rec = normalize_cowrie(line, instance, {})
                    elif agent == 'endlessh': rec = normalize_endlessh(line, instance)
                    elif agent == 'heralding' and 'log_session.json' in filepath.name: rec = normalize_heralding_session(line, instance)
                    elif agent == 'nginx': rec = normalize_nginx(line, instance)
                    
                    if rec:
                        cursor.execute("SELECT 1 FROM events WHERE event_id = ?", (rec[0],))
                        return cursor.fetchone() is not None
    except Exception:
        pass
    return False

def process_file(filepath, agent, instance, session_state, batch_size=20000):
    records = []
    rs, er = 0, 0
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if agent == 'heralding' and 'log_auth.csv' in filepath.name:
                reader = csv.reader(f)
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
    elif name in ('log_auth.csv', 'log_session.csv', 'log_session.json'):
        return 'heralding'
    elif name == 'access.log' or (name.startswith('honeypot_') and name.endswith('.log')):
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
    
    # Iterate files recursively under ROOT_DIR
    batch = []
    seen_instances = set()
    for filepath in base_dir.rglob("*"):
        if filepath.is_file() and not filepath.name.endswith('.gz'):
            agent, instance = get_agent_and_instance(filepath, base_dir)
            if not agent or not instance:
                continue
                
            # Skip known non-target files
            if agent == 'heralding' and 'log_session.csv' in filepath.name:
                continue 
            
            # Print once per processed combination to preserve logging behavior
            if (agent, instance) not in seen_instances:
                print(f"Processing {agent}/{instance}...")
                seen_instances.add((agent, instance))
            
            # Clever SQL skip: check if the first event of this file already exists in DB
            if is_file_processed(filepath, agent, instance, cursor):
                files_skipped += 1
                continue

            recs, rs, er = process_file(filepath, agent, instance, cowrie_sessions)
            total_rs += rs
            total_er += er
            batch.extend(recs)
            
            if len(batch) >= 50000:
                cursor.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                total_inserted += cursor.rowcount
                conn.commit()
                batch = []
                
    # Insert remaining
    if batch:
        cursor.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
        total_inserted += cursor.rowcount
        conn.commit()

    conn.close()
    print("=== Normalization Complete ===")
    print(f"Total Raw Lines Processed (Rs): {total_rs}")
    print(f"Total Inserted Events (Ne): {total_inserted}")
    print(f"Total Errors/Skipped (Er): {total_er}")
    print(f"Files completely skipped (unmodified): {files_skipped}")
    print(f"Rs == Ne + Er : {total_rs == (total_inserted + total_er)} (Note: INSERT OR IGNORE skips dupes, so Ne is distinct count)")

if __name__ == '__main__':
    run()
