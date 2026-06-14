"""
Deep Analyzer for Honeypot Normalized Data
Runs comprehensive queries against honeypot_normalized.db to answer
all of Recep's questions with full data evidence and methodology.
"""
import sqlite3
import json
from collections import defaultdict

DB_PATH = r"C:\honeypots-normalization\honeypot_normalized.db"
OUT_PATH = r"C:\honeypots-normalization\docs\deep_analysis_results.json"

def run():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    results = {}

    # ============================================================
    # Q1: How much data do you currently have per honeypot?
    # ============================================================
    print("[Q1] Data volume per honeypot...")
    
    # Total events per sensor_type
    c.execute("SELECT sensor_type, COUNT(*) as cnt FROM events GROUP BY sensor_type ORDER BY cnt DESC")
    results['q1_total_per_type'] = [dict(r) for r in c.fetchall()]
    
    # Events per sensor_instance
    c.execute("SELECT sensor_instance, sensor_type, COUNT(*) as cnt FROM events GROUP BY sensor_instance ORDER BY cnt DESC")
    results['q1_per_instance'] = [dict(r) for r in c.fetchall()]
    
    # Date range per sensor
    c.execute("SELECT sensor_type, MIN(timestamp) as earliest, MAX(timestamp) as latest FROM events GROUP BY sensor_type")
    results['q1_date_ranges'] = [dict(r) for r in c.fetchall()]
    
    # Events per category per sensor
    c.execute("""
        SELECT sensor_type, event_category, COUNT(*) as cnt 
        FROM events 
        GROUP BY sensor_type, event_category 
        ORDER BY sensor_type, cnt DESC
    """)
    results['q1_category_breakdown'] = [dict(r) for r in c.fetchall()]
    
    # Unique source IPs per sensor
    c.execute("SELECT sensor_type, COUNT(DISTINCT src_ip) as unique_ips FROM events GROUP BY sensor_type ORDER BY unique_ips DESC")
    results['q1_unique_ips_per_sensor'] = [dict(r) for r in c.fetchall()]

    # ============================================================
    # Q2: Which honeypot produces the most useful data and why?
    # ============================================================
    print("[Q2] Useful data analysis...")
    
    # "Useful" = authentication_attempt, command_execution, payload_delivery
    c.execute("""
        SELECT sensor_type, 
               COUNT(*) as total,
               SUM(CASE WHEN event_category IN ('authentication_attempt','command_execution','payload_delivery') THEN 1 ELSE 0 END) as useful,
               ROUND(100.0 * SUM(CASE WHEN event_category IN ('authentication_attempt','command_execution','payload_delivery') THEN 1 ELSE 0 END) / COUNT(*), 2) as useful_pct
        FROM events 
        GROUP BY sensor_type 
        ORDER BY useful DESC
    """)
    results['q2_useful_data'] = [dict(r) for r in c.fetchall()]

    # Sample cowrie command_execution payloads (top diversity)
    c.execute("""
        SELECT payload, COUNT(*) as cnt, COUNT(DISTINCT src_ip) as ips
        FROM events 
        WHERE sensor_type = 'cowrie' AND event_category = 'command_execution' AND payload != ''
        GROUP BY payload
        ORDER BY cnt DESC
        LIMIT 10
    """)
    results['q2_cowrie_top_commands'] = [dict(r) for r in c.fetchall()]

    # ============================================================
    # Q3: Which honeypot produces mostly noise?
    # ============================================================
    print("[Q3] Noise analysis...")
    
    c.execute("""
        SELECT sensor_type,
               SUM(CASE WHEN event_category = 'connection_established' THEN 1 ELSE 0 END) as noise_events,
               COUNT(*) as total,
               ROUND(100.0 * SUM(CASE WHEN event_category = 'connection_established' THEN 1 ELSE 0 END) / COUNT(*), 2) as noise_pct
        FROM events
        GROUP BY sensor_type
        ORDER BY noise_pct DESC
    """)
    results['q3_noise'] = [dict(r) for r in c.fetchall()]

    # Also check cowrie 'other' category
    c.execute("""
        SELECT sensor_type, event_category, COUNT(*) as cnt
        FROM events
        WHERE event_category = 'other'
        GROUP BY sensor_type, event_category
    """)
    results['q3_other_category'] = [dict(r) for r in c.fetchall()]

    # ============================================================
    # Q5: Which IPs hit multiple honeypots?
    # ============================================================
    print("[Q5] Cross-sensor IPs...")
    
    # Full count of how many IPs hit N sensors
    c.execute("""
        SELECT sensor_count, COUNT(*) as ip_count FROM (
            SELECT src_ip, COUNT(DISTINCT sensor_type) as sensor_count
            FROM events
            GROUP BY src_ip
        ) GROUP BY sensor_count ORDER BY sensor_count DESC
    """)
    results['q5_ip_sensor_distribution'] = [dict(r) for r in c.fetchall()]

    # Top 20 IPs hitting most sensors, with event counts per sensor
    c.execute("""
        SELECT src_ip, MAX(src_country) as src_country, COUNT(DISTINCT sensor_type) as sensor_count, 
               GROUP_CONCAT(DISTINCT sensor_type) as sensors,
               COUNT(*) as total_events,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen
        FROM events
        GROUP BY src_ip
        HAVING sensor_count > 1
        ORDER BY sensor_count DESC, total_events DESC
        LIMIT 30
    """)
    results['q5_top_multi_sensor_ips'] = [dict(r) for r in c.fetchall()]

    # For the top 5 cross-sensor IPs, get their per-sensor breakdown
    c.execute("""
        SELECT src_ip, sensor_type, event_category, COUNT(*) as cnt
        FROM events
        WHERE src_ip IN (
            SELECT src_ip FROM events GROUP BY src_ip HAVING COUNT(DISTINCT sensor_type) = 4 LIMIT 5
        )
        GROUP BY src_ip, sensor_type, event_category
        ORDER BY src_ip, sensor_type
    """)
    results['q5_top5_detail'] = [dict(r) for r in c.fetchall()]

    # ============================================================
    # Q6: Which events look automated?
    # ============================================================
    print("[Q6] Automation profiling...")
    
    # High-frequency identical payloads from single IPs
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

    # IPs with extremely high event counts (bot-like behavior)
    c.execute("""
        SELECT src_ip, MAX(src_country) as src_country, sensor_type, COUNT(*) as total_events,
               COUNT(DISTINCT payload) as unique_payloads,
               MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
        FROM events
        WHERE payload != ''
        GROUP BY src_ip, sensor_type
        HAVING total_events > 1000
        ORDER BY total_events DESC
        LIMIT 15
    """)
    results['q6_high_volume_ips'] = [dict(r) for r in c.fetchall()]

    # Ratio analysis: IPs with high event count but very low payload diversity
    c.execute("""
        SELECT src_ip, sensor_type, COUNT(*) as total,
               COUNT(DISTINCT payload) as unique_payloads,
               ROUND(1.0 * COUNT(*) / MAX(COUNT(DISTINCT payload), 1), 1) as repetition_ratio
        FROM events
        WHERE payload != ''
        GROUP BY src_ip, sensor_type
        HAVING total > 500 AND repetition_ratio > 100
        ORDER BY repetition_ratio DESC
        LIMIT 10
    """)
    results['q6_high_repetition_ratio'] = [dict(r) for r in c.fetchall()]

    # ============================================================
    # Q7: Which sessions look more interactive?
    # ============================================================
    print("[Q7] Interactive session detection...")
    
    # Sessions with most unique commands (Cowrie)
    c.execute("""
        SELECT session_id, src_ip, MAX(src_country) as src_country,
               COUNT(*) as total_cmds,
               COUNT(DISTINCT payload) as unique_cmds,
               MIN(timestamp) as session_start,
               MAX(timestamp) as session_end
        FROM events
        WHERE sensor_type = 'cowrie' AND event_category = 'command_execution' AND payload != ''
        GROUP BY session_id, src_ip
        HAVING unique_cmds > 5
        ORDER BY unique_cmds DESC
        LIMIT 15
    """)
    results['q7_interactive_sessions'] = [dict(r) for r in c.fetchall()]
    
    # Get actual commands from the top interactive session
    top_session_rows = results['q7_interactive_sessions']
    if top_session_rows:
        top_sid = top_session_rows[0]['session_id']
        c.execute("""
            SELECT timestamp, payload
            FROM events
            WHERE session_id = ? AND sensor_type = 'cowrie' AND event_category = 'command_execution' AND payload != ''
            ORDER BY timestamp
            LIMIT 30
        """, (top_sid,))
        results['q7_top_session_commands'] = [dict(r) for r in c.fetchall()]
    
    # Heralding sessions with many auth attempts (could be interactive brute force)
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

    # ============================================================
    # Q8: Which payloads repeat?
    # ============================================================
    print("[Q8] Payload recurrence...")
    
    # Top repeating payloads globally
    c.execute("""
        SELECT payload, event_category, COUNT(*) as total_hits,
               COUNT(DISTINCT src_ip) as unique_ips,
               COUNT(DISTINCT sensor_type) as sensor_count,
               GROUP_CONCAT(DISTINCT sensor_type) as sensors,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen
        FROM events
        WHERE payload != '' AND payload IS NOT NULL
        GROUP BY payload
        HAVING total_hits > 50
        ORDER BY total_hits DESC
        LIMIT 20
    """)
    results['q8_top_payloads'] = [dict(r) for r in c.fetchall()]

    # Top brute-force credential pairs across cowrie AND heralding
    c.execute("""
        SELECT payload, COUNT(*) as cnt, COUNT(DISTINCT src_ip) as ips,
               GROUP_CONCAT(DISTINCT sensor_type) as sensors
        FROM events
        WHERE event_category = 'authentication_attempt' AND payload LIKE '%:%'
        GROUP BY payload
        ORDER BY cnt DESC
        LIMIT 15
    """)
    results['q8_top_credentials'] = [dict(r) for r in c.fetchall()]

    # Payloads appearing across MULTIPLE sensor types
    c.execute("""
        SELECT payload, COUNT(DISTINCT sensor_type) as sensor_count,
               GROUP_CONCAT(DISTINCT sensor_type) as sensors,
               COUNT(*) as total,
               COUNT(DISTINCT src_ip) as ips
        FROM events
        WHERE payload != ''
        GROUP BY payload
        HAVING sensor_count > 1
        ORDER BY total DESC
        LIMIT 15
    """)
    results['q8_cross_sensor_payloads'] = [dict(r) for r in c.fetchall()]

    # ============================================================
    # Q9: Which attacker patterns appear across more than one sensor?
    # ============================================================
    print("[Q9] Multi-vector attacker patterns...")
    
    # IPs hitting 3+ sensors with behavior detail
    c.execute("""
        SELECT src_ip, 
               COUNT(DISTINCT sensor_type) as sensors_hit,
               GROUP_CONCAT(DISTINCT sensor_type) as sensor_list,
               GROUP_CONCAT(DISTINCT event_category) as categories,
               COUNT(*) as total_events,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen
        FROM events
        GROUP BY src_ip
        HAVING sensors_hit >= 3
        ORDER BY sensors_hit DESC, total_events DESC
        LIMIT 20
    """)
    results['q9_multi_vector_attackers'] = [dict(r) for r in c.fetchall()]
    
    # Detailed timeline for the top multi-vector IP
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

    # ============================================================
    # Q10: Most interesting finding
    # ============================================================
    print("[Q10] Interesting findings...")
    
    # The mdrfckr SSH key backdoor stats
    c.execute("""
        SELECT COUNT(*) as hits, COUNT(DISTINCT src_ip) as unique_ips,
               MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
        FROM events
        WHERE payload LIKE '%mdrfckr%'
    """)
    results['q10_mdrfckr_stats'] = dict(c.fetchone())
    
    # Top IPs deploying the mdrfckr key
    c.execute("""
        SELECT src_ip, COUNT(*) as hits, MIN(timestamp) as first, MAX(timestamp) as last
        FROM events
        WHERE payload LIKE '%mdrfckr%'
        GROUP BY src_ip
        ORDER BY hits DESC
        LIMIT 5
    """)
    results['q10_mdrfckr_top_ips'] = [dict(r) for r in c.fetchall()]

    # Top Mirai-like credentials
    c.execute("""
        SELECT payload, COUNT(*) as cnt, COUNT(DISTINCT src_ip) as ips
        FROM events
        WHERE event_category = 'authentication_attempt' 
          AND payload IN ('root:xc3511','root:vizxv','root:admin','admin:admin','root:default',
                          'root:root','root:1234','root:12345','root:password','root:123456',
                          '345gs5662d34:345gs5662d34','root:54321','root:888888')
        GROUP BY payload
        ORDER BY cnt DESC
    """)
    results['q10_mirai_credentials'] = [dict(r) for r in c.fetchall()]

    # ============================================================
    # Q11: Human/Manual attack interaction and Country stats
    # ============================================================
    print("[Q11] Human/Manual attack detection & Geolocation...")
    
    # Country percentages
    c.execute("""
        SELECT src_country, 
               COUNT(*) as total_attacks,
               ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM events WHERE src_country IS NOT NULL), 2) as pct
        FROM events
        WHERE src_country IS NOT NULL
        GROUP BY src_country
        ORDER BY total_attacks DESC
        LIMIT 15
    """)
    results['q11_country_distribution'] = [dict(r) for r in c.fetchall()]

    # Flag sessions for possible human/manual attack interaction based on signals
    c.execute("""
        SELECT session_id, src_ip, MAX(src_country) as src_country, sensor_type,
               COUNT(DISTINCT payload) as unique_cmds,
               (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400.0 as duration_sec,
               GROUP_CONCAT(payload, ' | ') as cmd_sequence
        FROM events
        WHERE sensor_type = 'cowrie' AND event_category = 'command_execution' AND payload != ''
        GROUP BY session_id, src_ip
        HAVING (duration_sec > 30 AND unique_cmds > 3) 
            OR cmd_sequence LIKE '%nano%'
            OR cmd_sequence LIKE '%vi %'
            OR cmd_sequence LIKE '%top%'
            OR cmd_sequence LIKE '%ping%'
        ORDER BY duration_sec DESC
        LIMIT 30
    """)
    flagged = []
    for r in c.fetchall():
        d = dict(r)
        reason = []
        if d['duration_sec'] and d['duration_sec'] > 30 and d['unique_cmds'] > 3:
            reason.append("Timing/Interactive (Duration > 30s, Unique cmds > 3)")
        if any(x in (d['cmd_sequence'] or "") for x in ['nano', 'vi ', 'top', 'ping']):
            reason.append("Interactive-shell artifacts (nano/vi/top/ping)")
        d['flag_reason'] = " + ".join(reason) if reason else "Manual interaction signals"
        flagged.append(d)
    results['q11_human_manual_sessions'] = flagged

    # ============================================================
    # VALIDATION BLOCK
    # ============================================================
    print("[VALIDATION] Running integrity checks...")
    
    # Total record count
    c.execute("SELECT COUNT(*) FROM events")
    results['validation_total_records'] = c.fetchone()[0]
    
    # Schema integrity: null checks on mandatory fields
    c.execute("""
        SELECT 
            SUM(CASE WHEN src_ip IS NULL OR src_ip = '' THEN 1 ELSE 0 END) as null_src_ip,
            SUM(CASE WHEN timestamp IS NULL OR timestamp = '' THEN 1 ELSE 0 END) as null_timestamp,
            SUM(CASE WHEN sensor_type IS NULL OR sensor_type = '' THEN 1 ELSE 0 END) as null_sensor_type,
            SUM(CASE WHEN event_category IS NULL OR event_category = '' THEN 1 ELSE 0 END) as null_category
        FROM events
    """)
    results['validation_nulls'] = dict(c.fetchone())
    
    # Distinct event categories
    c.execute("SELECT DISTINCT event_category FROM events ORDER BY event_category")
    results['validation_categories'] = [r[0] for r in c.fetchall()]
    
    # Distinct sensor types
    c.execute("SELECT DISTINCT sensor_type FROM events ORDER BY sensor_type")
    results['validation_sensor_types'] = [r[0] for r in c.fetchall()]

    conn.close()
    
    with open(OUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"Deep analysis complete. Results written to {OUT_PATH}")

if __name__ == '__main__':
    run()
