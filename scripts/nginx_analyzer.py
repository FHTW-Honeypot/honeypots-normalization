"""
Nginx Deep Analyzer — Honeypot Normalized Data
=================================================
Runs targeted SQL queries against honeypot_normalized.db restricted
exclusively to the nginx sensor, answering 20 creative forensic questions
about HTTP-based attack behaviour observed by the honeypot.

Output: scripts-out/nginx_analyzer_results.json
"""

import sqlite3
import json
import os
from collections import defaultdict
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH  = BASE_DIR / "honeypot_normalized.db"
OUT_PATH = BASE_DIR / "scripts-out" / "nginx_analyzer_results.json"

# Environment-variable overrides (handy on different OSes / CI)
DB_PATH  = Path(os.environ.get("HONEYPOT_DB", str(DB_PATH)))
OUT_PATH = Path(os.environ.get("NGINX_OUT",   str(OUT_PATH)))


# ── Helper ────────────────────────────────────────────────────────────────────
def rows(cursor):
    """Return all fetched sqlite3.Row objects as plain dicts."""
    return [dict(r) for r in cursor.fetchall()]


def run():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    results: dict = {}

    # ════════════════════════════════════════════════════════════════════════
    # Q1 · OVERVIEW — How big is the nginx dataset?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q1] Nginx dataset overview …")

    c.execute("""
        SELECT COUNT(*)               AS total_events,
               COUNT(DISTINCT src_ip) AS unique_ips,
               MIN(timestamp)         AS earliest,
               MAX(timestamp)         AS latest
        FROM   events
        WHERE  sensor_type = 'nginx'
    """)
    results["q1_overview"] = dict(c.fetchone())

    c.execute("""
        SELECT sensor_instance,
               COUNT(*)               AS total_events,
               COUNT(DISTINCT src_ip) AS unique_ips,
               MIN(timestamp)         AS earliest,
               MAX(timestamp)         AS latest
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY sensor_instance
        ORDER  BY total_events DESC
    """)
    results["q1_per_instance"] = rows(c)

    # Daily request volume — activity fluctuation over the observation period
    c.execute("""
        SELECT SUBSTR(timestamp, 1, 10) AS day,
               COUNT(*)                 AS requests,
               COUNT(DISTINCT src_ip)   AS unique_ips
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY day
        ORDER  BY day ASC
    """)
    results["q1_daily_volume"] = rows(c)

    # Hourly UTC heatmap — what time of day do attackers prefer?
    c.execute("""
        SELECT CAST(SUBSTR(timestamp, 12, 2) AS INTEGER) AS hour_utc,
               COUNT(*) AS requests
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  LENGTH(timestamp) >= 14
        GROUP  BY hour_utc
        ORDER  BY hour_utc ASC
    """)
    results["q1_hourly_heatmap"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q2 · GEOGRAPHY — Which countries are probing our HTTP server?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q2] Geographic origin of nginx attackers …")

    c.execute("""
        SELECT src_country,
               COUNT(*)               AS total_requests,
               COUNT(DISTINCT src_ip) AS unique_ips,
               ROUND(100.0 * COUNT(*) /
                     (SELECT COUNT(*) FROM events
                      WHERE sensor_type = 'nginx'
                        AND src_country IS NOT NULL), 2) AS pct
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  src_country IS NOT NULL
        GROUP  BY src_country
        ORDER  BY total_requests DESC
        LIMIT  20
    """)
    results["q2_country_distribution"] = rows(c)

    # Most prolific IP per country
    c.execute("""
        SELECT src_country, src_ip, COUNT(*) AS requests
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  src_country IS NOT NULL
        GROUP  BY src_country, src_ip
        HAVING requests = (
            SELECT MAX(cnt)
            FROM (
                SELECT COUNT(*) AS cnt
                FROM   events e2
                WHERE  e2.sensor_type = 'nginx'
                  AND  e2.src_country = events.src_country
                GROUP  BY e2.src_ip
            )
        )
        ORDER  BY requests DESC
        LIMIT  15
    """)
    results["q2_top_ip_per_country"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q3 · HTTP METHODS — Are attackers using exotic HTTP verbs?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q3] HTTP method distribution …")

    c.execute("""
        SELECT UPPER(TRIM(SUBSTR(payload, 1,
                   CASE WHEN INSTR(payload, ' ') = 0
                        THEN LENGTH(payload)
                        ELSE INSTR(payload, ' ') - 1
                   END
               )))                    AS http_method,
               COUNT(*)               AS requests,
               COUNT(DISTINCT src_ip) AS unique_ips
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  payload IS NOT NULL AND payload != ''
        GROUP  BY http_method
        ORDER  BY requests DESC
    """)
    results["q3_http_methods"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q4 · MOST SCANNED PATHS — Which URIs are attackers hunting?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q4] Most targeted URI payloads …")

    c.execute("""
        SELECT payload,
               COUNT(*)               AS total_hits,
               COUNT(DISTINCT src_ip) AS unique_ips,
               MIN(timestamp)         AS first_seen,
               MAX(timestamp)         AS last_seen
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  payload IS NOT NULL AND payload != ''
        GROUP  BY payload
        ORDER  BY total_hits DESC
        LIMIT  25
    """)
    results["q4_top_payloads"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q5 · EXPLOIT FINGERPRINTING — Which known CVE/bug families appear?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q5] Exploit / vulnerability probe fingerprinting …")

    exploit_signatures = {
        "PHPUnit_remote_exec":       ["phpunit", "eval-stdin"],
        "DotEnv_credential_leak":    ["/.env", ".env.bak", ".env.local"],
        "Git_repo_disclosure":       ["/.git/", ".git/HEAD", ".gitignore"],
        "PHP_RFI_ThinkPHP":          ["thinkphp", "invokefunction"],
        "Webshell_upload_probe":     ["/shell", "/cmd", "/c99", "/r57", "webshell"],
        "WordPress_attack":          ["/wp-login", "/wp-admin", "/xmlrpc.php", "/wp-includes"],
        "Log4Shell_JNDI":            ["jndi:", "${jndi"],
        "Spring4Shell":              ["class.module.classLoader", "spring.xml"],
        "SSRF_metadata_probe":       ["169.254.169.254", "metadata.internal"],
        "Path_traversal":            ["../", "..%2F", "%2e%2e"],
        "Actuator_exposure":         ["/actuator", "/health", "/metrics", "/jolokia"],
        "Admin_panel_hunt":          ["/admin", "/administrator", "/phpmyadmin", "/pma"],
        "WebDAV_PROPFIND":           ["PROPFIND"],
        "XMLRPC_bruteforce":         ["xmlrpc.php"],
        "Shellshock":                ["() {", "() { :;};"],
    }

    exploit_rows = []
    for family, sigs in exploit_signatures.items():
        clauses = " OR ".join(
            "LOWER(payload) LIKE '%" + s.lower().replace("'", "''") + "%'"
            for s in sigs
        )
        c.execute("""
            SELECT COUNT(*)               AS hits,
                   COUNT(DISTINCT src_ip) AS unique_ips,
                   MIN(timestamp)         AS first_seen,
                   MAX(timestamp)         AS last_seen
            FROM   events
            WHERE  sensor_type = 'nginx'
              AND  (""" + clauses + ")")
        row = dict(c.fetchone())
        row["family"] = family
        row["signatures"] = sigs
        exploit_rows.append(row)

    exploit_rows.sort(key=lambda x: x["hits"], reverse=True)
    results["q5_exploit_families"] = exploit_rows

    # Sample top-10 raw payloads from the most-hit exploit family
    if exploit_rows and exploit_rows[0]["hits"] > 0:
        top_sigs = exploit_rows[0]["signatures"]
        clauses2 = " OR ".join(
            "LOWER(payload) LIKE '%" + s.lower().replace("'", "''") + "%'"
            for s in top_sigs
        )
        c.execute("""
            SELECT payload,
                   COUNT(*)               AS hits,
                   COUNT(DISTINCT src_ip) AS unique_ips
            FROM   events
            WHERE  sensor_type = 'nginx'
              AND  (""" + clauses2 + """)
            GROUP  BY payload
            ORDER  BY hits DESC
            LIMIT  10
        """)
        results["q5_top_family_payloads"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q6 · USER-AGENT INTELLIGENCE — Who/what tool is doing the scanning?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q6] User-agent intelligence …")

    c.execute("""
        SELECT raw_data
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  raw_data IS NOT NULL AND raw_data != ''
    """)

    ua_tracker: dict = defaultdict(lambda: {"requests": 0, "ips": set()})
    for (raw,) in c.fetchall():
        try:
            obj = json.loads(raw)
            ua  = obj.get("user_agent", "").strip() or "(empty)"
            ip  = obj.get("src_ip", "")
        except Exception:
            continue
        ua_tracker[ua]["requests"] += 1
        ua_tracker[ua]["ips"].add(ip)

    ua_sorted = sorted(
        [{"user_agent": ua, "requests": v["requests"], "unique_ips": len(v["ips"])}
         for ua, v in ua_tracker.items()],
        key=lambda x: x["requests"], reverse=True
    )
    results["q6_top_user_agents"] = ua_sorted[:25]

    # Tool-bucket classification
    scanner_map = {
        "zgrab (internet-wide scanner)": ["zgrab"],
        "Nuclei vulnerability scanner":  ["nuclei", "projectdiscovery"],
        "Masscan":                        ["masscan"],
        "Go HTTP client (generic bots)":  ["go-http-client"],
        "Python requests / urllib":       ["python-requests", "python-urllib"],
        "curl":                           ["curl/"],
        "wget":                           ["wget/"],
        "Shodan crawler":                 ["shodan"],
        "Censys crawler":                 ["censys"],
        "Nmap scripting engine":          ["nmap"],
        "Empty / custom UA":              ["(empty)"],
        "Acunetix":                       ["acunetix"],
        "Nikto":                          ["nikto"],
    }
    tool_buckets: dict = defaultdict(lambda: {"requests": 0, "ips": set()})
    for ua, v in ua_tracker.items():
        matched = False
        for tool, patterns in scanner_map.items():
            if any(p.lower() in ua.lower() for p in patterns):
                tool_buckets[tool]["requests"] += v["requests"]
                tool_buckets[tool]["ips"]      |= v["ips"]
                matched = True
                break
        if not matched:
            tool_buckets["Unknown / browser-like"]["requests"] += v["requests"]
            tool_buckets["Unknown / browser-like"]["ips"]      |= v["ips"]

    results["q6_ua_tool_buckets"] = sorted(
        [{"tool": t, "requests": v["requests"], "unique_ips": len(v["ips"])}
         for t, v in tool_buckets.items()],
        key=lambda x: x["requests"], reverse=True
    )

    # ════════════════════════════════════════════════════════════════════════
    # Q7 · SCANNER PERSISTENCE — Which IPs return over many separate days?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q7] Scanner persistence …")

    c.execute("""
        SELECT src_ip,
               MAX(src_country)                        AS src_country,
               COUNT(*)                                AS total_requests,
               COUNT(DISTINCT SUBSTR(timestamp, 1, 10)) AS active_days,
               MIN(timestamp)                          AS first_seen,
               MAX(timestamp)                          AS last_seen,
               ROUND(julianday(MAX(timestamp)) - julianday(MIN(timestamp)), 1) AS span_days
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY src_ip
        HAVING active_days >= 5
        ORDER  BY active_days DESC, total_requests DESC
        LIMIT  20
    """)
    results["q7_persistent_scanners"] = rows(c)

    # Stealthy slow scanners — many distinct days, very low daily volume
    c.execute("""
        SELECT src_ip,
               MAX(src_country)                        AS src_country,
               COUNT(*)                                AS total_requests,
               COUNT(DISTINCT SUBSTR(timestamp, 1, 10)) AS active_days,
               ROUND(1.0 * COUNT(*) /
                     COUNT(DISTINCT SUBSTR(timestamp, 1, 10)), 2) AS avg_per_day
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY src_ip
        HAVING active_days >= 7
           AND avg_per_day < 5
        ORDER  BY active_days DESC
        LIMIT  15
    """)
    results["q7_stealthy_slow_scanners"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q8 · BURST BEHAVIOUR — Which IPs send many requests in a short window?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q8] Burst / request-rate analysis …")

    c.execute("""
        SELECT src_ip,
               MAX(src_country) AS src_country,
               COUNT(*)          AS total_requests,
               MIN(timestamp)    AS first_seen,
               MAX(timestamp)    AS last_seen,
               ROUND((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400.0, 1)
                                 AS duration_seconds,
               ROUND(COUNT(*) / MAX(
                   (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400.0, 1
               ), 2)             AS requests_per_second
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY src_ip
        HAVING total_requests > 50
           AND requests_per_second > 0.5
        ORDER  BY requests_per_second DESC
        LIMIT  15
    """)
    results["q8_burst_attackers"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q9 · PAYLOAD DIVERSITY — Broad scanners vs. targeted hammering
    # ════════════════════════════════════════════════════════════════════════
    print("[Q9] Payload diversity analysis …")

    c.execute("""
        SELECT src_ip,
               MAX(src_country)        AS src_country,
               COUNT(*)                AS total_requests,
               COUNT(DISTINCT payload) AS unique_payloads,
               ROUND(1.0 * COUNT(DISTINCT payload) / COUNT(*), 3) AS diversity_ratio
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  payload IS NOT NULL AND payload != ''
        GROUP  BY src_ip
        HAVING total_requests >= 10
        ORDER  BY unique_payloads DESC
        LIMIT  20
    """)
    results["q9_broad_scanners"] = rows(c)

    c.execute("""
        SELECT src_ip,
               MAX(src_country)        AS src_country,
               COUNT(*)                AS total_requests,
               COUNT(DISTINCT payload) AS unique_payloads,
               ROUND(1.0 * COUNT(*) / MAX(COUNT(DISTINCT payload), 1), 1) AS repetition_ratio
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  payload IS NOT NULL AND payload != ''
        GROUP  BY src_ip
        HAVING total_requests > 20
           AND repetition_ratio > 10
        ORDER  BY repetition_ratio DESC
        LIMIT  15
    """)
    results["q9_targeted_hammering"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q10 · MULTI-SENSOR CORRELATION — Did nginx IPs also hit SSH/telnet?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q10] Multi-sensor correlation …")

    c.execute("""
        SELECT e.src_ip,
               MAX(e.src_country)               AS src_country,
               n.nginx_hits,
               COUNT(DISTINCT e.sensor_type)    AS total_sensors,
               GROUP_CONCAT(DISTINCT e.sensor_type) AS sensors,
               COUNT(*)                         AS total_events
        FROM   events e
        JOIN (
            SELECT src_ip, COUNT(*) AS nginx_hits
            FROM   events
            WHERE  sensor_type = 'nginx'
            GROUP  BY src_ip
        ) n ON n.src_ip = e.src_ip
        GROUP  BY e.src_ip
        HAVING total_sensors > 1
        ORDER  BY total_sensors DESC, nginx_hits DESC
        LIMIT  25
    """)
    results["q10_multi_sensor_nginx_ips"] = rows(c)

    # IPs that ONLY appeared on nginx
    c.execute("""
        SELECT src_ip,
               MAX(src_country) AS src_country,
               COUNT(*)          AS nginx_requests
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  src_ip NOT IN (
              SELECT DISTINCT src_ip
              FROM   events
              WHERE  sensor_type != 'nginx'
          )
        GROUP  BY src_ip
        ORDER  BY nginx_requests DESC
        LIMIT  20
    """)
    results["q10_nginx_exclusive_ips"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q11 · ATTACK TYPE BREAKDOWN — Automated vs. uncertain classification
    # ════════════════════════════════════════════════════════════════════════
    print("[Q11] Attack type breakdown …")

    c.execute("""
        SELECT attack_type,
               COUNT(*)               AS events,
               COUNT(DISTINCT src_ip) AS unique_ips,
               ROUND(100.0 * COUNT(*) /
                     (SELECT COUNT(*) FROM events WHERE sensor_type = 'nginx'), 2) AS pct
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY attack_type
        ORDER  BY events DESC
    """)
    results["q11_attack_types"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q12 · FIRST-HIT PATH — What URI does each attacker probe first?
    #       Reveals the scanner playbook / execution order
    # ════════════════════════════════════════════════════════════════════════
    print("[Q12] First-hit path / scanner playbook reconstruction …")

    c.execute("""
        SELECT src_ip,
               MIN(timestamp) AS first_request_time,
               payload        AS first_payload
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  payload IS NOT NULL AND payload != ''
          AND  timestamp = (
              SELECT MIN(timestamp)
              FROM   events e2
              WHERE  e2.sensor_type = 'nginx'
                AND  e2.src_ip = events.src_ip
          )
        GROUP  BY src_ip
        LIMIT  500
    """)
    raw_first = rows(c)

    first_payload_counts: dict = defaultdict(int)
    for row in raw_first:
        first_payload_counts[row["first_payload"]] += 1

    results["q12_top_first_probe_payloads"] = sorted(
        [{"payload": p, "ip_count": cnt}
         for p, cnt in first_payload_counts.items()],
        key=lambda x: x["ip_count"], reverse=True
    )[:20]

    # ════════════════════════════════════════════════════════════════════════
    # Q13 · TEMPORAL PATTERNS — Day-of-week rhythm of HTTP attacks
    # ════════════════════════════════════════════════════════════════════════
    print("[Q13] Day-of-week attack rhythm …")

    c.execute("""
        SELECT CASE CAST(strftime('%w', timestamp) AS INTEGER)
                    WHEN 0 THEN 'Sunday'
                    WHEN 1 THEN 'Monday'
                    WHEN 2 THEN 'Tuesday'
                    WHEN 3 THEN 'Wednesday'
                    WHEN 4 THEN 'Thursday'
                    WHEN 5 THEN 'Friday'
                    WHEN 6 THEN 'Saturday'
               END                    AS weekday,
               CAST(strftime('%w', timestamp) AS INTEGER) AS weekday_num,
               COUNT(*)               AS requests,
               COUNT(DISTINCT src_ip) AS unique_ips
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY weekday_num
        ORDER  BY weekday_num ASC
    """)
    results["q13_weekday_distribution"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q14 · PORT TARGETING — Are attackers hitting non-standard ports?
    # ════════════════════════════════════════════════════════════════════════
    print("[Q14] Destination port analysis …")

    c.execute("""
        SELECT dst_port,
               COUNT(*)               AS requests,
               COUNT(DISTINCT src_ip) AS unique_ips
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  dst_port IS NOT NULL
        GROUP  BY dst_port
        ORDER  BY requests DESC
    """)
    results["q14_dst_ports"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q15 · CAMPAIGN HUNTING — Payloads shared by many IPs = coordinated waves
    # ════════════════════════════════════════════════════════════════════════
    print("[Q15] Coordinated campaign detection …")

    c.execute("""
        SELECT payload,
               COUNT(DISTINCT src_ip) AS ip_count,
               COUNT(*)               AS total_hits,
               MIN(timestamp)         AS first_seen,
               MAX(timestamp)         AS last_seen
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  payload IS NOT NULL AND payload != ''
        GROUP  BY payload
        HAVING ip_count >= 10
        ORDER  BY ip_count DESC
        LIMIT  20
    """)
    results["q15_campaign_payloads"] = rows(c)

    # Same payload, same day, by 5+ different IPs → burst campaign
    c.execute("""
        SELECT SUBSTR(timestamp, 1, 10) AS day,
               payload,
               COUNT(DISTINCT src_ip)   AS ip_count,
               COUNT(*)                 AS hits
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  payload IS NOT NULL AND payload != ''
        GROUP  BY day, payload
        HAVING ip_count >= 5
        ORDER  BY ip_count DESC, hits DESC
        LIMIT  20
    """)
    results["q15_daily_campaign_bursts"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q16 · HTTP VERSION USAGE — Old-school HTTP/1.0 often means bare scanners
    # ════════════════════════════════════════════════════════════════════════
    print("[Q16] HTTP version distribution …")

    c.execute("""
        SELECT TRIM(SUBSTR(payload, INSTR(payload, ' HTTP/') + 1)) AS http_version,
               COUNT(*)               AS requests,
               COUNT(DISTINCT src_ip) AS unique_ips
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  payload LIKE '% HTTP/%'
        GROUP  BY http_version
        ORDER  BY requests DESC
    """)
    results["q16_http_versions"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q17 · ATTACK PATH SPECIALISATION PER COUNTRY
    # ════════════════════════════════════════════════════════════════════════
    print("[Q17] Country-level payload diversity …")

    c.execute("""
        SELECT src_country,
               COUNT(DISTINCT payload) AS unique_payloads,
               COUNT(*)                AS total_requests,
               COUNT(DISTINCT src_ip)  AS unique_ips
        FROM   events
        WHERE  sensor_type = 'nginx'
          AND  src_country IS NOT NULL
          AND  payload IS NOT NULL AND payload != ''
        GROUP  BY src_country
        ORDER  BY unique_payloads DESC
        LIMIT  15
    """)
    results["q17_country_payload_diversity"] = rows(c)

    # ════════════════════════════════════════════════════════════════════════
    # Q18 · DAY-BY-DAY TIMELINE of the 5 busiest nginx IPs
    # ════════════════════════════════════════════════════════════════════════
    print("[Q18] Day-by-day IP timeline …")

    c.execute("""
        SELECT src_ip, COUNT(*) AS cnt
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY src_ip
        ORDER  BY cnt DESC
        LIMIT  5
    """)
    top5_ips = [r["src_ip"] for r in rows(c)]

    timelines = []
    for ip in top5_ips:
        c.execute("""
            SELECT SUBSTR(timestamp, 1, 10) AS day,
                   COUNT(*)                AS requests
            FROM   events
            WHERE  sensor_type = 'nginx'
              AND  src_ip = ?
            GROUP  BY day
            ORDER  BY day ASC
        """, (ip,))
        timelines.append({"src_ip": ip, "daily": rows(c)})
    results["q18_top5_ip_timelines"] = timelines

    # ════════════════════════════════════════════════════════════════════════
    # Q19 · SENSITIVE FILE HUNTING — Credential & config file probes
    # ════════════════════════════════════════════════════════════════════════
    print("[Q19] Sensitive file probe classification …")

    sensitive_categories = {
        "Environment & credentials":
            ["/.env", "/.aws/credentials", "/.ssh/", "id_rsa",
             "/.netrc", "/.docker/config", "/.kube/config"],
        "Backup & archive files":
            [".bak", ".backup", ".old", ".zip", ".tar.gz",
             ".sql", ".dump", ".sql.gz", ".db"],
        "Source code & VCS":
            ["/.git/", "/.svn/", "/.hg/", "/Makefile",
             "/composer.json", "/package.json", "/yarn.lock"],
        "Config files":
            ["config.php", "configuration.php", "settings.py",
             "wp-config.php", "database.yml",
             "application.properties", "secrets.yml"],
        "Log files":
            ["/var/log", "access.log", "error.log",
             "debug.log", "/logs/", "application.log"],
        "PHP info / server diagnostics":
            ["phpinfo", "info.php", "test.php",
             "phptest.php", "/server-info"],
    }

    sensitive_rows = []
    for category, keywords in sensitive_categories.items():
        clauses = " OR ".join(
            "LOWER(payload) LIKE '%" + kw.lower().replace("'", "''") + "%'"
            for kw in keywords
        )
        c.execute("""
            SELECT COUNT(*)               AS hits,
                   COUNT(DISTINCT src_ip) AS unique_ips,
                   MIN(timestamp)         AS first_seen,
                   MAX(timestamp)         AS last_seen
            FROM   events
            WHERE  sensor_type = 'nginx'
              AND  (""" + clauses + ")")
        row = dict(c.fetchone())
        row["category"] = category
        sensitive_rows.append(row)

    results["q19_sensitive_file_probes"] = sorted(
        sensitive_rows, key=lambda x: x["hits"], reverse=True
    )

    # ════════════════════════════════════════════════════════════════════════
    # Q20 · SUMMARY STATISTICS — Quick-reference numbers for the report
    # ════════════════════════════════════════════════════════════════════════
    print("[Q20] Summary statistics …")

    c.execute("""
        SELECT COUNT(DISTINCT src_ip)                  AS total_unique_attackers,
               COUNT(*)                                AS total_requests,
               COUNT(DISTINCT payload)                 AS unique_request_signatures,
               COUNT(DISTINCT SUBSTR(timestamp, 1, 10)) AS active_days
        FROM   events
        WHERE  sensor_type = 'nginx'
    """)
    results["q20_summary"] = dict(c.fetchone())

    c.execute("""
        SELECT attack_type, COUNT(*) AS cnt
        FROM   events
        WHERE  sensor_type = 'nginx'
        GROUP  BY attack_type
    """)
    results["q20_attack_type_split"] = {r["attack_type"]: r["cnt"]
                                         for r in rows(c)}

    conn.close()

    # ── Write JSON output ─────────────────────────────────────────────────
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(str(OUT_PATH), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nNginx analysis complete. Results saved to: {OUT_PATH}")


if __name__ == "__main__":
    run()
