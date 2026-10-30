# Nginx Honeypot — Deep Analysis Report

> **Sensor:** Nginx HTTP Honeypot  
> **Total Requests:** 46,318  
> **Unique Attackers:** 4,537  
> **Observation Period:** 2026-04-08 → 2026-06-21

---

## Table of Contents

1. [Dataset Overview](#1-dataset-overview)
2. [Geographic Origins](#2-geographic-origins)
3. [HTTP Method Distribution](#3-http-method-distribution)
4. [Most Targeted URI Paths](#4-most-targeted-uri-paths)
5. [Exploit / Vulnerability Probe Fingerprinting](#5-exploit--vulnerability-probe-fingerprinting)
6. [User-Agent Intelligence](#6-user-agent-intelligence)
7. [Scanner Persistence & Return Frequency](#7-scanner-persistence--return-frequency)
8. [Burst Behaviour & Request-Rate Analysis](#8-burst-behaviour--request-rate-analysis)
9. [Payload Diversity — Broad Scanners vs. Targeted Hammering](#9-payload-diversity--broad-scanners-vs-targeted-hammering)
10. [Multi-Sensor Correlation](#10-multi-sensor-correlation)
11. [Attack Type Classification](#11-attack-type-classification)
12. [First-Hit Path — Scanner Playbook Reconstruction](#12-first-hit-path--scanner-playbook-reconstruction)
13. [Day-of-Week Attack Rhythm](#13-day-of-week-attack-rhythm)
14. [Destination Port Targeting](#14-destination-port-targeting)
15. [Coordinated Campaign Detection](#15-coordinated-campaign-detection)
16. [HTTP Version Distribution](#16-http-version-distribution)
17. [Country-Level Attack Path Specialisation](#17-country-level-attack-path-specialisation)
18. [Day-by-Day Timeline of Top IPs](#18-day-by-day-timeline-of-top-ips)
19. [Sensitive File & Credential Probe Classification](#19-sensitive-file--credential-probe-classification)
20. [Summary Statistics](#20-summary-statistics)

---
## 1. Dataset Overview

**How big is the nginx honeypot dataset, and how is it distributed over time?**

| Metric | Value |
|:---|---:|
| Total Requests | **46,318** |
| Unique Attacker IPs | **4,537** |
| Unique Request Signatures | **5,924** |
| Active Observation Days | **57** |
| Earliest Event | `2026-04-08T08:34:58` |
| Latest Event | `2026-06-21T00:04:17` |

### 1.1 Per Sensor-Instance Breakdown

| Sensor Instance | Total Requests | Unique IPs | Active Period |
|:---|---:|---:|:---|
| `sensor-nginx-05` | 25,856 | 2,597 | 2026-05-26 → 2026-06-21 |
| `sensor-nginx-04` | 20,462 | 2,386 | 2026-04-08 → 2026-05-07 |

### 1.2 Daily Request Volume

| Date | Requests | Unique IPs | Volume |
|:---|---:|---:|:---|
| 2026-04-08 | 349 | 64 | `███░░░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-09 | 587 | 128 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-10 | 653 | 123 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-04-11 | 874 | 105 | `████████░░░░░░░░░░░░░░░░░` |
| 2026-04-12 | 523 | 116 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-13 | 541 | 114 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-14 | 603 | 131 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-15 | 380 | 132 | `███░░░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-16 | 769 | 136 | `███████░░░░░░░░░░░░░░░░░░` |
| 2026-04-17 | 753 | 123 | `███████░░░░░░░░░░░░░░░░░░` |
| 2026-04-18 | 369 | 107 | `███░░░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-19 | 444 | 121 | `████░░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-20 | 638 | 129 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-04-21 | 819 | 150 | `███████░░░░░░░░░░░░░░░░░░` |
| 2026-04-22 | 1,819 | 137 | `████████████████░░░░░░░░░` |
| 2026-04-23 | 436 | 158 | `████░░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-24 | 746 | 151 | `███████░░░░░░░░░░░░░░░░░░` |
| 2026-04-25 | 746 | 125 | `███████░░░░░░░░░░░░░░░░░░` |
| 2026-04-26 | 993 | 134 | `█████████░░░░░░░░░░░░░░░░` |
| 2026-04-27 | 1,478 | 135 | `█████████████░░░░░░░░░░░░` |
| 2026-04-28 | 983 | 141 | `█████████░░░░░░░░░░░░░░░░` |
| 2026-04-29 | 624 | 145 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-04-30 | 677 | 147 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-05-01 | 885 | 146 | `████████░░░░░░░░░░░░░░░░░` |
| 2026-05-02 | 640 | 144 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-05-03 | 475 | 122 | `████░░░░░░░░░░░░░░░░░░░░░` |
| 2026-05-04 | 504 | 140 | `████░░░░░░░░░░░░░░░░░░░░░` |
| 2026-05-05 | 466 | 139 | `████░░░░░░░░░░░░░░░░░░░░░` |
| 2026-05-06 | 687 | 138 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-05-07 | 1 | 1 | `░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 2026-05-26 | 188 | 55 | `██░░░░░░░░░░░░░░░░░░░░░░░` |
| 2026-05-27 | 1,445 | 110 | `█████████████░░░░░░░░░░░░` |
| 2026-05-28 | 539 | 141 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-05-29 | 1,990 | 155 | `█████████████████░░░░░░░░` |
| 2026-05-30 | 1,345 | 155 | `████████████░░░░░░░░░░░░░` |
| 2026-05-31 | 741 | 133 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-06-01 | 428 | 138 | `████░░░░░░░░░░░░░░░░░░░░░` |
| 2026-06-02 | 744 | 175 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-06-03 | 568 | 185 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-06-04 | 1,729 | 186 | `███████████████░░░░░░░░░░` |
| 2026-06-05 | 639 | 147 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-06-06 | 477 | 141 | `████░░░░░░░░░░░░░░░░░░░░░` |
| 2026-06-07 | 718 | 137 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-06-08 | 1,232 | 140 | `███████████░░░░░░░░░░░░░░` |
| 2026-06-09 | 616 | 188 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-06-10 | 721 | 149 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-06-11 | 2,867 | 133 | `█████████████████████████` |
| 2026-06-12 | 1,314 | 138 | `███████████░░░░░░░░░░░░░░` |
| 2026-06-13 | 979 | 134 | `█████████░░░░░░░░░░░░░░░░` |
| 2026-06-14 | 1,927 | 149 | `█████████████████░░░░░░░░` |
| 2026-06-15 | 1,314 | 140 | `███████████░░░░░░░░░░░░░░` |
| 2026-06-16 | 565 | 152 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-06-17 | 734 | 162 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-06-18 | 805 | 132 | `███████░░░░░░░░░░░░░░░░░░` |
| 2026-06-19 | 703 | 156 | `██████░░░░░░░░░░░░░░░░░░░` |
| 2026-06-20 | 526 | 145 | `█████░░░░░░░░░░░░░░░░░░░░` |
| 2026-06-21 | 2 | 2 | `░░░░░░░░░░░░░░░░░░░░░░░░░` |

### 1.3 Hourly UTC Heatmap

*What time of day (UTC) do HTTP attackers prefer?*

| Hour (UTC) | Requests | Heatmap |
|:---:|---:|:---|
| `00:00` | 2,346 | `█████████████████░░░░░░░░░░░░░` |
| `01:00` | 2,304 | `█████████████████░░░░░░░░░░░░░` |
| `02:00` | 1,651 | `████████████░░░░░░░░░░░░░░░░░░` |
| `03:00` | 1,371 | `██████████░░░░░░░░░░░░░░░░░░░░` |
| `04:00` | 1,379 | `██████████░░░░░░░░░░░░░░░░░░░░` |
| `05:00` | 3,314 | `████████████████████████░░░░░░` |
| `06:00` | 1,590 | `████████████░░░░░░░░░░░░░░░░░░` |
| `07:00` | 1,404 | `██████████░░░░░░░░░░░░░░░░░░░░` |
| `08:00` | 1,263 | `█████████░░░░░░░░░░░░░░░░░░░░░` |
| `09:00` | 1,173 | `█████████░░░░░░░░░░░░░░░░░░░░░` |
| `10:00` | 2,626 | `███████████████████░░░░░░░░░░░` |
| `11:00` | 1,636 | `████████████░░░░░░░░░░░░░░░░░░` |
| `12:00` | 4,110 | `██████████████████████████████` |
| `13:00` | 1,895 | `██████████████░░░░░░░░░░░░░░░░` |
| `14:00` | 3,758 | `███████████████████████████░░░` |
| `15:00` | 1,513 | `███████████░░░░░░░░░░░░░░░░░░░` |
| `16:00` | 1,341 | `██████████░░░░░░░░░░░░░░░░░░░░` |
| `17:00` | 1,752 | `█████████████░░░░░░░░░░░░░░░░░` |
| `18:00` | 1,487 | `███████████░░░░░░░░░░░░░░░░░░░` |
| `19:00` | 1,549 | `███████████░░░░░░░░░░░░░░░░░░░` |
| `20:00` | 1,865 | `██████████████░░░░░░░░░░░░░░░░` |
| `21:00` | 2,109 | `███████████████░░░░░░░░░░░░░░░` |
| `22:00` | 1,514 | `███████████░░░░░░░░░░░░░░░░░░░` |
| `23:00` | 1,368 | `██████████░░░░░░░░░░░░░░░░░░░░` |

---
## 2. Geographic Origins

**Which countries are probing our HTTP server, and who hits us the hardest?**

| Country | Total Requests | Unique IPs | Share |
|:---:|---:|---:|---:|
| **US** | 18,294 | 2,493 | 39.50% |
| **DE** | 6,090 | 175 | 13.15% |
| **BG** | 3,143 | 56 | 6.79% |
| **RU** | 3,100 | 63 | 6.69% |
| **FR** | 1,631 | 120 | 3.52% |
| **CN** | 1,559 | 165 | 3.37% |
| **GB** | 1,557 | 388 | 3.36% |
| **RO** | 1,530 | 24 | 3.30% |
| **SG** | 1,167 | 249 | 2.52% |
| **NL** | 1,147 | 70 | 2.48% |
| **PA** | 1,120 | 17 | 2.42% |
| **LT** | 953 | 9 | 2.06% |
| **SC** | 679 | 53 | 1.47% |
| **HK** | 631 | 62 | 1.36% |
| **KR** | 317 | 124 | 0.68% |
| **IN** | 314 | 28 | 0.68% |
| **BR** | 311 | 22 | 0.67% |
| **PT** | 257 | 65 | 0.55% |
| **UA** | 184 | 15 | 0.40% |
| **CA** | 181 | 12 | 0.39% |

### 2.1 Most Prolific Single IP per Country

| Country | Top IP | Requests |
|:---:|:---|---:|
| **DE** | `176.65.144.128` | 2,096 |
| **BG** | `194.180.49.49` | 1,379 |
| **FR** | `185.177.72.61` | 1,147 |
| **RO** | `45.148.10.200` | 1,044 |
| **LT** | `193.111.117.35` | 935 |
| **US** | `192.253.248.169` | 658 |
| **NL** | `46.151.178.13` | 407 |
| **RU** | `78.153.140.148` | 406 |
| **PA** | `179.43.168.58` | 378 |
| **GB** | `77.72.5.234` | 231 |
| **SG** | `101.47.8.187` | 140 |
| **CN** | `115.191.32.57` | 139 |
| **NO** | `185.12.59.118` | 135 |
| **SC** | `5.61.209.107` | 106 |
| **ID** | `110.35.80.116` | 95 |

---
## 3. HTTP Method Distribution

**Are attackers using exotic HTTP verbs beyond the standard GET/POST?**

Methods like `PROPFIND` (WebDAV enumeration), `HEAD` (lightweight probing),
and `OPTIONS` (CORS fishing) often reveal specific scanner toolkits.

| HTTP Method | Requests | Unique IPs |
|:---|---:|---:|
| `GET` | 39,882 | 3,910 |
| `POST` | 2,926 | 612 |
| `` | 2,487 | 1,025 |
| `PROPFIND` | 465 | 12 |
| `HEAD` | 397 | 25 |
| `CONNECT` | 99 | 33 |
| `OPTIONS` | 35 | 28 |
| `SSTP_DUPLEX_POST` | 13 | 13 |
| `UNKNOWN` | 4 | 2 |
| `PUT` | 4 | 1 |
| `YAWI` | 1 | 1 |
| `XUFV` | 1 | 1 |
| `WSDJ` | 1 | 1 |
| `SIYY` | 1 | 1 |
| `NEBQ` | 1 | 1 |
| `ICKP` | 1 | 1 |

---
## 4. Most Targeted URI Paths

**Which exact HTTP requests dominate the attack traffic?**

| Payload (METHOD URI VERSION) | Hits | Unique IPs | First Seen | Last Seen |
|:---|---:|---:|:---|:---|
| `GET / HTTP/1.1` | 5,098 | 2,451 | 2026-04-08 | 2026-06-21 |
| `  ` | 2,487 | 1,025 | 2026-04-08 | 2026-06-20 |
| `GET /.env HTTP/1.1` | 1,709 | 167 | 2026-04-08 | 2026-06-20 |
| `POST / HTTP/1.1` | 1,472 | 165 | 2026-04-08 | 2026-06-20 |
| `GET / HTTP/1.0` | 778 | 417 | 2026-04-08 | 2026-06-20 |
| `GET /favicon.ico HTTP/1.1` | 725 | 546 | 2026-04-08 | 2026-06-20 |
| `PROPFIND / HTTP/1.1` | 465 | 12 | 2026-04-08 | 2026-06-20 |
| `GET /.git/config HTTP/1.1` | 431 | 177 | 2026-04-08 | 2026-06-20 |
| `POST  HTTP/1.1` | 426 | 232 | 2026-04-08 | 2026-06-21 |
| `GET /robots.txt HTTP/1.1` | 319 | 220 | 2026-04-08 | 2026-06-20 |
| `GET /SDK/webLanguage HTTP/1.1` | 243 | 13 | 2026-04-08 | 2026-06-20 |
| `GET /.git/HEAD HTTP/1.1` | 178 | 80 | 2026-04-18 | 2026-06-20 |
| `GET /.env.production HTTP/1.1` | 172 | 89 | 2026-04-08 | 2026-06-20 |
| `GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 156 | 129 | 2026-04-08 | 2026-06-20 |
| `GET /.env.local HTTP/1.1` | 156 | 87 | 2026-04-08 | 2026-06-20 |
| `POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://inpu` | 147 | 125 | 2026-04-08 | 2026-06-20 |
| `GET /zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 146 | 124 | 2026-04-08 | 2026-06-20 |
| `GET /yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 146 | 124 | 2026-04-08 | 2026-06-20 |
| `GET /www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 146 | 124 | 2026-04-08 | 2026-06-20 |
| `GET /ws/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 146 | 124 | 2026-04-08 | 2026-06-20 |

---
## 5. Exploit / Vulnerability Probe Fingerprinting

**What known CVE/bug families are being probed against our nginx server?**

Each row represents a distinct exploit family detected in the payload stream,
identified by keyword signatures against the `payload` field.

| Exploit Family | Hits | Unique IPs | First Seen | Last Seen |
|:---|---:|---:|:---|:---|
| **DotEnv credential leak** | 9,154 | 178 | 2026-04-08 | 2026-06-20 |
| **PHPUnit remote exec** | 5,467 | 132 | 2026-04-08 | 2026-06-20 |
| **Git repo disclosure** | 1,788 | 205 | 2026-04-08 | 2026-06-20 |
| **Admin panel hunt** | 727 | 293 | 2026-04-08 | 2026-06-20 |
| **Actuator exposure** | 597 | 94 | 2026-04-08 | 2026-06-20 |
| **Path traversal** | 580 | 129 | 2026-04-08 | 2026-06-20 |
| **WebDAV PROPFIND** | 465 | 12 | 2026-04-08 | 2026-06-20 |
| **PHP RFI ThinkPHP** | 288 | 123 | 2026-04-08 | 2026-06-20 |
| **WordPress attack** | 43 | 11 | 2026-04-08 | 2026-06-14 |
| **Webshell upload probe** | 15 | 11 | 2026-04-10 | 2026-06-20 |
| **XMLRPC bruteforce** | 2 | 1 | 2026-06-14 | 2026-06-14 |
| **SSRF metadata probe** | 1 | 1 | 2026-06-18 | 2026-06-18 |

### 5.1 Top Payloads in Most-Hit Family: *DotEnv credential leak*

| Payload | Hits | Unique IPs |
|:---|---:|---:|
| `GET /.env HTTP/1.1` | 1,709 | 167 |
| `GET /.env.production HTTP/1.1` | 172 | 89 |
| `GET /.env.local HTTP/1.1` | 156 | 87 |
| `GET /.env.save HTTP/1.1` | 136 | 73 |
| `GET /.env.backup HTTP/1.1` | 133 | 73 |
| `GET /.env.bak HTTP/1.1` | 102 | 53 |
| `GET /api/.env HTTP/1.1` | 97 | 45 |
| `GET /20.19.171.42/.env HTTP/1.1` | 88 | 2 |
| `GET /app/.env HTTP/1.1` | 85 | 47 |
| `GET /.env.prod HTTP/1.1` | 80 | 38 |

---
## 6. User-Agent Intelligence

**What tools and scanners are behind the HTTP probes?**

User-agent strings extracted from the raw JSON log reveal the scanner ecosystem.

### 6.1 Top 20 User-Agents

| User-Agent | Requests | Unique IPs |
|:---|---:|---:|
| `libredtail-http` | 6,357 | 124 |
| `(empty)` | 3,887 | 1,726 |
| `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)` | 3,135 | 36 |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)` | 2,416 | 12 |
| `l9explore/1.2.2` | 2,134 | 2 |
| `Go-http-client/1.1` | 2,106 | 333 |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)` | 1,435 | 4 |
| `Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)` | 1,044 | 187 |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)` | 723 | 6 |
| `Mozilla/5.0 zgrab/0.x` | 706 | 431 |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)` | 686 | 14 |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)` | 597 | 136 |
| `Mozilla/5.0 (compatible; silver.inc/2.0)` | 539 | 2 |
| `-` | 509 | 9 |
| `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML` | 464 | 1 |
| `Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/genomecrawle` | 421 | 33 |
| `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/12` | 386 | 37 |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)` | 382 | 33 |
| `Hello from Palo Alto Networks, find out more about our scans in https://docs-cor` | 363 | 245 |
| `visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126` | 352 | 64 |

### 6.2 Scanner Tool Classification

IPs are grouped into known tool categories based on their user-agent string.

| Scanner Tool / Category | Requests | Unique IPs |
|:---|---:|---:|
| **Unknown / browser-like** | 37,936 | 2,553 |
| **Empty / custom UA** | 3,887 | 1,726 |
| **Go HTTP client (generic bots)** | 2,106 | 333 |
| **Censys crawler** | 1,044 | 187 |
| **zgrab (internet-wide scanner)** | 706 | 431 |
| **curl** | 249 | 129 |
| **Python requests / urllib** | 215 | 98 |
| **Shodan crawler** | 108 | 8 |
| **Masscan** | 53 | 16 |
| **wget** | 13 | 9 |
| **Nmap scripting engine** | 1 | 1 |

---
## 7. Scanner Persistence & Return Frequency

**Which attacker IPs return repeatedly over many separate days?**

Persistent scanners imply deliberate, long-term recon — not one-off mass-scans.

### 7.1 Most Persistent Scanners (≥ 5 active days)

| IP | Country | Total Requests | Active Days | Span (days) | First Seen | Last Seen |
|:---|:---:|---:|---:|---:|:---|:---|
| `93.174.93.12` | NL | 168 | 55 | 73.1 | 2026-04-08 | 2026-06-20 |
| `79.124.40.174` | BG | 269 | 49 | 67.9 | 2026-04-08 | 2026-06-15 |
| `185.12.59.118` | NO | 135 | 48 | 72.4 | 2026-04-09 | 2026-06-20 |
| `185.189.182.234` | NL | 44 | 44 | 70.9 | 2026-04-09 | 2026-06-19 |
| `46.151.178.13` | NL | 407 | 42 | 73.6 | 2026-04-08 | 2026-06-20 |
| `45.148.10.67` | RO | 309 | 39 | 60.3 | 2026-04-18 | 2026-06-17 |
| `96.126.104.20` | US | 38 | 38 | 72.0 | 2026-04-09 | 2026-06-20 |
| `80.66.83.43` | RU | 71 | 34 | 71.1 | 2026-04-10 | 2026-06-20 |
| `5.61.209.107` | SC | 106 | 29 | 28.0 | 2026-04-08 | 2026-05-06 |
| `192.253.248.169` | US | 658 | 27 | 67.1 | 2026-04-11 | 2026-06-17 |
| `185.242.226.108` | US | 55 | 27 | 28.1 | 2026-04-08 | 2026-05-06 |
| `176.65.139.66` | DE | 78 | 26 | 47.0 | 2026-05-04 | 2026-06-20 |
| `66.240.205.34` | US | 30 | 26 | 70.5 | 2026-04-09 | 2026-06-19 |
| `81.168.83.103` | GB | 100 | 25 | 27.7 | 2026-04-08 | 2026-05-06 |
| `213.209.159.175` | DE | 612 | 23 | 65.5 | 2026-04-11 | 2026-06-16 |
| `77.83.39.94` | UA | 54 | 23 | 64.3 | 2026-04-17 | 2026-06-20 |
| `77.83.39.197` | UA | 51 | 23 | 63.4 | 2026-04-15 | 2026-06-17 |
| `185.242.226.102` | US | 27 | 22 | 20.8 | 2026-05-30 | 2026-06-20 |
| `172.94.9.253` | US | 33 | 21 | 27.9 | 2026-04-08 | 2026-05-06 |
| `158.178.224.239` | US | 20 | 20 | 25.0 | 2026-05-26 | 2026-06-20 |

### 7.2 Stealthy Slow Scanners (≥ 7 active days, < 5 requests/day avg.)

*These IPs spread their probes across many days at low volume, attempting to stay below detection thresholds.*

| IP | Country | Total Requests | Active Days | Avg Requests/Day |
|:---|:---:|---:|---:|---:|
| `93.174.93.12` | NL | 168 | 55 | 3.05 |
| `185.12.59.118` | NO | 135 | 48 | 2.81 |
| `185.189.182.234` | NL | 44 | 44 | 1.0 |
| `96.126.104.20` | US | 38 | 38 | 1.0 |
| `80.66.83.43` | RU | 71 | 34 | 2.09 |
| `5.61.209.107` | SC | 106 | 29 | 3.66 |
| `185.242.226.108` | US | 55 | 27 | 2.04 |
| `66.240.205.34` | US | 30 | 26 | 1.15 |
| `176.65.139.66` | DE | 78 | 26 | 3.0 |
| `81.168.83.103` | GB | 100 | 25 | 4.0 |
| `77.83.39.94` | UA | 54 | 23 | 2.35 |
| `77.83.39.197` | UA | 51 | 23 | 2.22 |
| `185.242.226.102` | US | 27 | 22 | 1.23 |
| `172.94.9.253` | US | 33 | 21 | 1.57 |
| `158.178.224.239` | US | 20 | 20 | 1.0 |

---
## 8. Burst Behaviour & Request-Rate Analysis

**Which IPs fire dozens of requests in rapid succession?**

High requests-per-second values indicate automated tools rather than human browsing,
and may indicate DoS-adjacent spidering or weaponised exploit toolkits.

| IP | Country | Total Requests | Duration (s) | Requests/sec | First Seen | Last Seen |
|:---|:---:|---:|---:|---:|:---|:---|
| `156.67.26.103` | DE | 1,432 | 5.0 | **286.4** | 2026-04-22T05:44:05 | 2026-04-22T05:44:10 |
| `195.178.110.103` | BG | 210 | 0.0 | **210.0** | 2026-05-01T12:37:09 | 2026-05-01T12:37:09 |
| `34.19.167.188` | US | 383 | 2.0 | **191.5** | 2026-05-30T01:07:25 | 2026-05-30T01:07:27 |
| `35.199.20.151` | US | 166 | 1.0 | **166.0** | 2026-06-15T13:08:53 | 2026-06-15T13:08:54 |
| `8.230.111.17` | US | 151 | 1.0 | **151.0** | 2026-06-04T23:10:42 | 2026-06-04T23:10:43 |
| `34.21.70.198` | US | 427 | 3.0 | **142.33** | 2026-06-15T12:35:39 | 2026-06-15T12:35:42 |
| `34.129.65.121` | US | 427 | 3.0 | **142.33** | 2026-06-14T12:50:45 | 2026-06-14T12:50:48 |
| `34.96.198.106` | US | 383 | 3.0 | **127.67** | 2026-05-29T00:07:39 | 2026-05-29T00:07:42 |
| `34.155.146.71` | US | 383 | 3.0 | **127.67** | 2026-06-04T20:05:51 | 2026-06-04T20:05:54 |
| `208.84.100.220` | US | 115 | 1.0 | **115.0** | 2026-06-13T12:38:26 | 2026-06-13T12:38:27 |
| `176.65.144.128` | DE | 2,096 | 21.0 | **99.81** | 2026-06-11T14:06:27 | 2026-06-11T14:06:48 |
| `208.84.101.75` | US | 97 | 1.0 | **97.0** | 2026-06-07T17:12:27 | 2026-06-07T17:12:28 |
| `34.158.54.7` | US | 166 | 2.0 | **83.0** | 2026-06-14T12:29:26 | 2026-06-14T12:29:28 |
| `35.241.89.85` | US | 389 | 5.0 | **77.8** | 2026-05-30T01:45:50 | 2026-05-30T01:45:55 |
| `34.32.122.107` | US | 151 | 2.0 | **75.5** | 2026-05-29T08:07:21 | 2026-05-29T08:07:23 |

---
## 9. Payload Diversity — Broad Scanners vs. Targeted Hammering

**Are attackers probing everything they can think of, or hammering a single endpoint?**

A high `unique_payloads` count → wide-net scanner.  
A high `repetition_ratio` → laser-targeted exploit attempt.

### 9.1 Broadest Scanners (most distinct URI payloads per IP)

| IP | Country | Total Requests | Unique Payloads | Diversity Ratio |
|:---|:---:|---:|---:|---:|
| `176.65.144.128` | DE | 2,096 | 1,643 | 0.784 |
| `156.67.26.103` | DE | 1,432 | 1,379 | 0.963 |
| `193.111.117.35` | LT | 935 | 742 | 0.794 |
| `194.180.49.49` | BG | 1,379 | 474 | 0.344 |
| `34.21.70.198` | US | 427 | 425 | 0.995 |
| `34.129.65.121` | US | 427 | 425 | 0.995 |
| `35.241.89.85` | US | 389 | 382 | 0.982 |
| `34.88.228.181` | US | 386 | 382 | 0.99 |
| `34.19.184.212` | US | 387 | 382 | 0.987 |
| `34.176.153.40` | US | 388 | 382 | 0.985 |
| `34.96.198.106` | US | 383 | 381 | 0.995 |
| `34.19.167.188` | US | 383 | 381 | 0.995 |
| `34.155.146.71` | US | 383 | 381 | 0.995 |
| `93.123.109.165` | BG | 700 | 354 | 0.506 |
| `192.253.248.169` | US | 658 | 352 | 0.535 |
| `172.235.168.35` | US | 473 | 297 | 0.628 |
| `213.209.159.175` | DE | 612 | 230 | 0.376 |
| `195.178.110.103` | BG | 210 | 210 | 1.0 |
| `51.102.248.238` | US | 206 | 205 | 0.995 |
| `176.65.148.177` | DE | 441 | 205 | 0.465 |

### 9.2 Targeted Hammering (high repetition ratio — single exploit, many hits)

| IP | Country | Total Requests | Unique Payloads | Repetition Ratio |
|:---|:---:|---:|---:|---:|
| `46.151.178.13` | NL | 407 | 1 | **407.0×** |
| `45.148.10.67` | RO | 309 | 1 | **309.0×** |
| `78.153.140.148` | RU | 406 | 2 | **203.0×** |
| `78.153.140.147` | RU | 338 | 2 | **169.0×** |
| `78.153.140.39` | RU | 336 | 2 | **168.0×** |
| `78.128.112.74` | BG | 153 | 1 | **153.0×** |
| `78.153.140.40` | RU | 296 | 2 | **148.0×** |
| `5.61.209.107` | SC | 106 | 1 | **106.0×** |
| `78.153.140.149` | RU | 210 | 2 | **105.0×** |
| `78.153.140.252` | RU | 176 | 2 | **88.0×** |
| `93.174.93.12` | NL | 168 | 2 | **84.0×** |
| `176.65.139.66` | DE | 78 | 1 | **78.0×** |
| `80.66.83.43` | RU | 71 | 1 | **71.0×** |
| `185.12.59.118` | NO | 135 | 2 | **67.5×** |
| `78.153.140.50` | RU | 134 | 2 | **67.0×** |

---
## 10. Multi-Sensor Correlation

**Did nginx attackers also hit our SSH, credential-harvesting, or tarpit honeypots?**

IPs that appear across multiple sensors represent the most persistent and
multi-vector threat actors in our dataset.

### 10.1 Nginx IPs Also Seen on Other Honeypots

| IP | Country | Nginx Hits | Total Sensors | All Sensors | Total Events |
|:---|:---:|---:|:---:|:---|---:|
| `172.235.168.35` | US | 473 | 4 | cowrie,endlessh,heralding,nginx | 1,997 |
| `176.32.193.16` | AM | 57 | 4 | cowrie,endlessh,heralding,nginx | 238 |
| `95.215.0.144` | RU | 46 | 4 | cowrie,endlessh,heralding,nginx | 475 |
| `92.154.95.236` | FR | 28 | 4 | cowrie,endlessh,heralding,nginx | 173 |
| `80.13.153.140` | FR | 14 | 4 | cowrie,endlessh,heralding,nginx | 139 |
| `45.91.64.7` | RU | 13 | 4 | cowrie,endlessh,heralding,nginx | 349 |
| `72.14.178.148` | US | 11 | 4 | cowrie,endlessh,heralding,nginx | 48 |
| `45.33.12.214` | US | 9 | 4 | cowrie,endlessh,heralding,nginx | 73 |
| `45.79.207.181` | US | 9 | 4 | cowrie,endlessh,heralding,nginx | 67 |
| `69.164.217.74` | US | 9 | 4 | cowrie,endlessh,heralding,nginx | 86 |
| `66.228.53.162` | US | 8 | 4 | cowrie,endlessh,heralding,nginx | 43 |
| `45.33.109.18` | US | 7 | 4 | cowrie,endlessh,heralding,nginx | 43 |
| `45.33.14.5` | US | 7 | 4 | cowrie,endlessh,heralding,nginx | 71 |
| `45.79.115.59` | US | 7 | 4 | cowrie,endlessh,heralding,nginx | 66 |
| `45.79.5.11` | US | 7 | 4 | cowrie,endlessh,heralding,nginx | 66 |
| `69.164.217.245` | US | 7 | 4 | cowrie,heralding,nginx,endlessh | 42 |
| `92.63.197.22` | RU | 7 | 4 | cowrie,endlessh,heralding,nginx | 150 |
| `45.33.109.8` | US | 6 | 4 | cowrie,endlessh,heralding,nginx | 49 |
| `45.79.207.252` | US | 6 | 4 | cowrie,endlessh,heralding,nginx | 117 |
| `80.94.95.221` | RO | 6 | 4 | cowrie,endlessh,heralding,nginx | 423 |

### 10.2 HTTP-Only Attackers (Exclusive to Nginx)

*20 IPs appeared **exclusively** on the nginx sensor and were never seen on SSH, Heralding, or Endlessh.*
*These may be web-specific bots or scanners that do not attempt traditional SSH brute-forcing.*

| IP | Country | Nginx Requests |
|:---|:---:|---:|
| `176.65.144.128` | DE | 2,096 |
| `156.67.26.103` | DE | 1,432 |
| `93.123.109.165` | BG | 700 |
| `107.174.52.71` | US | 614 |
| `34.21.70.198` | US | 427 |
| `34.129.65.121` | US | 427 |
| `78.153.140.148` | RU | 406 |
| `35.241.89.85` | US | 389 |
| `34.176.153.40` | US | 388 |
| `34.19.184.212` | US | 387 |
| `34.88.228.181` | US | 386 |
| `34.96.198.106` | US | 383 |
| `34.19.167.188` | US | 383 |
| `34.155.146.71` | US | 383 |
| `78.153.140.147` | RU | 338 |

---
## 11. Attack Type Classification

**What fraction of nginx traffic was fingerprinted as fully automated?**

The heuristic flags known scanner UAs (`zgrab`, `masscan`, `curl`, etc.) and
known exploit probe paths (`.env`, `phpunit`, `PROPFIND`) as `automated`.

| Classification | Events | Unique IPs | Share |
|:---|---:|---:|---:|
| **uncertain** | 25,128 | 3,650 | 54.25% |
| **automated** | 21,190 | 1,415 | 45.75% |

---
## 12. First-Hit Path — Scanner Playbook Reconstruction

**What is the very first URI each attacker probes?**

The first probe reveals the scanner's default priority list — i.e., which
vulnerability it cares about *most*. This effectively reverse-engineers the
tool's built-in scan order.

| First Probe Payload | IPs Starting Here |
|:---|---:|
| `GET / HTTP/1.1` | 177 |
| `GET / HTTP/1.0` | 77 |
| `POST  HTTP/1.1` | 60 |
| `  ` | 44 |
| `POST /GponForm/diag_Form?images/ HTTP/1.1` | 12 |
| `GET /developmentserver/metadatauploader HTTP/1.1` | 11 |
| `GET /.env HTTP/1.1` | 9 |
| `GET /favicon.ico HTTP/1.1` | 8 |
| `GET /robots.txt HTTP/1.1` | 6 |
| `GET /boaform/admin/formLogin?username=ec8&psd=ec8 HTTP/1.0` | 6 |
| `GET /boaform/admin/formLogin?username=admin&psd=admin HTTP/1.0` | 5 |
| `GET /manager/html HTTP/1.1` | 5 |
| `GET /login HTTP/1.1` | 4 |
| `POST /HNAP1/ HTTP/1.0` | 4 |
| `GET /boaform/admin/formLogin?username=user&psd=user HTTP/1.0` | 4 |
| `GET /actuator/health HTTP/1.1` | 4 |
| `GET /ReportServer HTTP/1.1` | 4 |
| `GET /.git/config HTTP/1.1` | 3 |
| `GET /cgi-bin/authLogin.cgi HTTP/1.1` | 3 |
| `GET /.git/HEAD HTTP/1.1` | 3 |

---
## 13. Day-of-Week Attack Rhythm

**Does attack volume follow a human work-week pattern, or is it constant?**

Fully automated bots typically show flat distributions; any deviation hints at
human scheduling, botnet C2 windows, or geographically offset work hours.

| Day | Requests | Unique IPs | Volume |
|:---|---:|---:|:---|
| **Sunday** | 5,823 | 801 | `█████████████████░░░░░░░░` |
| **Monday** | 6,135 | 793 | `██████████████████░░░░░░░` |
| **Tuesday** | 4,984 | 928 | `███████████████░░░░░░░░░░` |
| **Wednesday** | 7,327 | 1,036 | `██████████████████████░░░` |
| **Thursday** | 8,410 | 990 | `█████████████████████████` |
| **Friday** | 7,683 | 969 | `███████████████████████░░` |
| **Saturday** | 5,956 | 903 | `██████████████████░░░░░░░` |

---
## 14. Destination Port Targeting

**Are attackers hitting the standard HTTP/HTTPS ports only, or scanning alternatives?**

Non-standard ports (e.g., 8080, 8443, 3000, 9200) reveal scanners that look
for misconfigured dev servers, Elasticsearch nodes, or Docker APIs.

| Destination Port | Requests | Unique IPs |
|:---:|---:|---:|
| **80** | 25,043 | 2,913 |
| **443** | 21,275 | 2,434 |

---
## 15. Coordinated Campaign Detection

**Are multiple IPs sending the exact same exploit payload in a coordinated wave?**

When many distinct source IPs all send the same `METHOD URI VERSION` string,
this strongly indicates a **distributed botnet campaign** or a shared exploit kit.

### 15.1 Campaign Signature Payloads (≥ 10 unique IPs sending identical payload)

| Payload | IPs | Total Hits | First Seen | Last Seen |
|:---|---:|---:|:---|:---|
| `GET / HTTP/1.1` | 2,451 | 5,098 | 2026-04-08 | 2026-06-21 |
| `  ` | 1,025 | 2,487 | 2026-04-08 | 2026-06-20 |
| `GET /favicon.ico HTTP/1.1` | 546 | 725 | 2026-04-08 | 2026-06-20 |
| `GET / HTTP/1.0` | 417 | 778 | 2026-04-08 | 2026-06-20 |
| `POST  HTTP/1.1` | 232 | 426 | 2026-04-08 | 2026-06-21 |
| `GET /robots.txt HTTP/1.1` | 220 | 319 | 2026-04-08 | 2026-06-20 |
| `GET /.git/config HTTP/1.1` | 177 | 431 | 2026-04-08 | 2026-06-20 |
| `GET /.env HTTP/1.1` | 167 | 1,709 | 2026-04-08 | 2026-06-20 |
| `POST / HTTP/1.1` | 165 | 1,472 | 2026-04-08 | 2026-06-20 |
| `GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 129 | 156 | 2026-04-08 | 2026-06-20 |
| `POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://inpu` | 125 | 147 | 2026-04-08 | 2026-06-20 |
| `GET /zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |
| `GET /yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |
| `GET /www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |
| `GET /ws/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |
| `GET /ws/ec/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |
| `GET /vendor/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |
| `GET /vendor/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |
| `GET /vendor/phpunit/phpunit/Util/PHP/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |
| `GET /vendor/phpunit/phpunit/LICENSE/eval-stdin.php HTTP/1.1` | 124 | 146 | 2026-04-08 | 2026-06-20 |

### 15.2 Daily Campaign Bursts (same payload, same day, ≥ 5 IPs)

| Day | Payload | IPs | Hits |
|:---|:---|---:|---:|
| 2026-04-23 | `GET / HTTP/1.1` | 98 | 128 |
| 2026-06-09 | `GET / HTTP/1.1` | 92 | 118 |
| 2026-04-28 | `GET / HTTP/1.1` | 90 | 114 |
| 2026-06-04 | `GET / HTTP/1.1` | 88 | 109 |
| 2026-06-02 | `GET / HTTP/1.1` | 87 | 122 |
| 2026-06-17 | `GET / HTTP/1.1` | 85 | 104 |
| 2026-06-11 | `GET / HTTP/1.1` | 82 | 145 |
| 2026-04-24 | `GET / HTTP/1.1` | 81 | 111 |
| 2026-06-14 | `GET / HTTP/1.1` | 78 | 113 |
| 2026-06-05 | `GET / HTTP/1.1` | 78 | 100 |
| 2026-06-10 | `GET / HTTP/1.1` | 77 | 110 |
| 2026-06-19 | `GET / HTTP/1.1` | 77 | 97 |
| 2026-04-14 | `GET / HTTP/1.1` | 75 | 101 |
| 2026-05-01 | `GET / HTTP/1.1` | 75 | 87 |
| 2026-06-08 | `GET / HTTP/1.1` | 74 | 111 |
| 2026-05-28 | `GET / HTTP/1.1` | 74 | 100 |
| 2026-04-21 | `GET / HTTP/1.1` | 74 | 95 |
| 2026-06-13 | `GET / HTTP/1.1` | 73 | 108 |
| 2026-05-29 | `GET / HTTP/1.1` | 73 | 103 |
| 2026-06-20 | `GET / HTTP/1.1` | 73 | 87 |

---
## 16. HTTP Version Distribution

**Are attackers using HTTP/1.0 (old/bare scanners) or HTTP/1.1 / HTTP/2?**

`HTTP/1.0` requests skip the mandatory `Host:` header — a hallmark of minimal
Internet-wide scanners like Masscan.

| HTTP Version | Requests | Unique IPs |
|:---|---:|---:|
| `HTTP/1.1` | 42,764 | 3,824 |
| `HTTP/1.0` | 1,067 | 501 |

---
## 17. Country-Level Attack Path Specialisation

**Do attackers from different countries probe different URI paths?**

A country with many unique payloads per IP implies more creative / sophisticated
attackers, whereas low diversity suggests mass-produced automated toolkits.

| Country | Unique Payloads | Total Requests | Unique IPs |
|:---:|---:|---:|---:|
| **DE** | 3,128 | 6,090 | 175 |
| **US** | 2,332 | 18,294 | 2,493 |
| **BG** | 1,020 | 3,143 | 56 |
| **LT** | 747 | 953 | 9 |
| **PA** | 425 | 1,120 | 17 |
| **RO** | 244 | 1,530 | 24 |
| **GB** | 214 | 1,557 | 388 |
| **SG** | 189 | 1,167 | 249 |
| **NL** | 152 | 1,147 | 70 |
| **FR** | 132 | 1,631 | 120 |
| **IN** | 117 | 314 | 28 |
| **KR** | 109 | 317 | 124 |
| **CN** | 78 | 1,559 | 165 |
| **SC** | 77 | 679 | 53 |
| **RU** | 73 | 3,100 | 63 |

---
## 18. Day-by-Day Timeline of Top IPs

**How does request volume evolve over the observation period for the 5 busiest attackers?**

Irregular spikes may indicate new exploit campaigns; flat lines indicate persistent
low-rate crawlers.

### `176.65.144.128`

| Date | Requests | Bar |
|:---|---:|:---|
| 2026-06-11 | 2,096 | `████████████████████` |

### `156.67.26.103`

| Date | Requests | Bar |
|:---|---:|:---|
| 2026-04-22 | 1,432 | `████████████████████` |

### `194.180.49.49`

| Date | Requests | Bar |
|:---|---:|:---|
| 2026-04-27 | 869 | `████████████████████` |
| 2026-04-28 | 510 | `████████████░░░░░░░░` |

### `185.177.72.61`

| Date | Requests | Bar |
|:---|---:|:---|
| 2026-04-08 | 60 | `███████░░░░░░░░░░░░░` |
| 2026-04-09 | 122 | `█████████████░░░░░░░` |
| 2026-04-10 | 61 | `███████░░░░░░░░░░░░░` |
| 2026-04-11 | 181 | `████████████████████` |
| 2026-04-12 | 181 | `████████████████████` |
| 2026-04-13 | 181 | `████████████████████` |
| 2026-04-14 | 60 | `███████░░░░░░░░░░░░░` |
| 2026-04-16 | 121 | `█████████████░░░░░░░` |
| 2026-04-17 | 120 | `█████████████░░░░░░░` |
| 2026-04-19 | 60 | `███████░░░░░░░░░░░░░` |

### `45.148.10.200`

| Date | Requests | Bar |
|:---|---:|:---|
| 2026-05-29 | 56 | `███████░░░░░░░░░░░░░` |
| 2026-06-10 | 87 | `███████████░░░░░░░░░` |
| 2026-06-11 | 142 | `██████████████████░░` |
| 2026-06-12 | 151 | `███████████████████░` |
| 2026-06-15 | 156 | `████████████████████` |
| 2026-06-16 | 52 | `███████░░░░░░░░░░░░░` |
| 2026-06-17 | 53 | `███████░░░░░░░░░░░░░` |
| 2026-06-18 | 157 | `████████████████████` |
| 2026-06-19 | 137 | `█████████████████░░░` |
| 2026-06-20 | 53 | `███████░░░░░░░░░░░░░` |


---
## 19. Sensitive File & Credential Probe Classification

**Which categories of sensitive resources are attackers hunting for?**

Probes for `.env` files, SSH keys, Git repositories, database dumps, and
server-info pages are grouped into semantic categories.

| Category | Hits | Unique IPs | First Seen | Last Seen |
|:---|---:|---:|:---|:---|
| **Environment & credentials** | 9,565 | 188 | 2026-04-08 | 2026-06-20 |
| **Source code & VCS** | 1,830 | 205 | 2026-04-08 | 2026-06-20 |
| **Backup & archive files** | 1,610 | 103 | 2026-04-08 | 2026-06-20 |
| **Config files** | 1,173 | 80 | 2026-04-09 | 2026-06-20 |
| **PHP info / server diagnostics** | 560 | 75 | 2026-04-11 | 2026-06-20 |
| **Log files** | 279 | 66 | 2026-04-11 | 2026-06-20 |

---
## 20. Summary Statistics

**Quick-reference numbers from the nginx honeypot analysis.**

| Metric | Value |
|:---|---:|
| Total HTTP Requests | **46,318** |
| Unique Attacker IPs | **4,537** |
| Unique Request Signatures | **5,924** |
| Observation Active Days | **57** |
| Automated Requests | **21,190** (45.7%) |
| Uncertain / Unclassified Requests | **25,128** |

### Key Findings

- **100% of nginx events are actionable** (`payload_delivery` category) — unlike SSH honeypots that produce connection noise.
- **Automated scanners dominate**, identified by known tool user-agents and exploit-probe URI patterns.
- **Multi-vector attackers** (IPs seen on both nginx and SSH honeypots) represent the most persistent threat actors.
- **Coordinated campaigns** (identical payloads from many IPs on the same day) confirm active botnet-driven exploitation waves.
- **Stealthy slow scanners** deliberately spread probes across many days to evade rate-based detection.

---

*Report generated by `nginx_md_generator.py` from `nginx_analyzer_results.json`.*
