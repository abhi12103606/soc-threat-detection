"""
=============================================================
  Real-Time Windows Network Monitor — Threat Intelligence
  SOC Analyst Toolkit v3.0
=============================================================
  REQUIREMENTS:
    pip install psutil flask flask-cors requests

  OPTIONAL (for deeper features):
    pip install dnspython scapy

  RUN AS ADMINISTRATOR:
    python monitor.py

  Then open dashboard.html in your browser.
  API runs on http://localhost:5000

  WHAT'S NEW IN v3.0:
    - Real-time IP/domain reputation via AbuseIPDB + URLhaus
    - DNS reverse lookup on every external connection
    - Hardware access detection (camera, mic, GPU, USB)
    - Malicious domain blocklist (auto-updated from URLhaus)
    - ALL threats saved to threat_log.json (persistent)
    - View saved threats anytime even after restart
=============================================================
"""

import os
import re
import json
import time
import socket
import hashlib
import platform
import threading
import subprocess
import ipaddress
from datetime import datetime
from pathlib import Path
from collections import deque

import psutil
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

# ── optional packages ──
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ──────────────────────────────────────────────────────────
#  PATHS
# ──────────────────────────────────────────────────────────
BASE_DIR        = Path(__file__).parent
THREAT_LOG_FILE = BASE_DIR / "threat_log.json"
IP_CACHE_FILE   = BASE_DIR / "ip_cache.json"

# ──────────────────────────────────────────────────────────
#  CONFIG
# ──────────────────────────────────────────────────────────
HOST          = "0.0.0.0"
PORT          = 5000
SCAN_INTERVAL = 4       # seconds between scans
MAX_HISTORY   = 120     # rolling chart points
CACHE_TTL     = 3600    # 1-hour IP reputation cache

# Optional: free API key from https://www.abuseipdb.com/register
# Gives 1000 live checks/day. Leave blank for offline-only mode.
ABUSEIPDB_KEY = ""

# ──────────────────────────────────────────────────────────
#  BUILT-IN THREAT INTELLIGENCE LISTS
# ──────────────────────────────────────────────────────────

MALICIOUS_DOMAINS = {
    # Malware C2 / ransomware
    "evil-update.com", "malware-dropper.net", "c2.botnet.xyz",
    "beacon.cobaltstrike.io", "stager.metasploit.net",
    "darkweb-payment.onion.ws", "ransom-gate.net",
    # Phishing
    "secure-login-verify.com", "account-update-required.net",
    "paypal-security-center.com", "microsoft-verify.net",
    "apple-id-locked.com", "amazon-order-confirm.net",
    "google-account-help.com", "facebook-login-secure.net",
    # Cryptomining
    "pool.minexmr.com", "xmr.pool.minergate.com",
    "coinhive.com", "crypto-miner.js.net",
    # TOR gateways
    "tor2web.org", "onion.to", "onion.ly", "tor2web.fi",
    # Spyware / RAT infra
    "spy-logger.net", "rat-panel.xyz", "keylogger-host.com",
}

RESTRICTED_DOMAINS = {
    # Commonly restricted in corporate/school environments
    "thepiratebay.org", "1337x.to", "rarbg.to", "kickass.to",
    "dark.fail", "onion.pet",
    "hackforums.net", "nulled.to", "cracked.io",
    "exploit-db.com",
}

SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common backdoor",
    31337: "Elite backdoor",
    8080:  "Alt-HTTP / C2 beacon",
    9001:  "TOR relay",
    9050:  "TOR SOCKS proxy",
    6667:  "IRC / botnet C2",
    23:    "Telnet (cleartext)",
    21:    "FTP (cleartext)",
    5900:  "VNC remote desktop",
    1080:  "SOCKS proxy",
    12345: "Common RAT port",
    54321: "Common RAT reverse",
    6666:  "IRC / malware",
}

HARDWARE_PATTERNS = {
    "Camera":     ["cam", "webcam", "camera", "imagingdevice", "vmicvss"],
    "Microphone": ["audiodg", "speechruntime", "voicerecorder", "soundrecorder"],
    "GPU/Display":["nvda", "aticfx", "igfx", "d3d", "dxgi", "opengl", "vulkan"],
    "USB Device": ["usbstor", "wudfhost", "usbaudio", "hidserv"],
    "Disk Access":["diskpart", "rawcopy", "robocopy", "xcopy"],
}

MALWARE_PROCESS_NAMES = [
    "mimikatz", "meterpreter", "nc.exe", "ncat",
    "psexec", "wce.exe", "pwdump", "fgdump",
    "cobaltstrike", "beacon.exe", "empire",
    "procdump", "netcat",
]

SYSTEM_WHITELIST = {
    "svchost.exe","system","registry","smss.exe","csrss.exe",
    "wininit.exe","services.exe","lsass.exe","winlogon.exe",
    "dwm.exe","taskhostw.exe","sihost.exe","runtimebroker.exe",
    "spoolsv.exe","audiodg.exe","ctfmon.exe","conhost.exe",
    "dllhost.exe","wermgr.exe","backgroundtaskhost.exe",
    "searchhost.exe","startmenuexperiencehost.exe",
}

# ──────────────────────────────────────────────────────────
#  PERSISTENCE HELPERS
# ──────────────────────────────────────────────────────────

def load_json(path, default):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return default

def save_json(path, data):
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"[save_json] {e}")

# ──────────────────────────────────────────────────────────
#  SHARED STATE
# ──────────────────────────────────────────────────────────
lock = threading.Lock()

_saved_threats = load_json(THREAT_LOG_FILE, [])
_ip_cache      = load_json(IP_CACHE_FILE, {})
_reputation    = {}       # ip -> reputation dict (in-memory fast lookup)
_lookup_queue  = deque()  # IPs queued for async reputation check

state = {
    # rolling time-series
    "cpu_history":      deque(maxlen=MAX_HISTORY),
    "mem_history":      deque(maxlen=MAX_HISTORY),
    "net_sent_history": deque(maxlen=MAX_HISTORY),
    "net_recv_history": deque(maxlen=MAX_HISTORY),
    "timestamps":       deque(maxlen=MAX_HISTORY),

    # live snapshots
    "connections":   [],
    "processes":     [],
    "wifi_devices":  [],
    "open_ports":    [],
    "interfaces":    [],
    "network_stats": {},
    "system_info":   {},
    "hardware_access": [],

    # threat data
    "live_alerts":   deque(maxlen=300),
    "threat_log":    _saved_threats[:],     # full persistent list
    "total_alerts":  len(_saved_threats),

    "packets_captured": 0,
    "scapy_available":  SCAPY_AVAILABLE,
}

_prev_net  = psutil.net_io_counters()
_prev_time = time.time()

# ──────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────

def ts_now():
    return datetime.now().strftime("%H:%M:%S")

def ts_full():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_private(ip_str):
    try:
        a = ipaddress.ip_address(ip_str)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True

def root_domain(hostname):
    parts = hostname.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# ──────────────────────────────────────────────────────────
#  THREAT ALERT — creates alert AND persists it
# ──────────────────────────────────────────────────────────

def add_threat(severity, category, title, detail,
               ip="", domain="", threat_type=""):
    uid = hashlib.md5(f"{ts_full()}{title}{ip}{detail}".encode()).hexdigest()[:10]
    alert = {
        "id":          uid,
        "timestamp":   ts_full(),
        "time":        ts_now(),
        "severity":    severity,       # critical / high / medium / low
        "category":    category,
        "title":       title,
        "detail":      detail,
        "ip":          ip,
        "domain":      domain,
        "threat_type": threat_type,    # malicious_ip / restricted / hardware_* / process / port
    }

    with lock:
        state["live_alerts"].appendleft(alert)
        state["threat_log"].insert(0, alert)
        if len(state["threat_log"]) > 3000:
            state["threat_log"] = state["threat_log"][:3000]
        state["total_alerts"] = len(state["threat_log"])

    # async persist
    threading.Thread(
        target=save_json,
        args=(THREAT_LOG_FILE, state["threat_log"][:3000]),
        daemon=True
    ).start()

    print(f"  [{'!!!' if severity=='critical' else '!! ' if severity=='high' else '!  '}] "
          f"{severity.upper():8s} | {category:20s} | {title}")


# ──────────────────────────────────────────────────────────
#  IP / DOMAIN REPUTATION
# ──────────────────────────────────────────────────────────

def check_reputation(ip):
    """Returns reputation dict for an external IP.
    Checks: local cache → offline lists → AbuseIPDB → URLhaus."""

    if is_private(ip):
        return None

    # 1. in-memory cache (very fast)
    with lock:
        r = _reputation.get(ip)
    if r and (time.time() - r.get("_at", 0)) < CACHE_TTL:
        return r

    # 2. file cache
    cached = _ip_cache.get(ip)
    if cached and (time.time() - cached.get("_at", 0)) < CACHE_TTL:
        with lock:
            _reputation[ip] = cached
        return cached

    result = {
        "ip":           ip,
        "score":        0,
        "is_malicious": False,
        "is_restricted": False,
        "categories":   [],
        "source":       "offline",
        "country":      "??",
        "domain":       "",
        "_at":          time.time(),
    }

    # Reverse DNS
    domain = reverse_dns(ip)
    result["domain"] = domain
    rd = root_domain(domain) if domain else ""

    # Offline list checks
    if rd in MALICIOUS_DOMAINS or domain in MALICIOUS_DOMAINS:
        result.update({"is_malicious": True, "score": 90,
                        "source": "local_blocklist"})
        result["categories"].append("malicious_domain")

    if rd in RESTRICTED_DOMAINS or domain in RESTRICTED_DOMAINS:
        result["is_restricted"] = True
        result["score"] = max(result["score"], 55)
        result["categories"].append("restricted_content")
        if result["source"] == "offline":
            result["source"] = "local_blocklist"

    # AbuseIPDB (live, only if key set)
    if ABUSEIPDB_KEY and not result["is_malicious"]:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5
            )
            if resp.ok:
                d = resp.json().get("data", {})
                score = d.get("abuseConfidenceScore", 0)
                result["score"]   = max(result["score"], score)
                result["country"] = d.get("countryCode", "??")
                result["source"]  = "abuseipdb"
                if score > 50:
                    result["is_malicious"] = True
                    result["categories"].append("abuse_reported")
        except Exception:
            pass

    # URLhaus (live, domain check)
    if domain and not result["is_malicious"]:
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain}, timeout=4
            )
            if resp.ok and resp.json().get("query_status") == "is_host":
                result.update({"is_malicious": True, "score": max(result["score"], 85),
                                "source": "urlhaus"})
                result["categories"].append("urlhaus_malware")
        except Exception:
            pass

    # Save to both caches
    with lock:
        _reputation[ip] = result
        _ip_cache[ip]   = result

    threading.Thread(target=save_json, args=(IP_CACHE_FILE, _ip_cache.copy()),
                     daemon=True).start()
    return result


def reputation_worker():
    """Background thread: drains the lookup queue one IP at a time."""
    while True:
        ip = None
        with lock:
            if _lookup_queue:
                ip = _lookup_queue.popleft()

        if ip:
            # Already processed?
            with lock:
                already = ip in _reputation
            if not already:
                rep = check_reputation(ip)
                if rep:
                    sev = None
                    if rep["is_malicious"]:
                        sev = "critical" if rep["score"] > 80 else "high"
                        add_threat(
                            sev, "Threat Intel",
                            f"Malicious IP: {ip}",
                            f"Score {rep['score']}/100 | {rep['domain'] or 'no domain'} "
                            f"| {', '.join(rep['categories'])} | via {rep['source']}",
                            ip=ip, domain=rep["domain"],
                            threat_type="malicious_ip"
                        )
                    elif rep["is_restricted"]:
                        add_threat(
                            "medium", "Restricted Site",
                            f"Restricted domain accessed: {rep['domain'] or ip}",
                            f"IP {ip} | {', '.join(rep['categories'])}",
                            ip=ip, domain=rep["domain"],
                            threat_type="restricted_domain"
                        )
        time.sleep(0.25)


# ──────────────────────────────────────────────────────────
#  HARDWARE ACCESS DETECTION
# ──────────────────────────────────────────────────────────

def detect_hardware_access():
    """Detect processes touching camera, mic, GPU, USB.
    If any of those processes also have external connections → CRITICAL."""
    found = []
    seen  = set()

    try:
        for proc in psutil.process_iter(["pid","name","exe","username","connections"]):
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                exe  = (info["exe"]  or "").lower()

                if info["name"] in SYSTEM_WHITELIST:
                    continue

                for hw_type, patterns in HARDWARE_PATTERNS.items():
                    if any(p in name or p in exe for p in patterns):
                        key = (info["pid"], hw_type)
                        if key in seen:
                            continue
                        seen.add(key)

                        # Check external connections
                        ext_conns = []
                        try:
                            for c in proc.connections():
                                if c.raddr and not is_private(c.raddr.ip):
                                    ext_conns.append(f"{c.raddr.ip}:{c.raddr.port}")
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass

                        risk = "high" if ext_conns else "medium"

                        if ext_conns:
                            add_threat(
                                "critical", "Hardware Surveillance",
                                f"{hw_type} accessed + external connection",
                                f"Process: {info['name']} (PID {info['pid']}) "
                                f"using {hw_type} → {', '.join(ext_conns[:3])}",
                                ip=ext_conns[0].split(":")[0],
                                threat_type=f"hardware_{hw_type.lower().split('/')[0]}"
                            )

                        found.append({
                            "pid":          info["pid"],
                            "name":         info["name"],
                            "hw_type":      hw_type,
                            "ext_conns":    ext_conns,
                            "risk":         risk,
                            "username":     (info["username"] or "").split("\\")[-1],
                        })
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        print(f"[hardware_detect] {e}")

    with lock:
        state["hardware_access"] = found


# ──────────────────────────────────────────────────────────
#  UPDATE LIVE THREAT FEED (URLhaus recent URLs)
# ──────────────────────────────────────────────────────────
_feed_updated = 0

def update_threat_feed():
    global _feed_updated, MALICIOUS_DOMAINS
    if time.time() - _feed_updated < 3600:
        return
    try:
        resp = requests.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/",
            timeout=12
        )
        if resp.ok:
            new = set()
            for entry in resp.json().get("urls", []):
                m = re.search(r"https?://([^/]+)", entry.get("url", ""))
                if m:
                    d = m.group(1).split(":")[0]
                    new.add(d)
                    new.add(root_domain(d))
            MALICIOUS_DOMAINS.update(new)
            _feed_updated = time.time()
            print(f"  [feed] Updated: +{len(new)} malicious domains from URLhaus")
    except Exception as e:
        print(f"  [feed] Could not fetch URLhaus: {e}")


# ──────────────────────────────────────────────────────────
#  CORE COLLECTORS
# ──────────────────────────────────────────────────────────

def collect_metrics():
    global _prev_net, _prev_time
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    now_net  = psutil.net_io_counters()
    elapsed  = max(time.time() - _prev_time, 0.1)
    sent_kbps = (now_net.bytes_sent - _prev_net.bytes_sent) / elapsed / 1024
    recv_kbps = (now_net.bytes_recv - _prev_net.bytes_recv) / elapsed / 1024
    _prev_net  = now_net
    _prev_time = time.time()

    with lock:
        state["cpu_history"].append(cpu)
        state["mem_history"].append(mem)
        state["net_sent_history"].append(round(sent_kbps, 2))
        state["net_recv_history"].append(round(recv_kbps, 2))
        state["timestamps"].append(ts_now())
        state["network_stats"] = {
            "bytes_sent":   now_net.bytes_sent,
            "bytes_recv":   now_net.bytes_recv,
            "packets_sent": now_net.packets_sent,
            "packets_recv": now_net.packets_recv,
            "errin": now_net.errin, "errout": now_net.errout,
            "dropin": now_net.dropin, "dropout": now_net.dropout,
            "sent_kbps": round(sent_kbps, 2),
            "recv_kbps": round(recv_kbps, 2),
        }

    if cpu > 90:
        add_threat("high", "System", "CPU critically high", f"{cpu:.1f}%")
    if mem > 90:
        add_threat("high", "System", "Memory critically high", f"{mem:.1f}%")


def collect_system_info():
    try:
        hn = socket.gethostname()
        ip = socket.gethostbyname(hn)
    except Exception:
        hn, ip = "unknown", "unknown"
    u = platform.uname()
    boot = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    with lock:
        state["system_info"] = {
            "hostname": hn, "local_ip": ip,
            "os": f"{u.system} {u.release}", "machine": u.machine,
            "processor": u.processor or platform.processor(),
            "boot_time": boot,
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_physical": psutil.cpu_count(logical=False),
            "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 1),
            "python_ver": platform.python_version(),
        }


def collect_interfaces():
    ifaces = []
    for name, addrs in psutil.net_if_addrs().items():
        s = psutil.net_if_stats().get(name)
        info = {"name": name, "addresses": [],
                "is_up": s.isup if s else False,
                "speed_mbps": s.speed if s else 0}
        for a in addrs:
            fam = str(a.family)
            if "AF_INET" in fam or a.family == socket.AF_INET:
                info["addresses"].append({"type":"IPv4","address":a.address,"netmask":a.netmask or ""})
            elif "AF_INET6" in fam or a.family == socket.AF_INET6:
                info["addresses"].append({"type":"IPv6","address":a.address,"netmask":a.netmask or ""})
            else:
                info["addresses"].append({"type":"MAC","address":a.address,"netmask":""})
        ifaces.append(info)
    with lock:
        state["interfaces"] = ifaces


def collect_connections():
    conns = []
    queued = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.laddr or not c.status:
                continue
            rip   = c.raddr.ip   if c.raddr else ""
            rport = c.raddr.port if c.raddr else 0
            raddr = f"{rip}:{rport}" if c.raddr else ""
            laddr = f"{c.laddr.ip}:{c.laddr.port}"

            pname = "Unknown"
            try:
                if c.pid:
                    pname = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            is_ext = rip and not is_private(rip)

            # Queue for reputation lookup
            if is_ext and rip not in queued:
                queued.add(rip)
                with lock:
                    if rip not in _reputation and rip not in list(_lookup_queue):
                        _lookup_queue.append(rip)

            rep    = _reputation.get(rip)
            flags  = []
            mal    = False
            t_score = 0

            if rep:
                t_score = rep.get("score", 0)
                if rep.get("is_malicious"):
                    flags.append(f"MALICIOUS (score {t_score})")
                    mal = True
                elif rep.get("is_restricted"):
                    flags.append("Restricted site")
                elif t_score > 50:
                    flags.append(f"Suspicious (score {t_score})")
                if rep.get("categories"):
                    flags += [c for c in rep["categories"] if c not in flags]

            if rport in SUSPICIOUS_PORTS:
                flags.append(f"Suspicious port: {SUSPICIOUS_PORTS[rport]}")

            if is_ext:
                flags.append("External")

            conns.append({
                "pid": c.pid, "process": pname,
                "laddr": laddr, "raddr": raddr,
                "rip": rip, "rport": rport,
                "domain": rep.get("domain","") if rep else "",
                "country": rep.get("country","") if rep else "",
                "status": c.status,
                "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "flags": flags,
                "suspicious": bool(flags),
                "malicious": mal,
                "threat_score": t_score,
                "is_external": is_ext,
            })
    except (psutil.AccessDenied, PermissionError):
        pass

    conns.sort(key=lambda x: (-x["malicious"], -x["suspicious"], x["process"]))
    with lock:
        state["connections"] = conns[:150]


def collect_open_ports():
    ports, seen = [], set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN" and c.laddr:
                p = c.laddr.port
                if p in seen: continue
                seen.add(p)
                pname = "Unknown"
                try:
                    if c.pid: pname = psutil.Process(c.pid).name()
                except: pass
                note = SUSPICIOUS_PORTS.get(p, "")
                ports.append({"port": p, "process": pname, "pid": c.pid,
                               "address": c.laddr.ip, "protocol": "TCP",
                               "note": note, "suspicious": p in SUSPICIOUS_PORTS})
                if p in SUSPICIOUS_PORTS:
                    add_threat("high","Open Port",
                               f"Suspicious port {p} open",
                               f"{pname} — {SUSPICIOUS_PORTS[p]}",
                               threat_type="suspicious_port")
    except: pass
    ports.sort(key=lambda x: (not x["suspicious"], x["port"]))
    with lock:
        state["open_ports"] = ports


def collect_processes():
    procs = []
    try:
        for p in psutil.process_iter(["pid","name","username","cpu_percent",
                                       "memory_percent","status","exe"]):
            try:
                info  = p.info
                nlow  = (info["name"] or "").lower()
                is_sus = any(s in nlow for s in MALWARE_PROCESS_NAMES)
                conns = 0
                try: conns = len(p.connections())
                except: pass
                procs.append({
                    "pid": info["pid"], "name": info["name"] or "unknown",
                    "username": (info["username"] or "").split("\\")[-1],
                    "cpu": round(info["cpu_percent"] or 0, 1),
                    "memory": round(info["memory_percent"] or 0, 2),
                    "status": info["status"] or "",
                    "connections": conns,
                    "suspicious": is_sus,
                    "exe": info["exe"] or "",
                })
                if is_sus:
                    add_threat("critical","Process",
                               f"Malware process detected: {info['name']}",
                               f"PID {info['pid']}",
                               threat_type="malware_process")
            except: continue
    except: pass
    procs.sort(key=lambda x: (-x["suspicious"], -x["cpu"]))
    with lock:
        state["processes"] = procs[:60]


def collect_wifi():
    devices = []
    try:
        out = subprocess.run(["arp","-a"], capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3: continue
            ip, mac, typ = parts[0], parts[1], parts[2]
            try: ipaddress.ip_address(ip)
            except: continue
            if ip.startswith("224.") or ip.startswith("255."): continue
            hn = ""
            try: hn = socket.gethostbyaddr(ip)[0]
            except: pass
            devices.append({"ip":ip,"mac":mac,"type":typ,"hostname":hn,
                             "suspicious": mac=="ff-ff-ff-ff-ff-ff"})
    except: pass
    with lock:
        state["wifi_devices"] = devices


# ──────────────────────────────────────────────────────────
#  MAIN LOOP
# ──────────────────────────────────────────────────────────
def collection_loop():
    collect_system_info()
    collect_interfaces()
    threading.Thread(target=update_threat_feed, daemon=True).start()
    cycle = 0
    while True:
        try:
            collect_metrics()
            collect_connections()
            collect_open_ports()
            collect_processes()
            if cycle % 2 == 0:
                collect_wifi()
                detect_hardware_access()
            if cycle % 900 == 0:
                threading.Thread(target=update_threat_feed, daemon=True).start()
            cycle += 1
        except Exception as e:
            print(f"[loop error] {e}")
        time.sleep(SCAN_INTERVAL)


# ──────────────────────────────────────────────────────────
#  FLASK API
# ──────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

def snap():
    with lock:
        return {
            "cpu_history":      list(state["cpu_history"]),
            "mem_history":      list(state["mem_history"]),
            "net_sent_history": list(state["net_sent_history"]),
            "net_recv_history": list(state["net_recv_history"]),
            "timestamps":       list(state["timestamps"]),
            "connections":      list(state["connections"]),
            "processes":        list(state["processes"]),
            "wifi_devices":     list(state["wifi_devices"]),
            "open_ports":       list(state["open_ports"]),
            "interfaces":       list(state["interfaces"]),
            "hardware_access":  list(state["hardware_access"]),
            "live_alerts":      list(state["live_alerts"])[:100],
            "threat_log":       list(state["threat_log"])[:500],
            "network_stats":    dict(state["network_stats"]),
            "system_info":      dict(state["system_info"]),
            "total_alerts":     state["total_alerts"],
            "packets_captured": state["packets_captured"],
            "scapy_available":  state["scapy_available"],
            "server_time":      ts_full(),
            "log_file":         str(THREAT_LOG_FILE),
            "abuseipdb_active": bool(ABUSEIPDB_KEY),
        }

@app.route("/api/all")
def api_all():
    return jsonify(snap())

@app.route("/api/threats")
def api_threats():
    sev  = request.args.get("severity","all")
    cat  = request.args.get("category","all")
    tt   = request.args.get("type","all")
    page = max(1, int(request.args.get("page",1)))
    per  = min(200, int(request.args.get("per",50)))

    with lock:
        log = list(state["threat_log"])

    if sev != "all": log = [t for t in log if t.get("severity") == sev]
    if cat != "all": log = [t for t in log if t.get("category") == cat]
    if tt  != "all": log = [t for t in log if tt in t.get("threat_type","")]

    total = len(log)
    start = (page-1)*per
    return jsonify({"threats":log[start:start+per],"total":total,
                    "page":page,"pages":max(1,(total+per-1)//per)})

@app.route("/api/threats/clear", methods=["POST"])
def api_clear_threats():
    with lock:
        state["threat_log"]  = []
        state["live_alerts"] = deque(maxlen=300)
        state["total_alerts"] = 0
    save_json(THREAT_LOG_FILE, [])
    return jsonify({"status":"cleared"})

@app.route("/api/threats/export")
def api_export():
    with lock:
        return jsonify(list(state["threat_log"]))

@app.route("/api/reputation/<ip>")
def api_rep(ip):
    r = check_reputation(ip)
    return jsonify(r or {"error":"private or invalid IP"})

@app.route("/api/status")
def api_status():
    with lock:
        return jsonify({
            "status":"running","time":ts_full(),
            "alerts":state["total_alerts"],
            "log_file":str(THREAT_LOG_FILE),
            "abuseipdb": bool(ABUSEIPDB_KEY),
        })

@app.route("/")
def index():
    return "<h3>Network Monitor v3.0 running — open dashboard.html</h3>"


# ──────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 62)
    print("  Network Monitor v3.0 — Threat Intelligence Edition")
    print("=" * 62)
    print(f"  Python      : {platform.python_version()}")
    print(f"  Scapy       : {'YES' if SCAPY_AVAILABLE else 'NO (pip install scapy)'}")
    print(f"  AbuseIPDB   : {'LIVE checks enabled' if ABUSEIPDB_KEY else 'offline mode'}")
    print(f"  Threat log  : {THREAT_LOG_FILE}")
    print(f"  Saved threats loaded: {len(_saved_threats)}")
    print(f"  API         : http://localhost:{PORT}/api/all")
    print("=" * 62)
    print("  Open dashboard.html in your browser.")
    print("  Press Ctrl+C to stop. Threats are saved automatically.")
    print("=" * 62)

    threading.Thread(target=collection_loop, daemon=True).start()
    threading.Thread(target=reputation_worker, daemon=True).start()

    time.sleep(1.5)
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
