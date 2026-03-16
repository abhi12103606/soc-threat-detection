# 🛡️ SOC Analyst: Log-Based Threat Detection & Network Intelligence System

A real-time Security Operations Center (SOC) dashboard built by a CS graduate with hands-on experience in fraud analysis and cybersecurity. Monitors live network traffic on Windows, detects threats using external intelligence feeds, flags malicious connections, hardware surveillance attempts, and suspicious processes — all with a persistent threat log.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D4)
![License](https://img.shields.io/badge/License-MIT-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red)

---

## 📸 Screenshots

> Dashboard running live on my Windows 11 machine (Grandhi Abhishek) — showing real network data with 150+ active connections

| Overview | Threat Log | Connections |
|---|---|---|
| Live CPU, Memory, Network charts | Persistent saved threats | External IPs with threat scores |

*Add your own screenshots here after running the project*

---

## 🔍 What It Does

I wanted to understand what a real SOC analyst sees day-to-day, so I built a lightweight personal SIEM (Security Information and Event Management) tool that runs locally on Windows. It:

- **Monitors all active network connections** on your machine in real time
- **Resolves every external IP** to its domain name via reverse DNS
- **Scores IPs for threat level** using AbuseIPDB and URLhaus threat feeds
- **Detects hardware surveillance** — flags processes accessing camera/mic while sending data externally
- **Saves all threats persistently** to `threat_log.json` — survives restarts
- **Maps detections to MITRE ATT&CK** techniques for professional SOC reporting

---

## ⚙️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  dashboard.html                      │
│         (Live UI — polls API every 4 seconds)        │
└─────────────────────┬───────────────────────────────┘
                      │ HTTP (localhost:5000)
┌─────────────────────▼───────────────────────────────┐
│                   monitor.py                         │
│              Flask REST API Backend                  │
├──────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │   psutil     │  │  AbuseIPDB  │  │  URLhaus   │  │
│  │ (live system │  │  (IP rep.)  │  │  (malware  │  │
│  │    data)     │  │             │  │   feed)    │  │
│  └──────────────┘  └─────────────┘  └────────────┘  │
│  ┌──────────────────────────────────────────────┐    │
│  │         threat_log.json  (persistent)        │    │
│  └──────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

---

## 🚨 Detection Capabilities

### Network Threat Intelligence
| Check | Source | Description |
|---|---|---|
| Malicious IP | AbuseIPDB (live) | IPs reported for abuse, C2, scanning |
| Malware domain | URLhaus (live feed) | Domains hosting malware/ransomware |
| Local blocklist | Built-in | TOR exits, phishing, cryptominers, RAT infra |
| Restricted sites | Built-in | Known piracy, exploit forums, dark web gateways |
| Suspicious ports | Built-in | Metasploit, TOR, backdoor, RAT ports |

### MITRE ATT&CK Mapped Rules
| Rule | MITRE ID | Trigger |
|---|---|---|
| Brute Force Login | T1110 | ≥5 failed auth in 60s |
| Lateral Movement | T1021 | SMB/RDP to multiple internal hosts |
| Data Exfiltration | T1041 | Bulk transfer or C2 channel |
| Malware Execution | T1055 | Office app spawning cmd.exe |
| Privilege Escalation | T1078 | User added to admin group |
| Network Recon | T1046 | Port scan across subnet |
| Log Tampering | T1562 | Audit log disabled |
| DNS Tunneling | T1071 | High-entropy DNS queries |

### Hardware Surveillance Detection
Detects processes accessing:
- 📷 **Camera** — webcam, imaging devices
- 🎤 **Microphone** — audio drivers, speech runtime
- 🖥️ **GPU** — DirectX, Vulkan, CUDA
- 🔌 **USB devices** — HID, USB storage
- 💾 **Disk** — raw copy tools

**Critical alert fires** when any hardware-accessing process simultaneously has an external network connection — strong indicator of spyware.

---

## 🗂️ Project Structure

```
soc-threat-detection/
│
├── monitor.py          # Python backend — data collection + Flask API
├── dashboard.html      # Live web dashboard — connects to API
├── threat_log.json     # Auto-generated — persistent threat storage
├── ip_cache.json       # Auto-generated — IP reputation cache (1hr TTL)
└── README.md
```

---

## 🚀 Installation & Setup

### Requirements
- Windows 10 / 11
- Python 3.8+
- Google Chrome / Edge / Firefox

### Step 1 — Install dependencies
```bash
pip install psutil flask flask-cors requests
```

### Step 2 — Optional: Enable live threat intelligence
Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/register) (1000 checks/day free).

Open `monitor.py` and set:
```python
ABUSEIPDB_KEY = "your_api_key_here"
```

### Step 3 — Run as Administrator
Right-click PowerShell → **Run as Administrator** (needed for full connection visibility):
```bash
python monitor.py
```

You should see:
```
============================================================
  Network Monitor v3.0 — Threat Intelligence Edition
============================================================
  API : http://localhost:5000/api/all
  Threat log : threat_log.json
  Press Ctrl+C to stop.
============================================================
```

### Step 4 — Open the dashboard
Double-click `dashboard.html` in your browser. It auto-connects to the API.

---

## 📡 API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/all` | Full snapshot — all data |
| `GET /api/threats` | Paginated threat log with filters |
| `GET /api/threats/export` | Download full threat log as JSON |
| `POST /api/threats/clear` | Clear all saved threats |
| `GET /api/reputation/<ip>` | Check reputation of any IP |
| `GET /api/status` | Health check |

### Threat log filters
```
GET /api/threats?severity=critical&category=Threat Intel&page=1&per=50
```

---

## 🧪 Testing

### Test 1 — Check IP reputation
```
http://localhost:5000/api/reputation/185.220.101.42
```
Expected: TOR exit node detected

### Test 2 — View all live connections
```
http://localhost:5000/api/all
```
Check the `connections` array — every external IP will have domain, country, and threat score

### Test 3 — Hardware access
Open your Camera app → check the **Hardware Access** tab in the dashboard

### Test 4 — Persistent log
Stop `monitor.py` → restart it → open **Threat Log** tab — all previous threats are still there

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3, Flask, Flask-CORS |
| System monitoring | psutil |
| Threat intelligence | AbuseIPDB API, URLhaus API |
| DNS resolution | socket (built-in) |
| Frontend | Vanilla HTML, CSS, JavaScript |
| Charts | Chart.js |
| Storage | JSON (flat file, no database needed) |
| Network scan | arp -a (Windows built-in) |
| OS | Windows 11 |

**Relevant skills from this project:** Python · Flask · REST API · Network Security · Log Analysis · Threat Intelligence · MITRE ATT&CK · SOC Analysis · JavaScript · Linux-compatible

---

## 📊 What Was Tested

- ✅ Tested live on **Windows 11** with real network traffic
- ✅ **150+ active connections** monitored and classified simultaneously
- ✅ Real-time CPU, Memory and Network throughput metrics confirmed accurate
- ✅ **Reverse DNS resolution** successfully resolving external IPs to domains
- ✅ Known malicious IP `185.220.101.42` (TOR exit node) correctly identified
- ✅ **URLhaus feed** auto-updates malicious domain list hourly
- ✅ Persistent threat log confirmed working across restarts
- ✅ Hardware access detection tested with Camera app on Windows 11

---

## 🔐 Privacy & Safety

- All monitoring is **local only** — no data leaves your machine
- The Flask API only listens on `localhost:5000` — not accessible from outside
- IP reputation checks are one-way lookups to public APIs (no personal data sent)
- `threat_log.json` is stored locally in the project folder only

---

## 🚧 Potential Improvements

- [ ] Email/SMS alerts for critical threats
- [ ] Scapy deep packet inspection (requires Npcap)
- [ ] SQLite database instead of JSON for larger logs
- [ ] Geo-IP map visualization of external connections
- [ ] Scheduled PDF report generation
- [ ] Windows Service auto-start on boot
- [ ] Integration with Splunk / Elastic SIEM

---

## 👨‍💻 Author

**Grandhi Abhishek**
B.Tech Computer Science — Lovely Professional University | Cybersecurity Enthusiast

- 📧 grandhiabhishek487@gmail.com
- 🔗 [linkedin.com/in/abhishek-grandhi-2556a3220](https://linkedin.com/in/abhishek-grandhi-2556a3220)

Built this as a personal hands-on project coming from a background in fraud analysis and cybersecurity. Having worked as a Chargeback Fraud Analyst reviewing high-volume financial transaction records to detect anomalous patterns, and previously as a Cybersecurity Intern analysing system and web activity logs — I wanted to apply that same analytical thinking to network-level threat detection and build a tool that actually monitors a real machine in real time rather than just studying theory.

---

## 📄 License

MIT License — free to use, modify and distribute.

---

## 🙏 Acknowledgements

- [AbuseIPDB](https://www.abuseipdb.com) — IP reputation database
- [URLhaus by abuse.ch](https://urlhaus.abuse.ch) — Malware URL feed
- [MITRE ATT&CK](https://attack.mitre.org) — Threat technique framework
- [psutil](https://github.com/giampaolo/psutil) — Cross-platform system monitoring
