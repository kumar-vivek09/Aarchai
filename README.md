# Aarchai 🔍

> Automated Reconnaissance & Penetration Testing Framework for Kali Linux

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple?style=flat-square&logo=linux)](https://kali.org)
[![FastAPI](https://img.shields.io/badge/Web%20UI-FastAPI-teal?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)

Aarchai is a fully automated, modular, AI-powered recon and pentest framework that runs a **14-stage pipeline** covering every phase of an engagement — from passive OSINT to active exploitation path analysis.

---

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| **Passive Recon** | whois, crt.sh, Shodan, amass, theHarvester, ASN/BGP, HIBP breach check |
| **Active Recon** | subfinder, gobuster, nmap — fully parallel via `asyncio.gather()` |
| **Web Scanning** | httpx, nikto, wafw00f, whatweb, Playwright screenshots |
| **Fingerprinting** | JS framework detection, form discovery, tech stack identification |
| **Vulnerability** | nuclei, sqlmap, wpscan, testssl.sh, sslscan |
| **Secret Detection** | gitleaks, 20+ exposed file checks, JS secret scanning, default credentials |
| **Cloud Discovery** | S3/Azure/GCP bucket enumeration, metadata SSRF endpoint |
| **API Security** | Swagger/OpenAPI, GraphQL introspection, JWT, CORS, arjun, kiterunner |
| **OSINT** | Email harvest, breach check, social media footprint, cert monitoring |
| **Network Topology** | arp-scan, traceroute, D3.js network diagram |
| **AD/Kerberos** | LDAP enum, kerbrute, AS-REP roasting, SMB signing check, BloodHound |
| **Advanced** | Subdomain takeover (14 services), WAF bypass, screenshot diff |
| **Intel** | CISA KEV, Exploit-DB, GitHub PoC, Metasploit module lookup |
| **AI Analysis** | Red team kill chain, exploit chain builder, STRIDE threat model |
| **Compliance** | OWASP Top 10, PCI-DSS v4.0, ISO 27001:2022, NIST CSF 2.0 |

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/kumar-vivek09/Aarchai.git
cd Aarchai

# 2. Install tools
sudo bash setup.sh

# 3. Install Python dependencies
pip3 install -r requirements.txt
playwright install chromium

# 4. Configure
cp .env.example .env
nano .env   # add your API keys + DB URL

# 5. Initialize database
python3 aarchai.py init
alembic upgrade head

# 6. Launch interactive menu
python3 menu.py
```

---

## 🖥️ Interactive Menu

Run `python3 menu.py` for a fully guided experience — no CLI knowledge needed:

```
  [ 1]  🌐  Full Scan              Complete 14-stage pipeline
  [ 2]  ⚡  Quick Scan             Fast mode — top tools only
  [ 3]  👁   Passive Only           No direct target contact
  [ 4]  🕸   Web App Scan          Web surface + vulnerabilities
  [ 5]  🌩   Cloud Scan            AWS/Azure/GCP asset discovery
  [ 6]  🔌  API Security Scan      REST/GraphQL/JWT/CORS testing
  [ 7]  🗺   Network Topology       Internal CIDR + network diagram
  [ 8]  🕵   OSINT Module          Employees, breaches, ASN, social
  [ 9]  🏰  AD/Kerberos Scan       Active Directory penetration test
  [10]  📋  View Recent Scans
  [11]  ✅  Triage Findings
  [12]  📊  Compliance Report       OWASP / PCI / ISO / NIST
  [13]  🔔  Monitor Target          Cron-based scheduled scanning
  [14]  🖥   Web Dashboard          http://localhost:8000
  [15]  🔗  Exploit Chain Builder   AI-powered attack path analysis
  [16]  🗡   STRIDE Threat Model
  [17]  🔑  Settings / API Keys
  [18]  🆙  Database Migrate
```

---

## 🌐 Web UI

Start the real-time dashboard:

```bash
python3 web/run.py
# Open http://localhost:8000
```

Features:
- **Live findings** via WebSocket as tools finish
- **D3.js attack graph** — target → subdomain → IP → port → CVE → exploit
- **Triage panel** — confirm / false positive / accept risk per finding
- **Confidence scores**, CISA KEV badges, exploit indicators
- **Red Team tab** — AI attacker perspective
- **Reports tab** — HTML, PDF, JSON, CSV download

---

## 📊 Reports Generated Per Scan

Every scan produces `reports/scan_<ID>/`:

| File | Description |
|------|-------------|
| `dashboard.html` | Interactive findings dashboard |
| `report.pdf` | Professional PDF report |
| `attacker_perspective.txt` | AI red team kill chain simulation |
| `exploit_chain.txt` | Step-by-step PoC attack commands |
| `threat_model_stride.html` | STRIDE threat model |
| `compliance_owasp.html` | OWASP Top 10 gap analysis |
| `compliance_pci.html` | PCI-DSS v4.0 compliance |
| `compliance_iso27001.html` | ISO 27001:2022 control assessment |
| `compliance_nist.html` | NIST CSF 2.0 assessment |
| `network_topology.html` | D3.js interactive network map |
| `findings.json` + `findings.csv` | Raw export |

---

## ⚙️ Configuration (`.env`)

```bash
# Database (PostgreSQL)
AARCHAI_DB_URL=postgresql://aarchai:password@localhost/aarchai

# APIs (all free tier)
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
NVD_API_KEY=

# LLM for AI reports (optional)
LLM_PROVIDER=stub          # stub | ollama | openai
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
OPENAI_API_KEY=

# Alerts
SLACK_WEBHOOK_URL=
ALERT_EMAIL=
```

---

## 🏗️ Architecture

```
menu.py / aarchai.py (CLI)
          │
    stages/runner.py
          │
  ┌───────┼───────────────────┐
  │       │                   │
14 Stages  utils/          output/
  │       ├─ scope.py        ├─ html_dashboard.py
  │       ├─ confidence.py   ├─ pdf_report.py
  │       ├─ exploit_chain.py├─ json_export.py
  │       ├─ threat_model.py └─ compliance.py
  │       ├─ exploit_mapper.py
  │       └─ rate_limiter.py
  │
  ├─ core/         (DB, job manager, target parser)
  ├─ normalizer/   (parsers + dedup + schema)
  ├─ diff_engine/  (snapshot + cross-scan diff)
  ├─ plugins/      (drop-in tool plugins)
  ├─ alembic/      (DB migrations)
  └─ web/          (FastAPI + WebSocket + D3.js)
```

---

## 📋 CLI Reference

```bash
python3 aarchai.py scan --target example.com
python3 aarchai.py scan --target 192.168.1.0/24 --stages 11,12
python3 aarchai.py scan --target example.com --exclude internal.example.com --fast
python3 aarchai.py compliance  --scan-id 1 --framework owasp
python3 aarchai.py exploit-chain --scan-id 1
python3 aarchai.py threat-model  --scan-id 1
python3 aarchai.py triage 1 42 --status false_positive
python3 aarchai.py suppress --tool nikto --reason "too noisy"
python3 aarchai.py db       # run alembic migrations
python3 aarchai.py list     # list recent scans
python3 aarchai.py web      # start web UI
```

---

## 📦 Requirements

- **OS**: Kali Linux (recommended) / Ubuntu 22+
- **Python**: 3.11+
- **Database**: PostgreSQL
- **Tools**: nmap, nuclei, amass, subfinder, gobuster, theHarvester, gitleaks, and more (installed by `setup.sh`)

---

## ⚠️ Legal Disclaimer

> Aarchai is intended for **authorized security testing only**.  
> Only run against systems you own or have explicit written permission to test.  
> Unauthorized use is illegal and unethical. The developers assume no liability.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
