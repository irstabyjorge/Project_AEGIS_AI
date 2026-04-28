# Project AEGIS AI

**AI-Powered Threat Intelligence & Security Platform**

Project AEGIS AI combines machine learning, real-time network analysis, and the QByte-22 threat scoring engine to provide autonomous security monitoring and intelligent threat response.

---

## Components

| Module | File | Purpose |
|--------|------|---------|
| **QByte-22 Engine** | `qbyte_engine.py` | Production IP threat scoring with 50+ signal vectors |
| **AEGIS Unified** | `aegis_unified.py` | Full security platform with interactive CLI |
| **AEGIS OMNI-XEON** | `aegis_omni.py` | Autonomous security operations with ML prediction |
| **AEGIS Real** | `aegis_real.py` | Live system monitoring and forensic analysis |

## Key Capabilities

- **Real IP Threat Scoring** — Tor exit nodes, scanner nets, threat intel feeds, bogon ranges
- **ML Threat Prediction** — Random Forest trained on real threat history
- **Live Network Scanning** — Real-time connection analysis with auto-blocklisting
- **Auth Log Auditing** — Failed login detection, privilege escalation monitoring
- **Firewall Inspection** — UFW and iptables status reporting
- **Session Tracking** — Cross-scan velocity analysis for persistent threats

## Security Modules

### API Server (`modules/api_server.py`)
REST API exposing all AEGIS capabilities over HTTP. Zero external dependencies.

| Endpoint | Description |
|----------|-------------|
| `GET /api/status` | System health overview |
| `GET /api/threats` | Scan live connections with QByte-22 |
| `GET /api/scan/<ip>` | Analyze specific IP threat level |
| `GET /api/connections` | Active network connections |
| `GET /api/entropy` | Generate cryptographic key material |
| `GET /api/blocklist` | Auto-blocked IP list |
| `GET /api/uptime` | Service availability report |
| `GET /api/logs/analysis` | System log security analysis |
| `GET /api/predict` | ML-based threat prediction |

### Log Analyzer (`modules/log_analyzer.py`)
Pattern-based security log analysis — scans auth.log, syslog, kern.log for brute force, privilege escalation, SSH scanning, suspicious commands, and firewall changes.

### Uptime Monitor (`modules/uptime_monitor.py`)
Service availability tracking with HTTP endpoint monitoring, TCP port checks, DNS resolution, and SSL certificate expiry warnings.

### Vulnerability Scanner (`modules/vuln_scanner.py`)
Local system security assessment: SUID files, world-writable files, SSH config, firewall, exposed ports, sensitive file permissions, kernel hardening (ASLR, ptrace, core dumps). Produces a 0-10 security score.

## Quick Start

```bash
git clone https://github.com/irstabyjorge/Project_AEGIS_AI.git
cd Project_AEGIS_AI
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 aegis_unified.py
```

## License

- **Personal & Academic**: Free under [MIT License](LICENSE)
- **Commercial**: See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)

## Author

**Jorge Francisco Paredes** (irstabyjorge) — IRSTAXBYJORGE@GMAIL.COM

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-GitHub-ea4aaa?logo=github)](https://github.com/sponsors/irstabyjorge)

---

Copyright (c) 2024-2026 Jorge Francisco Paredes. All rights reserved.
