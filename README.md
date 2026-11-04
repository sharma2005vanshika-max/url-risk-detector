# 🛡️ AegisGuard - Next-Gen URL Risk & Threat Intelligence Detector

A comprehensive, fully functional, and high-performance **URL Risk & Malicious Link Detection Website**. 

AegisGuard evaluates URLs across multiple vectors in real-time, detecting phishing pages, typosquatting, IDN homoglyph spoofs, raw IP malware hosts, deep subdomain camouflage, and expired SSL handshakes.

---

## ✨ Features

- **🎯 Real-Time URL Risk Scanner**:
  - Live animated SVG circular **Risk Meter** (0–100 score).
  - Risk categorization: **Safe** (0–20), **Low Risk** (21–45), **Suspicious** (46–70), and **Malicious** (71–100).
  - 6-Point Security Checklist (HTTPS, Active DNS, Valid SSL Certificate, Clean Character Encoding, Clean URL Structure, Reputation / Brand Spoofing Free).
  - Shannon Entropy calculator for host and path (flags DGA botnet domains).
  - Live DNS resolver (A, AAAA, MX, NS records).
  - Live SSL/TLS certificate probe (Issuer, Subject, Expiration, Days remaining).

- **📑 Batch URL Threat Scanner**:
  - Scan up to 30 URLs concurrently.
  - Analytics summary cards (Total, Safe, Suspicious, Malicious count, Average Score).
  - Filterable table with one-click full URL inspection.
  - Export reports to **CSV**.

- **🔒 Link Defanger & Sanitizer Tool**:
  - Bi-directional defanging (`https://` ⇄ `hxxps[://]`, `.` ⇄ `[.]`, `@` ⇄ `[@]`).
  - Safe sharing format for SOC incident reporting, email tickets, and slack channels.

- **📜 Security Audit History**:
  - Automatically compiles an audit log of inspected URLs stored in localStorage.
  - One-click inspection and log clearance.

- **🎓 Threat Intelligence Academy**:
  - Educational deep-dives on IDN Homograph Attacks, Typosquatting/Combosquatting, Shannon Entropy & DGAs, and Subdomain Cloaking.

- **⚡ Zero External Dependencies for Server**:
  - Built using Node.js native modules (`http`, `dns`, `tls`, `url`, `fs`, `path`).
  - No external database or paid API keys required out of the box.

---

## 🚀 Quick Start

### Option 1: Unified Full-Stack Server (Recommended)
Runs the unified backend API and serves the production frontend on port `5001`:

```bash
cd url-risk-detector
./start.sh
```

Or directly:
```bash
cd url-risk-detector/server
node server.js
```
Open **[http://localhost:5001](http://localhost:5001)** in your browser.

---

### Option 2: Frontend Development Mode
To develop and hot-reload the React frontend with Vite:

```bash
# Terminal 1: Backend API
cd url-risk-detector/server
node server.js

# Terminal 2: Vite Dev Server
cd url-risk-detector/client
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.

---

## 🧪 Running Automated Unit Tests

Verify the multi-vector detection engine across safe, typosquatted, homoglyph, and raw IP threat vectors:

```bash
cd url-risk-detector/server
node test-scanner.js
```

---

## 🏗️ Project Architecture

```
url-risk-detector/
├── start.sh                      # One-click launcher script
├── README.md                     # Documentation
├── server/
│   ├── package.json              # Server configuration
│   ├── server.js                 # HTTP Server & API endpoints + static file serving
│   ├── analyzer.js               # Multi-layer detection engine (lexical, DNS, SSL, brand)
│   └── test-scanner.js           # Automated test suite
└── client/
    ├── index.html                # HTML entrypoint
    ├── package.json              # Client dependencies
    ├── vite.config.ts            # Vite config with backend proxy
    ├── tailwind.config.js        # Cybersecurity dark-mode theme
    ├── src/
    │   ├── types.ts              # TypeScript interfaces
    │   ├── App.tsx               # Main application shell & tab routing
    │   ├── main.tsx              # React DOM render
    │   ├── index.css             # Cyber glow animations & base styles
    │   └── components/
    │       ├── Navbar.tsx        # Header & navigation
    │       ├── RiskGauge.tsx     # Animated SVG Risk Gauge
    │       ├── ScanResults.tsx   # Detailed analysis dashboard & checklist
    │       ├── BatchScanner.tsx  # Bulk scanning & CSV exporter
    │       ├── DefangerTool.tsx  # Interactive link defanger & refanger
    │       ├── ThreatHistory.tsx # Local audit log
    │       └── SecurityAcademy.tsx # Threat education & taxonomy
```
# url-risk-detector
