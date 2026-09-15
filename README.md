<p align="center">
  <img src="assets/logo.jpg" alt="jsXray Logo" width="700">
</p>

<p align="center">
  <strong>High-Performance JavaScript Security Intelligence & Secrets Scanner</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-38BDF8.svg?style=flat-square" alt="Python Version">
  <img src="https://img.shields.io/badge/AST-Tree--Sitter-6366F1.svg?style=flat-square" alt="Tree-sitter">
  <img src="https://img.shields.io/badge/Secret_Rules-560%2B-10B981.svg?style=flat-square" alt="Secret Rules">
  <img src="https://img.shields.io/badge/License-MIT-F59E0B.svg?style=flat-square" alt="License">
</p>

---

## ⚡ Overview

**jsXray** is a standalone, high-performance static analysis tool designed for security researchers, bug bounty hunters, and penetration testers to extract actionable attack surfaces from minified JavaScript bundles and single-page applications.

> *You discover the JavaScript URLs. jsXray extracts the attack surface, hidden routes, parameters, and credentials.*

---

## 🎯 Key Features

- **Zero Node.js Runtime Dependencies**: 100% Python engine powered by native C bindings for Tree-sitter.
- **560+ Secret & Token Signatures**: Provider-specific regex signatures with verification checksums and false-positive suppression (AWS, OpenAI, GitHub, Stripe, Google Cloud, Twilio, SendGrid, JWT, Slack, and hundreds more).
- **Subdomain & In-Scope API Host Scoping**: Automatically identifies in-scope subdomains and third-party APIs using `-d / --domain`.
- **AST Constant Reconstruction**: Propagates string concatenations, template literals, Base64/Hex decodings, and array lookups statically without code execution.
- **15+ Surface Analyzers**:
  - 📡 REST & Dynamic API Endpoints (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`)
  - 🌐 Application Routes & Navigation Paths
  - 🏷️ Query, Body, and Path Parameters
  - 🏢 In-Scope Subdomains & External API Providers
  - 🔑 Secrets, Tokens, and Hardcoded Credentials
  - 🔐 Auth Headers (`Bearer`, `Basic`, `OAuth`) & Login Endpoints
  - ⚡ GraphQL Operations & WebSocket/SSE Endpoints
  - ⚠️ Dangerous DOM Sinks (`innerHTML`, `location.href`, `eval`)
  - 📦 Tech Stack & Framework Detection (React, Vue, Svelte, Vite, Webpack)
  - 🗺️ Source Map Discovery (`.map`) & Dynamic Module Chunks
- **Self-Contained Offline HTML Report**: Dark-mode interactive dashboard with instant search, confidence filters, exact source line previews, and one-click list export (`📋 Copy List`).

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/bashx7/jsxray.git
cd jsxray

# Install locally
pip install .
```

```text
       _      __  __                  
      (_)___  \ \/ /_ __ __ _ _   _  
      | / __|  \  /| '__/ _` | | | | 
      | \__ \  /  \| | | (_| | |_| | 
     _/ |___/ /_/\_\_|  \__,_|\__, | 
    |__/                      |___/  
  [ JavaScript Security & Secrets Scanner ] - v1.0.0
  Created by Salman (aka @bashx7)
```


---

## 💻 Usage

```bash
# 1. Scan a list of JS URLs (Root domain is auto-inferred)
python3 -m jsxray -uf urls.txt -o report.html

# 2. Scan a local directory of JS files with target domain scoping
python3 -m jsxray -jf ./js-dist/ -d target.com -o report.html

# 3. Fast multi-threaded scan with custom concurrency
python3 -m jsxray -uf urls.txt --concurrency 25 --timeout 15 -o report.html
```

### CLI Options

| Flag | Description |
| :--- | :--- |
| `-uf`, `--url-file FILE` | File containing JavaScript URLs (one per line) |
| `-jf`, `--js-file PATH` | Local JavaScript file or directory to scan recursively |
| `-d`, `--domain DOMAIN` | Target domain to scope in-scope subdomains (e.g. `example.com`) |
| `-o`, `--output REPORT` | Output HTML report file path (default: `jsxray-results.html`) |
| `--concurrency N` | Number of concurrent download workers (default: `10`) |
| `--timeout SEC` | HTTP request timeout in seconds (default: `10`) |
| `--insecure` | Disable SSL/TLS certificate validation |
| `-v`, `--version` | Display version information |

---

## 📊 Interactive HTML Report

Each scan outputs a single self-contained HTML file containing:
- **Metrics Grid**: Instant breakdown of endpoints, secrets, parameters, and technologies.
- **One-Click Copy**: Grab clean, newline-delimited lists of endpoints, parameters, or subdomains directly for tool pipelines (`ffuf`, `nuclei`, `httpx`, `sqlmap`).
- **Code Drawer**: Inspect the exact file and line number where any endpoint or token was discovered.
- **Correlation Tree**: Host-to-endpoint visual mapping.

---

## 👤 Author

**Salman** (aka **@bashx7**)
* GitHub: [@bashx7](https://github.com/bashx7)
* LinkedIn: [@bashx7](https://www.linkedin.com/in/bashx7/)

---



