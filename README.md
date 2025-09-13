# 🕶️ shadowEnum — Asynchronous Subdomain Enumeration & Recon Tool  

> *Uncover the unseen. Map the shadows.*  

shadowEnum is a **fast & async** subdomain enumeration + recon tool ⚡. It blends **brute-force DNS resolution** with **OSINT APIs** (VirusTotal, SecurityTrails, AlienVault OTX), and enriches results with **Shodan intelligence** 🔍.  

💡 Perfect for recon, bug bounty, and security research.  
⚠️ **Legal Disclaimer**: Only use shadowEnum on targets you own or have explicit permission to test.  

---

## 🚀 Features

⚡ **Asynchronous DNS Resolution**  
Uses `aiodns` with Cloudflare DNS (`1.1.1.1` & `1.0.0.1`) for fast, concurrent subdomain resolution.

📜 **Wordlist-Based Bruteforce**  
Supports custom subdomain wordlists for brute-force enumeration.

🌐 **Passive API-Based Enumeration (Optional)**  
Fetches subdomains from:
- 🧪 **VirusTotal API**
- 🔍 **SecurityTrails API**
- 🛡 **AlienVault OTX API**

🗂 **Duplicate Filtering (Default)**  
Filters subdomains that resolve to the same IP set (default mode).  
Option to disable filtering (`-df`) to reveal virtual hosts and multiple subdomains pointing to the same IP.

🛰 **Private / Public IP Detection**  
Automatically labels resolved IPs as `Public` or `Private`.

♻ **Global Deduplication**  
Ensures unique subdomain names across both wordlist and API results (prevents duplicate entries when a subdomain appears in multiple sources).

💾 **Customizable Output**  
- Save results in **TXT** format (`-oT`)  
- Save results in **JSON** format (`-oJ`)  
- Save results in **HTML** format (`-oH`)  

Each format includes:  
- Subdomain → IP mapping  
- IP classification (Public/Private)  
- Metadata (timestamps, total counts, duration)  
- Optional **Shodan enrichment** (open ports, CVEs, server info)

🔑 **Environment File Auto-Creation**  
Automatically creates `~/.env` with placeholders for API keys if missing.  
API keys are loaded securely from `.env` (via `python-dotenv`).

🔎 **Optional Shodan Enrichment (for Public IPs)**  
When enabled (`--shodan`) shadowEnum will query Shodan for public IPs and include:
- Organization & ASN
- Open ports & service banners
- Detected CVEs / vulnerabilities
- Basic OS / server fingerprinting

🧰 **CLI Flags & Controls**  
- `-w, --wordlist` — path to subdomain wordlist  
- `--api` — enable API-based enumeration (VirusTotal, SecurityTrails, OTX) 
- `--shodan` — enable Shodan enrichment (requires `SHODAN_API_KEY`)  
- `-df, --dont-filter-ip` — disable IP-based filtering (show all hostnames)  
- `-oT, --output-txt` — save TXT report  
- `-oJ, --output-json` — save JSON report  
- `-oH, --output-html` — save HTML report

---

## 📦 Installation

You can install and run **ShadowEnum** in two ways:

### 1. Run Directly with Python
```bash
# Clone the repo
git clone https://github.com/HusnainZargar/ShadowEnum.git
cd ShadowEnum

# Run directly
python3 shadowenum.py
```
### 2. Install System-wide (using install.sh)
```bash
# Clone the repo
git clone https://github.com/HusnainZargar/ShadowEnum.git
cd ShadowEnum

# Make install.sh executable
sudo chmod +x install.sh

# Run Install.sh
./install.sh
```
---

🛡 **Ethical Reminder**  
Only run shadowEnum against domains you own or have explicit permission to test. Unauthorized scanning may be illegal.
