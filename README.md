# 🕶️ shadowEnum — Asynchronous Subdomain Enumeration & Recon Tool  

> *Uncover the unseen. Map the shadows.*  

ShadowEnum is a **fast & async** subdomain enumeration + recon tool ⚡. It blends **brute-force DNS resolution** with **OSINT APIs** (VirusTotal, SecurityTrails, AlienVault OTX), and enriches results with **Shodan intelligence** 🔍.  

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

# Now you can run ShadowEnum directly from anywhere using the command:
shadowenum example.com
```
---

## Configuration & API Keys

On first run, shadowEnum will create `~/.env` with placeholders. Populate it with your API keys:

```bash
VIRUSTOTAL_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
```
## ⚙️ Usage

Basic brute-force mode:
```bash
python3 shadowenum.py example.com -w wordlist.txt
```

API mode (requires API keys):
```bash
python3 shadowenum.py example.com -w wordlist.txt --api
```

Shodan mode (requires API keys):
```bash
python3 shadowenum.py example.com -w wordlist.txt --api --shodan
```
---
## 🌐 View HTML Report

ShadowEnum can generate an HTML report that you can open in any web browser for easy viewing and analysis.  

### Example

```bash
# Run ShadowEnum and save results as HTML
python3 shadowenum.py -w wordlist.txt -oH output.html example.com

# Open the report in Firefox
firefox output.html
```

The HTML report includes:
- Subdomain → IP mapping
- IP classification (Public/Private)
- Optional Shodan enrichment (organization, open ports, CVEs, server info)

> ⚠️ **Note:**  
> When running ShadowEnum with the `--shodan` flag, the Shodan enrichment details (open ports, CVEs, server information, etc.) **will not be displayed directly in the terminal**.  
> To view these details, you must save the output using one of the supported formats: `-oH` (HTML), `-oJ` (JSON), or `-oT` (TXT).  
> Once saved, you can open the HTML report in a browser or view the JSON/TXT files to access the full enrichment data.

---

## Example Output

```
                                                                                                                                                                    
                                             _________.__                .___            ___________                                                                
                                            /   _____/|  |__ _____     __| _/______  _  _\_   _____/ ____  __ __  _____                                             
                                            \_____  \ |  |  \\__  \   / __ |/  _ \ \/ \/ /|    __)_ /    \|  |  \/     \                                            
                                            /        \|   Y  \/ __ \_/ /_/ (  <_> )     / |        \   |  \  |  /  Y Y  \                                           
                                           /_______  /|___|  (____  /\____ |\____/ \/\_/ /_______  /___|  /____/|__|_|  /                                           
                                                   \/      \/     \/      \/                     \/     \/            \/                                            
                                                                                                                                                                    
                                                                   >>> By Team Cyber Hunters <<<                                                                    
                                                       LinkedIn: Black Byt3 | Email: blackbyt3.info@gmail.com                                                       
                                          Team Members: Mushaib Ahmed | Muhammad Husnain | Muhammad Aeiyan | Fawad Qureshi                  

[+] Starting async subdomain enumeration for example.com
[i] Filtering by IP is OFF
[+] Loaded 19967 subdomain candidates
[LIVE] www.shop.example.com -> 10.10.10.10
[LIVE] mail.example.com -> 10.10.10.10
[+] VirusTotal returned 32 subdomains
[LIVE] admissions.example.com -> 10.10.10.10
[+] AlienVault returned 70 subdomains
[LIVE] academic.example.com -> 10.10.10.10
[+] Found 49 unique live subdomains in 79.82 seconds
[+] Shodan lookups requested. Querying 9 public IP(s)...
[+] HTML report saved to output.html

```
---

## Contact

Maintainer: Muhammad Husnain — husnainzargar@proton.me

---
🛡 **Ethical Reminder**  
Only run shadowEnum against domains you own or have explicit permission to test. Unauthorized scanning may be illegal.
