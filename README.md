# SubEnum

**SubEnum** is a fast asynchronous subdomain enumeration tool built in Python.  
It supports **wordlist-based brute forcing** and **API-based discovery** (VirusTotal, SecurityTrails, AlienVault), filtering duplicates by unique IP sets.  

---

## Features

- ⚡ Asynchronous DNS resolution with [`aiodns`](https://pypi.org/project/aiodns/)  
- 🌍 Uses Cloudflare DNS (`1.1.1.1`, `1.0.0.1`)  
- 🔎 Filters duplicate subdomains (based on IP sets)  
- 🎨 Color-coded output for better visibility  
- 🛠️ Supports both **wordlist brute force** and **API-based enumeration**  
- 🔑 API keys loaded securely via `.env` file  

---
