#!/usr/bin/env python3
"""
async_subenum.py
Subdomain Enumeration using Async DNS & APIs
Optionally runs Shodan lookups in parallel for public IPs
"""

import asyncio
import aiodns
import time
from pathlib import Path
import argparse
import aiohttp
import os
import json
import ipaddress
from dotenv import load_dotenv
from shodan import Shodan, APIError

# ===== Colors =====
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ===== Ensure .env =====
ENV_PATH = Path.home() / ".env"
if not ENV_PATH.exists():
    with open(ENV_PATH, "w") as f:
        f.write("VIRUSTOTAL_API_KEY=\n")
        f.write("SECURITYTRAILS_API_KEY=\n")
        f.write("ALIENVAULT_API_KEY=\n")
        f.write("SHODAN_API_KEY=\n")
    print(f"{YELLOW}[+] Created {ENV_PATH} with placeholder API keys{RESET}")

load_dotenv(ENV_PATH)

# ===== Helper: Public/Private IP check =====
def ip_type(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return "Private" if ip_obj.is_private else "Public"
    except ValueError:
        return "Unknown"

# ===== Save results =====
def save_results(domain, live_subdomains, elapsed, txt_file=None, json_file=None):
    if txt_file:
        lines = []
        for sub, ips in live_subdomains:
            lines.append(f"[LIVE] {sub}")
            for ip in ips:
                lines.append(f"    IP: {ip} ({ip_type(ip)})")
            lines.append("")
        lines.append(f"Total unique live subdomains: {len(live_subdomains)}")
        lines.append(f"Scan completed in {elapsed:.2f} seconds")
        Path(txt_file).write_text("\n".join(lines))
        print(f"{YELLOW}[+] TXT results saved to {txt_file}{RESET}")

    if json_file:
        data = {
            "domain": domain,
            "total_live_subdomains": len(live_subdomains),
            "scan_time_seconds": round(elapsed, 2),
            "results": [
                {"subdomain": sub, "ips": [{"ip": ip, "type": ip_type(ip)} for ip in ips]}
                for sub, ips in live_subdomains
            ]
        }
        Path(json_file).write_text(json.dumps(data, indent=4))
        print(f"{YELLOW}[+] JSON results saved to {json_file}{RESET}")

# ===== DNS Resolver =====
async def resolve_subdomain(resolver, subdomain):
    try:
        result_a = await resolver.query(subdomain, 'A')
        return subdomain, sorted({r.host for r in result_a})
    except aiodns.error.DNSError:
        return None, None

# ===== Brute-force =====
async def brute_force_subdomains(domain, wordlist_path, seen_subdomains, filter_ip=True, concurrency=200):
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    words = [
        f"{w.strip()}.{domain}"
        for w in Path(wordlist_path).read_text(errors="ignore").splitlines()
        if w.strip() and not w.startswith("#")
    ]
    print(f"{YELLOW}[+] Loaded {len(words)} subdomain candidates{RESET}")

    live_subdomains, seen_items = [], set()
    sem = asyncio.Semaphore(concurrency)

    async def worker(sub):
        async with sem:
            sub, ips = await resolve_subdomain(resolver, sub)
            if sub and ips and sub not in seen_subdomains:
                seen_subdomains.add(sub)
                key = tuple(ips) if filter_ip else sub
                if key not in seen_items:
                    seen_items.add(key)
                    live_subdomains.append((sub, ips))
                    print(f"{GREEN}[LIVE]{RESET} {sub} -> {', '.join(ips)}")

    await asyncio.gather(*(worker(sub) for sub in words))
    return live_subdomains

# ===== API Subdomain Fetch =====
async def fetch_api_subdomains(domain):
    api_results = set()
    async with aiohttp.ClientSession() as session:
        # VirusTotal
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if vt_key:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": vt_key}
            try:
                while url:
                    async with session.get(url, headers=headers) as r:
                        if r.status != 200:
                            break
                        data = await r.json()
                        for item in data.get("data", []):
                            api_results.add(item.get("id"))
                        url = data.get("links", {}).get("next")
                print(f"{YELLOW}[+] VirusTotal returned {len(api_results)} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] VT API error: {e}{RESET}")

        # SecurityTrails
        st_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()
        if st_key:
            try:
                async with session.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    headers={"APIKEY": st_key}
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        for s in data.get("subdomains", []):
                            api_results.add(f"{s}.{domain}")
                        print(f"{YELLOW}[+] SecurityTrails returned {len(data.get('subdomains', []))} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] ST API error: {e}{RESET}")

        # AlienVault OTX
        av_key = os.getenv("ALIENVAULT_API_KEY", "").strip()
        if av_key:
            try:
                async with session.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                    headers={"X-OTX-API-KEY": av_key}
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        for entry in data.get("passive_dns", []):
                            if entry.get("hostname"):
                                api_results.add(entry["hostname"])
                        print(f"{YELLOW}[+] AlienVault returned {len(data.get('passive_dns', []))} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] AlienVault API error: {e}{RESET}")

    return sorted(s for s in api_results if s and s.endswith(domain))

# ===== Resolve API subdomains =====
async def resolve_api_subdomains(subdomains, seen_subdomains, filter_ip=True, concurrency=200):
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    live_subdomains, seen = [], set()
    sem = asyncio.Semaphore(concurrency)

    async def worker(sub):
        async with sem:
            sub_resolved, ips = await resolve_subdomain(resolver, sub)
            if sub_resolved and ips and sub_resolved not in seen_subdomains:
                seen_subdomains.add(sub_resolved)
                key = tuple(ips) if filter_ip else sub_resolved
                if key not in seen:
                    seen.add(key)
                    live_subdomains.append((sub_resolved, ips))
                    print(f"{GREEN}[LIVE]{RESET} {sub_resolved} -> {', '.join(ips)}")

    if subdomains:
        await asyncio.gather(*(worker(sub) for sub in subdomains))
    return live_subdomains


async def _shodan_lookup(ip, api):
    loop = asyncio.get_event_loop()
    try:
        data = await loop.run_in_executor(None, api.host, ip)
        if isinstance(data, dict) and "error" in data:
            if any(msg in data["error"] for msg in ["403", "Access denied", "No information available"]):
                return None
        return ip, {
            "ip": data.get("ip_str"),
            "org": data.get("org"),
            "os": data.get("os"),
            "ports": data.get("ports"),
            "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else []
        }
    except APIError as e:
        if any(msg in str(e) for msg in ["403", "Access denied", "No information available"]):
            return None
        return None

# ===== Shodan Async =====
async def fetch_shodan_data(ip, api, rate_limit, fast_mode=False):
    async with rate_limit:
        if not fast_mode:
            await asyncio.sleep(1)  # Safe mode delay
        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, api.host, ip)

            # Skip results with errors
            if isinstance(data, dict) and "error" in data:
                if any(msg in data["error"] for msg in ["403", "Access denied", "No information available"]):
                    return None

            return ip, {
                "ip": data.get("ip_str"),
                "org": data.get("org"),
                "os": data.get("os"),
                "ports": data.get("ports"),
                "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else []
            }

        except APIError as e:
            if any(msg in str(e) for msg in ["403", "Access denied", "No information available"]):
                return None
            return None

async def query_shodan_async(ip_list, domain, fast_mode=False):
    if not ip_list:
        print(f"{YELLOW}[+] No public IPs found — skipping Shodan query.{RESET}")
        return
    shodan_key = os.getenv("SHODAN_API_KEY", "").strip()
    if not shodan_key:
        print(f"{RED}[-] Shodan API key not set — skipping Shodan query.{RESET}")
        return

    api = Shodan(shodan_key)
    rate_limit = asyncio.Semaphore(1)  # Limit concurrency
    print(f"{YELLOW}[+] Querying Shodan for {len(ip_list)} IP(s)...{RESET}")

    # Run all requests
    results = await asyncio.gather(*(fetch_shodan_data(ip, api, rate_limit, fast_mode) for ip in ip_list))

    # Remove None values before saving
    cleaned_results = {ip: data for item in results if item for ip, data in [item]}

    Path(f"{domain}_shodan.json").write_text(json.dumps(cleaned_results, indent=4))
    print(f"{YELLOW}[+] Shodan results saved to {domain}_shodan.json{RESET}")

# ===== Main =====
async def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool with Shodan Integration")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument("--api", action="store_true", help="Use API-based enumeration")
    parser.add_argument("--shodan", action="store_true", help="Run Shodan lookups")
    parser.add_argument("--fast", action="store_true", help="Run Shodan without delay (may hit rate limits)")
    parser.add_argument("-df", "--dont-filter-ip", action="store_true", help="Do not filter by IP set")
    parser.add_argument("-oT", "--output-txt", help="Save results in TXT format")
    parser.add_argument("-oJ", "--output-json", help="Save results in JSON format")
    args = parser.parse_args()

    filter_ip = not args.dont_filter_ip
    seen_subdomains = set()
    start_time = time.time()

    print(f"{YELLOW}[+] Starting async subdomain enumeration for {args.domain}{RESET}")
    print(f"{YELLOW}[i] Filtering by IP is {'ON' if filter_ip else 'OFF'}{RESET}")

    tasks = []
    if args.wordlist:
        tasks.append(brute_force_subdomains(args.domain, args.wordlist, seen_subdomains, filter_ip))
    if args.api:
        async def api_task():
            api_subs = await fetch_api_subdomains(args.domain)
            return await resolve_api_subdomains(api_subs, seen_subdomains, filter_ip)
        tasks.append(api_task())

    live_results = await asyncio.gather(*tasks)
    live_subs_total = [item for sublist in live_results for item in sublist]

    elapsed = time.time() - start_time
    print(f"\n{GREEN}[+] Found {len(live_subs_total)} unique live subdomains in {elapsed:.2f} seconds{RESET}")

    if args.output_txt or args.output_json:
        save_results(args.domain, live_subs_total, elapsed, txt_file=args.output_txt, json_file=args.output_json)

    if args.shodan:
        public_ips = sorted({ip for _, ips in live_subs_total for ip in ips if ip_type(ip) == "Public"})
        await query_shodan_async(public_ips, args.domain, fast_mode=args.fast)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{RED}[-] Interrupted by user{RESET}")
