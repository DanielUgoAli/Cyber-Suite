# simple_vuln_scanner.py

import nmap
import requests
import os

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_api_key():
    key = os.getenv("NVD_API_KEY")
    if not key:
        key = input("Enter your NVD API key: ").strip()
    return key

def scan_services(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV')
    results = []
    for proto in scanner[ip].all_protocols():
        for port in scanner[ip][proto]:
            if scanner[ip][proto][port]['state'] == 'open':
                name = scanner[ip][proto][port]['name']
                product = scanner[ip][proto][port].get('product', '')
                version = scanner[ip][proto][port].get('version', '')
                banner = f"{product} {version}".strip()
                results.append((port, banner or name))
    return results

def search_cve(banner, api_key):
    keyword = next((w for w in banner.split() if any(c.isalpha() for c in w)), 'Unknown')
    params = {"keywordSearch": keyword, "resultsPerPage": 1}
    headers = {"apiKey": api_key}
    try:
        res = requests.get(NVD_API_BASE, params=params, headers=headers)
        if res.status_code != 200:
            return None
        data = res.json()
        vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
        metrics = vuln.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        return {
            "cve_id": vuln.get("id", "N/A"),
            "score": metrics.get("baseScore", "N/A"),
            "severity": metrics.get("baseSeverity", "Unknown"),
            "desc": vuln.get("descriptions", [{}])[0].get("value", "")
        }
    except:
        return None

def main():
    ip = input("Target IP: ").strip()
    api_key = get_api_key()
    services = scan_services(ip)

    for port, banner in services:
        print(f"\n[+] Port {port} | Service: {banner}")
        cve = search_cve(banner, api_key)
        if cve:
            print(f"    CVE: {cve['cve_id']} | Score: {cve['score']} | Severity: {cve['severity']}")
            print(f"    Description: {cve['desc']}")
        else:
            print("    No CVE found.")


