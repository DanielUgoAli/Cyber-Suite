import requests
import sqlite3
import json
import datetime
import ipwhois
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

DB_FILE = "scan_results.db"

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            source TEXT,
            risk_level TEXT,
            score INTEGER,
            flagged INTEGER,
            isp TEXT,
            country TEXT,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# --- WHOIS Lookup ---
def whois_lookup(ip):
    try:
        obj = ipwhois.IPWhois(ip)
        results = obj.lookup_rdap()
        isp = results.get("network", {}).get("name", "Unknown")
        country = results.get("asn_country_code", "Unknown")
        return isp, country
    except Exception:
        return "Unknown", "Unknown"

# --- AbuseIPDB Check ---
def check_abuseipdb(ip, api_key):
    if not api_key:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json()["data"]
        score = data["abuseConfidenceScore"]
        risk = "SAFE"
        if score >= 70:
            risk = "HIGH"
        elif score >= 30:
            risk = "MEDIUM"
        elif score > 0:
            risk = "LOW"
        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "risk": risk,
            "score": score,
            "flagged": score > 0,
            "isp": data.get("isp", "Unknown"),
            "country": data.get("countryCode", "Unknown"),
            "status": "Checked"
        }
    except Exception:
        return None

# --- VirusTotal Check ---
def check_virustotal(ip, api_key):
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()["data"]
        malicious = data["attributes"]["last_analysis_stats"]["malicious"]
        score = malicious
        risk = "SAFE"
        if score >= 10:
            risk = "HIGH"
        elif score >= 3:
            risk = "MEDIUM"
        elif score > 0:
            risk = "LOW"
        return {
            "source": "VirusTotal",
            "ip": ip,
            "risk": risk,
            "score": score,
            "flagged": score > 0,
            "isp": data["attributes"].get("as_owner", "Unknown"),
            "country": data["attributes"].get("country", "Unknown"),
            "status": "Checked"
        }
    except Exception:
        return None

# --- Save to DB ---
def save_result(result):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (ip, source, risk_level, score, flagged, isp, country, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (result["ip"], result["source"], result["risk"], result["score"],
          int(result["flagged"]), result["isp"], result["country"], result["status"]))
    conn.commit()
    conn.close()

# --- Export Results ---
def export_results(all_results, whois_results, fmt="txt"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if fmt == "txt":
        lines = []
        lines.append("Manual IP Scan Results")
        lines.append(f"Date: {timestamp}\n")

        # Group by source
        sources = {}
        for r in all_results:
            sources.setdefault(r["source"], []).append(r)

        for source, results in sources.items():
            lines.append(f"=== {source} Results ===")
            for r in results:
                lines.append(f"{r['ip']} | Risk: {r['score']} ({r['risk']}) | "
                             f"Flagged: {r['flagged']} | ISP: {r['isp']} | "
                             f"Country: {r['country']} | Status: {r['status']}")
            lines.append("")

        # WHOIS always added
        lines.append("=== WHOIS Lookup (Standardized Reference) ===")
        for ip, (isp, country) in whois_results.items():
            lines.append(f"{ip} | ISP: {isp} | Country: {country}")
        lines.append("")

        # Notes
        lines.append("=== Notes ===")
        lines.append("ISP and Country values may differ between sources (AbuseIPDB, VirusTotal, WHOIS).")
        lines.append("WHOIS lookup is recommended as the authoritative reference for ISP/Country data.\n")

        # Summary
        summary = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0}
        for r in all_results:
            summary[r["risk"].capitalize()] += 1
        lines.append("=== Summary ===")
        lines.append(f"- High   : {summary['High']}")
        lines.append(f"- Medium : {summary['Medium']}")
        lines.append(f"- Low    : {summary['Low']}")
        lines.append(f"- Safe   : {summary['Safe']}")

        filename = "scan_results.txt"
        with open(filename, "w") as f:
            f.write("\n".join(lines))
        print(f"[+] Results saved to {filename}")

    elif fmt == "json":
        data = {"results": all_results, "whois": whois_results, "timestamp": timestamp}
        filename = "scan_results.json"
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Results saved to {filename}")

# --- Main ---
def main():
    print("=== Manual IP Scanner (AbuseIPDB + VirusTotal + WHOIS) ===")
    ips = input("Enter IPs to check (comma/space separated): ").replace(",", " ").split()
    abuse_key = input("Enter AbuseIPDB API key (or leave blank to skip): ").strip()
    vt_key = input("Enter VirusTotal API key (or leave blank to skip): ").strip()

    print("\n[*] Checking IPs...\n")
    init_db()
    all_results = []
    whois_results = {}

    for ip in ips:
        if abuse_key:
            r = check_abuseipdb(ip, abuse_key)
            if r:
                all_results.append(r)
                save_result(r)
                color = Fore.RED if r["risk"] == "HIGH" else Fore.YELLOW if r["risk"] == "MEDIUM" else Fore.GREEN
                print(color + f"[AbuseIPDB] {ip} - {r['risk']} (Score: {r['score']})")

        if vt_key:
            r = check_virustotal(ip, vt_key)
            if r:
                all_results.append(r)
                save_result(r)
                color = Fore.RED if r["risk"] == "HIGH" else Fore.YELLOW if r["risk"] == "MEDIUM" else Fore.GREEN
                print(color + f"[VirusTotal] {ip} - {r['risk']} (Score: {r['score']})")

        # Always do WHOIS
        isp, country = whois_lookup(ip)
        whois_results[ip] = (isp, country)

    # Summary
    print("\n=== Scan Summary ===")
    summary = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0}
    for r in all_results:
        summary[r["risk"].capitalize()] += 1
    print(f"High   : {summary['High']}")
    print(f"Medium : {summary['Medium']}")
    print(f"Low    : {summary['Low']}")
    print(f"Safe   : {summary['Safe']}")

    # Export
    choice = input("\nExport results? (json/txt/skip): ").strip().lower()
    if choice in ["json", "txt"]:
        export_results(all_results, whois_results, fmt=choice)

if __name__ == "__main__":
    main()
