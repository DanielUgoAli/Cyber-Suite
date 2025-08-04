import nmap
import requests
import json


def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV')  # Top 1000 ports with version detection
    open_ports = []
    if ip not in scanner.all_hosts():
        print(f"[!] Host {ip} could not be scanned.")
        return open_ports
    for proto in scanner[ip].all_protocols():
        for port in scanner[ip][proto]:
            port_data = scanner[ip][proto][port]
            if port_data['state'] == 'open':
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                banner = f"{product} {version}".strip() or port_data['name']
                open_ports.append((port, banner))
    return open_ports


def get_cves_with_details(banner):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={banner}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []
            for item in data.get("vulnerabilities", []):
                cve_id = item["cve"]["id"]
                metrics = item["cve"].get("metrics", {})
                score = "N/A"
                severity = "Unknown"

                if "cvssMetricV31" in metrics:
                    metric = metrics["cvssMetricV31"][0]
                    score = metric["cvssData"]["baseScore"]
                    severity = metric["cvssData"]["baseSeverity"]
                elif "cvssMetricV2" in metrics:
                    metric = metrics["cvssMetricV2"][0]
                    score = metric["cvssData"]["baseScore"]
                    severity = metric.get("baseSeverity", "Unknown")

                vulnerabilities.append({
                    "cve": cve_id,
                    "cvss_score": score,
                    "severity": severity
                })
            return vulnerabilities if vulnerabilities else "No vulnerabilities found"
    except requests.RequestException as e:
        print(f"[!] Error fetching CVEs for {banner}: {e}")
    return "No vulnerabilities found"


def main():
    ip = input("Enter target IP address: ")
    results = []

    for port, banner in scan_ports(ip):
        print(f"[*] Scanning Port {port} - {banner}")
        cve_details = get_cves_with_details(banner)
        if isinstance(cve_details, list):
            print(
                f"[+] Vulnerabilities found for port {port}: {len(cve_details)}")
        else:
            print(f"[-] {cve_details}")
        results.append({
            'port': port,
            'banner': banner,
            'vulnerabilities': cve_details
        })

    with open('scan_report.json', 'w') as f:
        json.dump({'target': ip, 'vulnerabilities': results}, f, indent=4)
    print("[+] Full JSON report saved to scan_report.json")


if __name__ == '__main__':
    main()
