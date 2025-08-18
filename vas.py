"""
Vulnerability Assessment Scanner (VAS) Module
Provides functionality to scan target IPs for open ports and known vulnerabilities.
"""

import nmap
import requests
import json
import re
import os
import ipaddress
from urllib.parse import quote_plus
import time
from typing import List, Tuple, Dict, Union, Optional


class VulnerabilityScanner:
    """Main vulnerability scanner class that handles port scanning and CVE lookups."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the vulnerability scanner.
        
        Args:
            api_key: Optional NVD API key for authentication
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.scan_results = []
    
    def validate_ip(self, ip: str) -> bool:
        """
        Validates if the input is a valid IP address.
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def scan_ports(self, ip: str) -> List[Tuple[int, str]]:
        """
        Scan ports on a target IP address.
        
        Args:
            ip: The target IP address to scan
            
        Returns:
            A list of tuples containing (port, banner) for open ports
        """
        if not self.validate_ip(ip):
            print(f"[!] Invalid IP address: {ip}")
            return []
        
        open_ports = []
        try:
            scanner = nmap.PortScanner()
            scanner.scan(ip, arguments='-sV')  # Top 1000 ports with version detection
            
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
        except nmap.PortScannerError as e:
            print(f"[!] Nmap scan error: {e}")
        except Exception as e:
            print(f"[!] Unexpected error during port scan: {e}")
            
        return open_ports
    
    def _sanitize_banner(self, banner: str) -> str:
        """
        Sanitize banner text to make it safe for API queries.
        
        Args:
            banner: The service banner to sanitize
            
        Returns:
            Sanitized banner string
        """
        if not banner:
            return ""
        sanitized = re.sub(r'[^\w\s.-]', '', banner)
        return sanitized[:100]  # Limit length to prevent excessively long queries
    
    def get_cves_with_details(self, banner: str) -> Union[List[Dict], str]:
        """
        Search for CVEs based on a service banner.
        
        Args:
            banner: The service banner to search for vulnerabilities
            
        Returns:
            List of vulnerabilities or status message string
        """
        safe_banner = self._sanitize_banner(banner)
        if not safe_banner:
            return "No banner information to search"
            
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote_plus(safe_banner)}"
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        # Rate limiting to avoid API abuse
        time.sleep(0.6)  # NVD recommends no more than 5 requests in 30 seconds
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 403:
                print("[!] API access denied. Check if API key is required or rate limit reached.")
                return "API access denied"
                
            if response.status_code != 200:
                print(f"[!] API request failed with status code {response.status_code}")
                return f"API request failed: {response.status_code}"
                
            return self._parse_nvd_response(response.json())
            
        except requests.RequestException as e:
            print(f"[!] Error fetching CVEs for {banner}: {e}")
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing API response: {e}")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            
        return "Error fetching vulnerability data"
    
    def _parse_nvd_response(self, data: Dict) -> List[Dict]:
        """
        Parse the NVD API response and extract vulnerability details.
        
        Args:
            data: JSON response from NVD API
            
        Returns:
            List of parsed vulnerability dictionaries
        """
        vulnerabilities = []
        
        for item in data.get("vulnerabilities", []):
            try:
                cve_id = item["cve"]["id"]
                metrics = item["cve"].get("metrics", {})
                description = item["cve"].get("descriptions", [])
                desc_text = next((d["value"] for d in description if d.get("lang") == "en"), "No description")
                
                score = "N/A"
                severity = "Unknown"

                # Extract CVSS score from metrics
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
                    "severity": severity,
                    "description": desc_text[:200]  # Limit description length
                })
            except KeyError as e:
                print(f"[!] Error parsing CVE data: {e}")
                continue
                
        return vulnerabilities if vulnerabilities else []
    
    def search_cve(self, banner: str) -> Optional[Dict]:
        """
        Search for a single CVE based on a service banner.
        Used by the GUI to get a single vulnerability entry.
        
        Args:
            banner: The service banner to search for vulnerabilities
            
        Returns:
            First vulnerability found or None if none found
        """
        results = self.get_cves_with_details(banner)
        
        if isinstance(results, list) and results:
            cve = results[0]
            return {
                "cve_id": cve["cve"],
                "score": cve["cvss_score"],
                "severity": cve["severity"],
                "desc": cve.get("description", "No description available")
            }
        return None
    
    def scan_target(self, ip: str) -> Dict:
        """
        Perform a full vulnerability scan on a target IP.
        
        Args:
            ip: Target IP address to scan
            
        Returns:
            Dictionary containing scan results
        """
        if not self.validate_ip(ip):
            return {"error": "Invalid IP address"}
            
        print(f"[*] Scanning target: {ip}")
        results = []

        for port, banner in self.scan_ports(ip):
            print(f"[*] Scanning Port {port} - {banner}")
            cve_details = self.get_cves_with_details(banner)
            
            if isinstance(cve_details, list):
                print(f"[+] Vulnerabilities found for port {port}: {len(cve_details)}")
            else:
                print(f"[-] {cve_details}")
                cve_details = []  # Ensure we always have a list for JSON serialization
                
            results.append({
                'port': port,
                'banner': banner,
                'vulnerabilities': cve_details
            })
            
        return {'target': ip, 'results': results}
    
    def save_report(self, scan_data: Dict, output_file: Optional[str] = None) -> str:
        """
        Save scan results to a JSON file.
        
        Args:
            scan_data: Scan results dictionary
            output_file: Optional output filename
            
        Returns:
            Path to the saved report file
        """
        try:
            ip = scan_data.get('target', 'unknown')
            report_path = output_file or f"scan_report_{ip.replace('.', '_')}.json"
            with open(report_path, 'w') as f:
                json.dump(scan_data, f, indent=4)
            print(f"[+] Full JSON report saved to {report_path}")
            return report_path
        except IOError as e:
            print(f"[!] Error saving report: {e}")
            return ""


# Compatibility functions for backward compatibility
def validate_ip(ip: str) -> bool:
    """Legacy function for IP validation."""
    scanner = VulnerabilityScanner()
    return scanner.validate_ip(ip)

def scan_ports(ip: str) -> List[Tuple[int, str]]:
    """Legacy function for port scanning."""
    scanner = VulnerabilityScanner()
    return scanner.scan_ports(ip)

def get_cves_with_details(banner: str, api_key: Optional[str] = None) -> Union[List[Dict], str]:
    """Legacy function for CVE lookups."""
    scanner = VulnerabilityScanner(api_key)
    return scanner.get_cves_with_details(banner)

def search_cve(banner: str, api_key: Optional[str] = None) -> Optional[Dict]:
    """Legacy function for single CVE search."""
    scanner = VulnerabilityScanner(api_key)
    return scanner.search_cve(banner)


def main():
    """Main function to run the vulnerability scanner from the command line."""
    print("[+] Vulnerability Scanner")
    print("[+] ---------------------")
    
    # Get API key from environment or user input
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        print("[*] No NVD API key found in environment. API key is recommended to avoid rate limiting.")
        api_key = input("[?] Enter NVD API key (press Enter to skip): ").strip() or None
        
    # Get target IP with validation
    ip = input("[?] Enter target IP address: ")
    
    # Create scanner and run scan
    scanner = VulnerabilityScanner(api_key)
    if not scanner.validate_ip(ip):
        print("[!] Invalid IP address provided. Exiting.")
        return
    
    scan_data = scanner.scan_target(ip)
    
    # Save results
    scanner.save_report(scan_data)
    
    # Print summary
    results = scan_data.get('results', [])
    if not results:
        print("[!] No results found.")
        return
        
    print("[+] Scan Summary:")
    for result in results:
        port = result.get('port', 'unknown')
        banner = result.get('banner', 'unknown')
        vulns = result.get('vulnerabilities', [])
        if isinstance(vulns, list):
            vuln_count = len(vulns)
        else:
            vuln_count = 0
        print(f"  Port {port} - {banner} - Found {vuln_count} vulnerabilities")


if __name__ == '__main__':
    main()
