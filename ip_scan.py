import requests
import sqlite3
import json
import datetime
# import ipwhois
import ipaddress
import socket
from typing import List, Dict
from colorama import Fore, init

# Initialize Colorama
init(autoreset=True)



# IP categorization constants
KNOWN_MALICIOUS_RANGES = [
    "185.147.34.0/24",  # Example known malware distribution range
    "194.58.56.0/24",   # Example known spammer network
    "91.132.255.0/24",  # Example known botnet C2 network
]

class IPAnalyzer:
    """Class for analyzing and categorizing IP addresses."""
    
    def __init__(self):
        self.ip_info_cache = {}  # Cache for IP geolocation data
    
    def classify_ip(self, ip: str) -> Dict[str, bool]:
        """
        Classify an IP address into various categories.
        
        Args:
            ip: IP address to classify
            
        Returns:
            Dictionary of categories and boolean values
        """
        ip_obj = ipaddress.ip_address(ip)
        
        classification = {
            "private": ip_obj.is_private,
            "global": ip_obj.is_global,
            "multicast": ip_obj.is_multicast,
            "loopback": ip_obj.is_loopback,
            "reserved": ip_obj.is_reserved,
            "link_local": ip_obj.is_link_local,
            "potentially_malicious": self._check_if_potentially_malicious(ip)
        }
        
        return classification
    
    def _check_if_potentially_malicious(self, ip: str) -> bool:
        """
        Check if an IP is in known malicious ranges.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if potentially malicious, False otherwise
        """
        ip_obj = ipaddress.ip_address(ip)
        
        for malicious_range in KNOWN_MALICIOUS_RANGES:
            network = ipaddress.ip_network(malicious_range)
            if ip_obj in network:
                return True
        
        return False
    
    def get_ip_info(self, ip: str) -> Dict:
        """
        Get geolocation and additional info for an IP.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with IP information
        """
        if ip in self.ip_info_cache:
            return self.ip_info_cache[ip]
            
        try:
            # Use free IP-API service for geolocation
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    # Cache the result
                    self.ip_info_cache[ip] = data
                    return data
        except (requests.RequestException, json.JSONDecodeError):
            pass
            
        # Return basic info if API fails
        return {
            "query": ip,
            "status": "fail",
            "country": "Unknown",
            "isp": "Unknown",
            "org": "Unknown"
        }
    
    def scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """
        Scan for open ports on an IP address.
        
        Args:
            ip: IP address to scan
            ports: List of port numbers to check
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except socket.error:
                pass
                
        return open_ports
    
    def analyze_ip(self, ip: str, scan_ports: bool = False) -> Dict:
        """
        Perform comprehensive analysis on an IP address.
        
        Args:
            ip: IP address to analyze
            scan_ports: Whether to scan common ports
            
        Returns:
            Dictionary with analysis results
        """
        # Validate IP
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return {"error": "Invalid IP address"}
            
        # Get basic classification
        classification = self.classify_ip(ip)
        
        # Get geolocation data
        geo_info = self.get_ip_info(ip)
        
        # Port scanning (optional)
        port_data = {}
        if scan_ports and ip_obj.is_global:
            common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
            open_ports = self.scan_ports(ip, common_ports)
            port_data = {
                "scanned_ports": common_ports,
                "open_ports": open_ports
            }
        
        # Assemble results
        result = {
            "ip": str(ip_obj),
            "version": f"IPv{ip_obj.version}",
            "classification": classification,
            "geolocation": geo_info,
        }
        
        if port_data:
            result["ports"] = port_data
            
        return result
        
    def analyze_ips(self, ip_list: List[str], scan_ports: bool = False) -> List[Dict]:
        """
        Analyze multiple IP addresses.
        
        Args:
            ip_list: List of IP addresses to analyze
            scan_ports: Whether to scan ports
            
        Returns:
            List of analysis results for each IP
        """
        results = []
        for ip in ip_list:
            try:
                result = self.analyze_ip(ip, scan_ports)
                results.append(result)
            except Exception as e:
                results.append({
                    "ip": ip,
                    "error": str(e)
                })
        return results


# --- Deprecated: WHOIS Lookup ---
def whois_lookup(ip):
    """
    DEPRECATED: Use IPAnalyzer.get_ip_info instead.
    Kept for backwards compatibility.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        Tuple of (ISP, country)
    """
    # Use the IPAnalyzer instead which has caching and redundancy handling
    analyzer = IPAnalyzer()
    geo_info = analyzer.get_ip_info(ip)
    isp = geo_info.get("isp", "Unknown")
    country = geo_info.get("country", "Unknown")
    return isp, country

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



# --- Export Results ---
def export_results(all_results, geo_results, fmt="txt"):
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

        # Geolocation data always added
        lines.append("=== IP Geolocation Data ===")
        for ip, (isp, country) in geo_results.items():
            lines.append(f"{ip} | ISP: {isp} | Country: {country}")
        lines.append("")

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
        data = {"results": all_results, "geo_data": geo_results, "timestamp": timestamp}
        filename = "scan_results.json"
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Results saved to {filename}")

# --- IP Analyzer Utility Functions ---
def parse_ip_input(input_str: str) -> List[str]:
    """
    Parse IP addresses and CIDR ranges from input string.
    
    Args:
        input_str: String containing IPs and CIDR ranges
        
    Returns:
        List of IP addresses
    """
    ip_list = []
    items = [item.strip() for item in input_str.replace(",", " ").split()]
    
    for item in items:
        try:
            # Check if it's a CIDR range
            if "/" in item:
                network = ipaddress.ip_network(item, strict=False)
                # Limit to first 100 IPs for large networks
                for i, ip in enumerate(network.hosts()):
                    if i >= 100:  # Don't process huge networks completely
                        break
                    ip_list.append(str(ip))
            else:
                # It's a single IP
                ip = ipaddress.ip_address(item)
                ip_list.append(str(ip))
        except ValueError:
            print(Fore.RED + f"Invalid IP/CIDR skipped: {item}")
    
    return ip_list



# Deprecated - use IPAnalyzer.analyze_ips directly
def analyze_ips(ip_list: List[str], scan_ports: bool = False) -> List[Dict]:
    """
    DEPRECATED: Use IPAnalyzer.analyze_ips directly.
    Kept for backwards compatibility.
    
    Args:
        ip_list: List of IP addresses to analyze
        scan_ports: Whether to scan ports
        
    Returns:
        List of analysis results for each IP
    """
    analyzer = IPAnalyzer()
    return analyzer.analyze_ips(ip_list, scan_ports)

def display_ip_analysis(analysis_results):
    """Display IP analysis results in the console with colorama."""
    for result in analysis_results:
        ip = result.get("ip", "Unknown")
        version = result.get("version", "Unknown")
        
        # Determine color based on classification
        classification = result.get("classification", {})
        
        if classification.get("potentially_malicious", False):
            ip_color = Fore.RED
            status = "⚠️  POTENTIALLY MALICIOUS"
        elif classification.get("private", False):
            ip_color = Fore.BLUE
            status = "🏠 PRIVATE"
        elif classification.get("loopback", False):
            ip_color = Fore.CYAN
            status = "🔄 LOOPBACK"
        elif classification.get("reserved", False):
            ip_color = Fore.MAGENTA
            status = "🚫 RESERVED"
        else:
            ip_color = Fore.GREEN
            status = "🌐 PUBLIC"
            
        # Print IP with status
        print(f"\n{ip_color}IP: {ip} [{version}] - {status}")
        
        # Geolocation info
        geo = result.get("geolocation", {})
        if geo.get("status") == "success":
            print(f"{Fore.YELLOW}Location: {geo.get('country', 'Unknown')}, {geo.get('regionName', 'Unknown')}")
            print(f"{Fore.YELLOW}ISP: {geo.get('isp', 'Unknown')}")
            print(f"{Fore.YELLOW}Organization: {geo.get('org', 'Unknown')}")
        
        # Port information
        ports = result.get("ports", {})
        open_ports = ports.get("open_ports", [])
        if open_ports:
            print(f"{Fore.RED}Open Ports: {', '.join(map(str, open_ports))}")
        
        # Print a separator
        print(f"{Fore.WHITE}{'-' * 60}")

# The Quick Scan functions (scan_network, ping_ip, get_public_ip, check_ip_reputation)
# have been removed as they are no longer used in the application.


