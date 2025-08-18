import random
import ipaddress
import socket
import requests
import json
import concurrent.futures
from typing import List, Dict, Tuple, Set, Union, Optional
from colorama import Fore, Style, init

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


def generate_random_ip(ipv6: bool = False) -> str:
    """
    Generate a random IP address.
    
    Args:
        ipv6: Whether to generate IPv6 (True) or IPv4 (False)
        
    Returns:
        String representation of IP address
    """
    if ipv6:
        return ":".join(f"{random.randint(0, 0xffff):x}" for _ in range(8))
    else:
        return ".".join(str(random.randint(0, 255)) for _ in range(4))


def analyze_ips(ip_list: List[str], scan_ports: bool = False) -> List[Dict]:
    """
    Analyze a list of IPs in parallel.
    
    Args:
        ip_list: List of IPs to analyze
        scan_ports: Whether to scan ports
        
    Returns:
        List of analysis results
    """
    analyzer = IPAnalyzer()
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(analyzer.analyze_ip, ip, scan_ports): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(future_to_ip):
            results.append(future.result())
    
    return results


def generate_ips(count: int, version: str = "ipv4") -> List[Tuple[str, str]]:
    """
    Generate a list of random IPs.
    
    Args:
        count: Number of IPs to generate
        version: IP version ('ipv4', 'ipv6', or 'both')
        
    Returns:
        List of (IP, version) tuples
    """
    ips = []
    
    for _ in range(count):
        if version in {"ipv4", "both"}:
            ip4 = generate_random_ip(ipv6=False)
            ips.append((ip4, "IPv4"))

        if version in {"ipv6", "both"}:
            ip6 = generate_random_ip(ipv6=True)
            ips.append((ip6, "IPv6"))
    
    return ips


def generate_and_compare(count: int, version: str, user_ips: Set[str]) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Generate IPs and compare with user-provided list.
    
    Args:
        count: Number of IPs to generate
        version: IP version ('ipv4', 'ipv6', or 'both')
        user_ips: Set of user-provided IPs to compare against
        
    Returns:
        Tuple of (generated_ips, flagged_ips)
    """
    generated_ips = generate_ips(count, version)
    flagged_ips = [(ip, ver) for ip, ver in generated_ips if ip in user_ips]
    
    return generated_ips, flagged_ips

def get_user_ips():
    """Get IPs from user input with support for CIDR notation."""
    raw_input = input(Fore.YELLOW + "Enter IPs to analyze (supports CIDR notation, e.g., 192.168.1.0/24):\n> ")
    return parse_ip_input(raw_input)


def get_user_config():
    """Get user configuration for IP generation."""
    while True:
        try:
            count = int(input(Fore.YELLOW + "How many IP addresses do you want to generate?\n> "))
            if count > 0:
                break
        except ValueError:
            print(Fore.RED + "Enter a valid number.")
    
    while True:
        version = input(Fore.YELLOW + "Generate IPv4, IPv6, or both? (Enter: ipv4 / ipv6 / both):\n> ").lower()
        if version in {"ipv4", "ipv6", "both"}:
            break
        print(Fore.RED + "Invalid input. Choose 'ipv4', 'ipv6', or 'both'.")
    
    return count, version


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


def main_analyze():
    """Main function for IP analysis mode."""
    print(Fore.CYAN + "=== IP Address Analyzer ===")
    
    # Get IPs to analyze
    ips_to_analyze = get_user_ips()
    
    if not ips_to_analyze:
        print(Fore.RED + "No valid IPs to analyze.")
        return
        
    # Ask about port scanning
    scan_ports = input(Fore.YELLOW + "Scan common ports? (y/n): ").lower() == 'y'
    
    print(Fore.MAGENTA + f"\n[*] Analyzing {len(ips_to_analyze)} IP addresses...\n")
    
    # Analyze IPs
    results = analyze_ips(ips_to_analyze, scan_ports)
    
    # Display results
    display_ip_analysis(results)
    
    # Ask if user wants to save the results
    save_results = input(Fore.YELLOW + "\nSave results to file? (y/n): ").lower() == 'y'
    if save_results:
        filename = input(Fore.YELLOW + "Enter filename (default: ip_analysis.json): ").strip() or "ip_analysis.json"
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(Fore.GREEN + f"Results saved to {filename}")
        except Exception as e:
            print(Fore.RED + f"Error saving results: {e}")


def main_generate():
    """Main function for IP generation mode."""
    print(Fore.CYAN + "=== IP Address Generator ===")
    
    # Get user configuration
    count, version = get_user_config()
    
    # Get IPs to flag (optional)
    flag_ips = input(Fore.YELLOW + "Enter IPs to flag (optional): ").strip()
    user_ips = set(parse_ip_input(flag_ips)) if flag_ips else set()
    
    print(Fore.MAGENTA + "\n[*] Generating and checking IPs...\n")
    generated, flagged = generate_and_compare(count, version, user_ips)
    
    print(Fore.CYAN + "\n=== Generated IP Addresses ===")
    for ip, ip_type in generated:
        color = Fore.RED if (ip, ip_type) in flagged else Fore.GREEN
        print(color + f"- {ip} [{ip_type}]")
    
    print(Fore.CYAN + "\n=== Summary Report ===")
    print(f"{Fore.BLUE}Total IPs Generated: {len(generated)}")
    print(f"{Fore.RED if flagged else Fore.GREEN}Total Flagged IPs Detected: {len(flagged)}")
    
    if flagged:
        print(Fore.RED + "\nFlagged IPs:")
        for ip, ip_type in flagged:
            print(Fore.RED + f"- {ip} [{ip_type}]")
    else:
        print(Fore.GREEN + "No flagged IPs found.")


def main():
    """Main function with menu options."""
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "🌐 Advanced IP Toolkit")
    print(Fore.CYAN + "=" * 60)
    
    while True:
        print("\n" + Fore.YELLOW + "Select operation:")
        print(Fore.YELLOW + "1. Analyze IPs (with geolocation & security checks)")
        print(Fore.YELLOW + "2. Generate random IPs")
        print(Fore.YELLOW + "3. Exit")
        
        choice = input(Fore.WHITE + "\nEnter your choice (1-3): ")
        
        if choice == '1':
            main_analyze()
        elif choice == '2':
            main_generate()
        elif choice == '3':
            print(Fore.CYAN + "\nThank you for using the Advanced IP Toolkit. Goodbye!")
            break
        else:
            print(Fore.RED + "Invalid choice. Please enter 1-3.")


if __name__ == "__main__":
    main()
