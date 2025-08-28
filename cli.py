#!/usr/bin/env python3
"""
Cyber-Suite: A comprehensive cybersecurity toolkit
Author: DanielUgoAli
"""

import sys
import os
from datetime import datetime

# Import our modules
import encrypted_ps_gen
import vas
import ip_scan  # Use ip_scan instead of ipgen

def print_banner():
    """Display the main banner"""
    print("=" * 60)
    print("  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ")
    print(" ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗")
    print(" ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝")
    print(" ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗")
    print(" ╚██████╗   ██║   ██████╔╝███████╗██║  ██║")
    print("  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝")
    print("               SECURITY SUITE")
    print("=" * 60)
    print(f"Welcome to Cyber-Suite | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

def print_menu():
    """Display the main menu options"""
    print("\n🔧 Available Tools:")
    print("1. 🔐 Password Generator & Encryption")
    print("2. 🌐 IP Address Generator & Flag Detector") 
    print("3. 🔍 Vulnerability Scanner")
    print("4. 🖥️  Launch GUI Interface")
    print("5. ❌ Exit")
    print("-" * 40)

def password_tool():
    """Handle password generation and encryption"""
    print("\n🔐 PASSWORD GENERATOR & ENCRYPTION")
    print("-" * 40)
    
    while True:
        print("\nOptions:")
        print("a) Generate a new password")
        print("b) Encrypt a password")
        print("c) Decrypt a password")
        print("d) Back to main menu")
        
        choice = input("\nSelect option (a/b/c/d): ").lower().strip()
        
        if choice == 'a':
            try:
                length = int(input("Password length (default 16): ") or "16")
                password = encrypted_ps_gen.generate_password(length)
                print(f"\n✅ Generated Password: {password}")
            except ValueError:
                print("❌ Invalid length. Using default (16).")
                password = encrypted_ps_gen.generate_password()
                print(f"\n✅ Generated Password: {password}")
                
        elif choice == 'b':
            password = input("Enter password to encrypt: ")
            key = encrypted_ps_gen.generate_key()
            encrypted = encrypted_ps_gen.encrypt_password(password, key)
            print(f"\n✅ Encryption Key (SAVE THIS!): {key.decode()}")
            print(f"✅ Encrypted Password: {encrypted.decode()}")
            
        elif choice == 'c':
            try:
                encrypted_pw = input("Enter encrypted password: ").encode()
                key = input("Enter decryption key: ").encode()
                decrypted = encrypted_ps_gen.decrypt_password(encrypted_pw, key)
                print(f"\n✅ Decrypted Password: {decrypted}")
            except Exception as e:
                print(f"❌ Decryption failed: {e}")
                
        elif choice == 'd':
            break
        else:
            print("❌ Invalid option. Please try again.")

def ip_tool():
    """Handle IP address analysis and scanning"""
    print("\n🌐 IP ADDRESS ANALYZER & SCANNER")
    print("-" * 40)
    
    # Get IP address(es) from user
    ip_input = input("Enter IP addresses to analyze (comma/space separated): ").strip()
    ip_list = ip_scan.parse_ip_input(ip_input)
    
    if not ip_list:
        print("❌ No valid IP addresses entered.")
        return
        
    # Ask if user wants to scan ports
    scan_ports = input("Do you want to scan ports? (y/n): ").lower().strip() == 'y'
    
    print("\n[*] Analyzing IP addresses...\n")
    
    # Create analyzer and analyze IPs
    analyzer = ip_scan.IPAnalyzer()
    results = []
    
    for ip in ip_list:
        try:
            result = analyzer.analyze_ip(ip, scan_ports)
            results.append(result)
            
            # Display basic info
            classification = result.get("classification", {})
            is_malicious = classification.get("potentially_malicious", False)
            is_private = classification.get("private", False)
            
            if is_malicious:
                status = "⚠️  POTENTIALLY MALICIOUS"
            elif is_private:
                status = "🏠 PRIVATE"
            else:
                status = "🌐 PUBLIC"
                
            print(f"\n- {ip} - {status}")
            
            # Show geolocation if available
            geo = result.get("geolocation", {})
            if geo.get("status") == "success":
                print(f"  Location: {geo.get('country', 'Unknown')}")
                print(f"  ISP: {geo.get('isp', 'Unknown')}")
                
        except Exception as e:
            print(f"❌ Error analyzing {ip}: {e}")
    
    # Display summary
    print("\n=== Summary Report ===")
    total_ips = len(results)
    private_ips = sum(1 for r in results if r.get("classification", {}).get("private", False))
    malicious_ips = sum(1 for r in results if r.get("classification", {}).get("potentially_malicious", False))
    
    print(f"Total IPs Analyzed: {total_ips}")
    print(f"Private IPs: {private_ips}")
    print(f"Potentially Malicious IPs: {malicious_ips}")
    
    # If port scanning was enabled, show summary of open ports
    if scan_ports:
        all_open_ports = set()
        for result in results:
            ports = result.get("ports", {})
            all_open_ports.update(ports.get("open_ports", []))
            
        if all_open_ports:
            print(f"\nOpen ports detected: {', '.join(map(str, sorted(all_open_ports)))}")
        else:
            print("\nNo open ports detected.")

def vulnerability_scanner():
    """Handle vulnerability scanning"""
    print("\n🔍 VULNERABILITY SCANNER")
    print("-" * 40)
    print("⚠️  Note: This tool requires nmap and internet connection")
    
    try:
        # Get target IP with validation
        ip = input("[?] Enter target IP address: ")
        
        # Get optional API key
        api_key = input("[?] Enter NVD API key (or leave blank to skip): ").strip() or None
        
        # Create scanner and run scan
        scanner = vas.VulnerabilityScanner(api_key)
        if not scanner.validate_ip(ip):
            print("[!] Invalid IP address provided. Exiting.")
            return
        
        print(f"[*] Scanning target: {ip}")
        scan_data = scanner.scan_target(ip)
        
        results = scan_data.get('results', [])
        
        if not results:
            print("[!] No results found.")
            return
        
        # Save results
        report_path = scanner.save_report(scan_data)
        if report_path:
            print(f"[+] Full report saved to {report_path}")
        
        # Print summary
        print("[+] Scan Summary:")
        total_vulns = 0
        for result in results:
            port = result.get('port', 'unknown')
            banner = result.get('banner', 'unknown')
            vulns = result.get('vulnerabilities', [])
            if isinstance(vulns, list):
                vuln_count = len(vulns)
                total_vulns += vuln_count
            else:
                vuln_count = 0
            print(f"  Port {port} - {banner} - Found {vuln_count} vulnerabilities")
        
        print(f"\nTotal vulnerabilities found: {total_vulns}")
        
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user.")
    except Exception as e:
        print(f"❌ Scanner error: {e}")
        print("Make sure nmap is installed and you have proper permissions.")

def launch_gui():
    """Launch the GUI interface"""
    try:
        print("\n🖥️  Launching GUI interface...")
        import gui
        app = gui.CyberSuiteGUI()
        app.mainloop()
    except ImportError as e:
        print(f"❌ Missing required package for GUI: {e}")
        print("📦 Install GUI dependencies with:")
        print("   pip install customtkinter")
    except Exception as e:
        print(f"❌ GUI launch error: {e}")

def main():
    """Main program loop"""
    print_banner()
    print_menu()
    
    while True:
        try:
            choice = input("Select tool (1-5): ").strip()
            
            if choice == '1':
                password_tool()
            elif choice == '2':
                ip_tool()
            elif choice == '3':
                vulnerability_scanner()
            elif choice == '4':
                launch_gui()
            elif choice == '5':
                print("\n👋 Thanks for using Cyber-Suite! Stay secure!")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please select 1-5.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye! Stay secure!")
            sys.exit(0)
        except Exception as e:
            print(f"❌ An error occurred: {e}")
            print("Please try again or contact support.")

if __name__ == "__main__":
    main() 