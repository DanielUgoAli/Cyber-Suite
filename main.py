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
import ip
import vas

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
    print("2. 🌐 IP Address Generator & Mask Detector") 
    print("3. 🔍 Vulnerability Scanner")
    print("4. ❌ Exit")
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
    """Handle IP generation and masking"""
    print("\n🌐 IP ADDRESS GENERATOR & MASK DETECTOR")
    print("-" * 40)
    
    # Use the existing functionality from ip.py
    user_ips = ip.get_user_ips()
    count, version = ip.get_user_config()
    
    print("\n[*] Generating and checking IPs...\n")
    generated, masked = ip.generate_and_compare(count, version, user_ips)
    
    # Display results
    print("\n=== Generated IP Addresses ===")
    for ip_addr, ip_type in generated:
        print(f"- {ip_addr} [{ip_type}]")
    
    print("\n=== Summary Report ===")
    print(f"Total IPs Generated: {len(generated)}")
    print(f"Total Masked IPs Detected: {len(masked)}")
    
    if masked:
        print("\nMasked IPs:")
        for ip_addr, ip_type in masked:
            print(f"- {ip_addr} [{ip_type}]")
    else:
        print("✅ No masked IPs found.")

def vulnerability_scanner():
    """Handle vulnerability scanning"""
    print("\n🔍 VULNERABILITY SCANNER")
    print("-" * 40)
    print("⚠️  Note: This tool requires nmap and internet connection")
    
    try:
        # Use the existing functionality from vas.py
        vas.main()
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user.")
    except Exception as e:
        print(f"❌ Scanner error: {e}")
        print("Make sure nmap is installed and you have proper permissions.")

def main():
    """Main program loop"""
    print_banner()
    print_menu()
    
    while True:
        try:
            choice = input("Select tool (1-4): ").strip()
            
            if choice == '1':
                password_tool()
            elif choice == '2':
                ip_tool()
            elif choice == '3':
                vulnerability_scanner()
            elif choice == '4':
                print("\n👋 Thanks for using Cyber-Suite! Stay secure!")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please select 1-4.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye! Stay secure!")
            sys.exit(0)
        except Exception as e:
            print(f"❌ An error occurred: {e}")
            print("Please try again or contact support.")

if __name__ == "__main__":
    main() 