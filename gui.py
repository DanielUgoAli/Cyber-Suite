"""
Cyber-Suite GUI: A modern GUI interface for the cybersecurity toolkit
Built with CustomTkinter
Author: DanielUgoAli
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import threading
import sys
import os
from datetime import datetime

# Import our modules
import encrypted_ps_gen
import ipgen as ip
import vas

# Set appearance mode and color theme
ctk.set_appearance_mode("dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class CyberSuiteGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Cyber-Suite - Security Toolkit")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Header Frame
        self.header_frame = ctk.CTkFrame(self.root, height=100)
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        self.header_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="🛡️ CYBER-SUITE", 
            font=ctk.CTkFont(size=28, weight="bold")
        )
        self.title_label.grid(row=0, column=0, pady=10)
        
        # Subtitle
        self.subtitle_label = ctk.CTkLabel(
            self.header_frame, 
            text=f"Comprehensive Security Toolkit | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
            font=ctk.CTkFont(size=14)
        )
        self.subtitle_label.grid(row=1, column=0, pady=(0, 10))
        
        # Main Content Frame
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        
        # Left Panel - Tool Selection
        self.left_panel = ctk.CTkFrame(self.main_frame, width=250)
        self.left_panel.grid(row=0, column=0, sticky="ns", padx=(20, 10), pady=20)
        self.left_panel.grid_propagate(False)
        
        # Tool buttons
        self.tools_label = ctk.CTkLabel(
            self.left_panel, 
            text="🔧 Available Tools", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.tools_label.grid(row=0, column=0, pady=(20, 10), padx=20)
        
        self.password_btn = ctk.CTkButton(
            self.left_panel,
            text="🔐 Password Tools",
            command=self.show_password_tools,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.password_btn.grid(row=1, column=0, pady=10, padx=20, sticky="ew")
        
        self.ip_btn = ctk.CTkButton(
            self.left_panel,
            text="🌐 IP Generator",
            command=self.show_ip_tools,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.ip_btn.grid(row=2, column=0, pady=10, padx=20, sticky="ew")
        
        self.vuln_btn = ctk.CTkButton(
            self.left_panel,
            text="🔍 Vuln Scanner",
            command=self.show_vuln_scanner,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.vuln_btn.grid(row=3, column=0, pady=10, padx=20, sticky="ew")
        
        self.about_btn = ctk.CTkButton(
            self.left_panel,
            text="ℹ️ About",
            command=self.show_about,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.about_btn.grid(row=4, column=0, pady=10, padx=20, sticky="ew")
        
        # Right Panel - Tool Interface
        self.right_panel = ctk.CTkFrame(self.main_frame)
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 20), pady=20)
        self.right_panel.grid_columnconfigure(0, weight=1)
        self.right_panel.grid_rowconfigure(0, weight=1)
        
        # Initialize with welcome screen
        self.show_welcome()
        
    def clear_right_panel(self):
        """Clear the right panel"""
        for widget in self.right_panel.winfo_children():
            widget.destroy()
            
    def show_welcome(self):
        """Show welcome screen"""
        self.clear_right_panel()
        
        welcome_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        welcome_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        welcome_frame.grid_columnconfigure(0, weight=1)
        welcome_frame.grid_rowconfigure(0, weight=1)
        
        welcome_text = """
🛡️ Welcome to Cyber-Suite

A comprehensive cybersecurity toolkit featuring:

🔐 Password Generator & Encryption
• Generate secure random passwords
• Encrypt/decrypt passwords with Fernet encryption
• Customizable password length and complexity

🌐 IP Address Generator & Flag Detector
• Generate random IPv4 and IPv6 addresses
• Detect flagged/filtered IPs
• Bulk generation with detailed reporting

🔍 Vulnerability Scanner
• Network port scanning with nmap
• CVE lookup using NVD API
• Service detection and vulnerability assessment

Select a tool from the left panel to get started!
        """
        
        welcome_label = ctk.CTkLabel(
            welcome_frame,
            text=welcome_text,
            font=ctk.CTkFont(size=14),
            justify="left"
        )
        welcome_label.grid(row=0, column=0, pady=50)
        
    def show_password_tools(self):
        """Show password generation and encryption tools"""
        self.clear_right_panel()
        
        # Main container
        container = ctk.CTkScrollableFrame(self.right_panel)
        container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        container.grid_columnconfigure(0, weight=1)
        
        # Title
        title = ctk.CTkLabel(container, text="🔐 Password Tools", font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Password Generation Section
        gen_frame = ctk.CTkFrame(container)
        gen_frame.grid(row=1, column=0, sticky="ew", pady=10)
        gen_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(gen_frame, text="Password Generation", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=3, pady=10)
        
        ctk.CTkLabel(gen_frame, text="Length:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.pw_length_entry = ctk.CTkEntry(gen_frame, placeholder_text="16")
        self.pw_length_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        
        gen_btn = ctk.CTkButton(gen_frame, text="Generate", command=self.generate_password)
        gen_btn.grid(row=1, column=2, padx=10, pady=5)
        
        self.pw_result = ctk.CTkTextbox(gen_frame, height=60)
        self.pw_result.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        
        # Encryption Section
        enc_frame = ctk.CTkFrame(container)
        enc_frame.grid(row=2, column=0, sticky="ew", pady=10)
        enc_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(enc_frame, text="Password Encryption", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=3, pady=10)
        
        ctk.CTkLabel(enc_frame, text="Password:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.encrypt_pw_entry = ctk.CTkEntry(enc_frame, show="*")
        self.encrypt_pw_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        
        encrypt_btn = ctk.CTkButton(enc_frame, text="Encrypt", command=self.encrypt_password)
        encrypt_btn.grid(row=1, column=2, padx=10, pady=5)
        
        self.encrypt_result = ctk.CTkTextbox(enc_frame, height=100)
        self.encrypt_result.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        
        # Decryption Section
        dec_frame = ctk.CTkFrame(container)
        dec_frame.grid(row=3, column=0, sticky="ew", pady=10)
        dec_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(dec_frame, text="Password Decryption", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=3, pady=10)
        
        ctk.CTkLabel(dec_frame, text="Encrypted:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.decrypt_pw_entry = ctk.CTkEntry(dec_frame)
        self.decrypt_pw_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        
        ctk.CTkLabel(dec_frame, text="Key:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.decrypt_key_entry = ctk.CTkEntry(dec_frame)
        self.decrypt_key_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
        
        decrypt_btn = ctk.CTkButton(dec_frame, text="Decrypt", command=self.decrypt_password)
        decrypt_btn.grid(row=3, column=1, padx=10, pady=10)
        
        self.decrypt_result = ctk.CTkTextbox(dec_frame, height=60)
        self.decrypt_result.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        
    def show_ip_tools(self):
        """Show IP generation tools"""
        self.clear_right_panel()
        
        container = ctk.CTkScrollableFrame(self.right_panel)
        container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        container.grid_columnconfigure(0, weight=1)
        
        # Title
        title = ctk.CTkLabel(container, text="🌐 IP Address Generator", font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Configuration Frame
        config_frame = ctk.CTkFrame(container)
        config_frame.grid(row=1, column=0, sticky="ew", pady=10)
        config_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(config_frame, text="Configuration", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=2, pady=10)
        
        ctk.CTkLabel(config_frame, text="Number of IPs:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.ip_count_entry = ctk.CTkEntry(config_frame, placeholder_text="10")
        self.ip_count_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        
        ctk.CTkLabel(config_frame, text="IP Version:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.ip_version_var = ctk.StringVar(value="ipv4")
        ip_version_menu = ctk.CTkOptionMenu(config_frame, variable=self.ip_version_var, values=["ipv4", "ipv6", "both"])
        ip_version_menu.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
        
        ctk.CTkLabel(config_frame, text="Compare IPs (comma-separated):").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.compare_ips_entry = ctk.CTkEntry(config_frame, placeholder_text="192.168.1.1, 10.0.0.1")
        self.compare_ips_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        
        generate_ip_btn = ctk.CTkButton(config_frame, text="Generate IPs", command=self.generate_ips)
        generate_ip_btn.grid(row=4, column=1, padx=10, pady=10, sticky="e")
        
        # Results Frame
        results_frame = ctk.CTkFrame(container)
        results_frame.grid(row=2, column=0, sticky="nsew", pady=10)
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(results_frame, text="Results", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, pady=10)
        
        self.ip_results = ctk.CTkTextbox(results_frame, height=300)
        self.ip_results.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
    def show_vuln_scanner(self):
        """Show vulnerability scanner"""
        self.clear_right_panel()
        
        container = ctk.CTkScrollableFrame(self.right_panel)
        container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        container.grid_columnconfigure(0, weight=1)
        
        # Title
        title = ctk.CTkLabel(container, text="🔍 Vulnerability Scanner", font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Warning
        warning = ctk.CTkLabel(container, text="⚠️ Requires nmap installation and internet connection", 
                              font=ctk.CTkFont(size=12), text_color="orange")
        warning.grid(row=1, column=0, pady=(0, 10))
        
        # Configuration Frame
        config_frame = ctk.CTkFrame(container)
        config_frame.grid(row=2, column=0, sticky="ew", pady=10)
        config_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(config_frame, text="Target Configuration", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=3, pady=10)
        
        ctk.CTkLabel(config_frame, text="Target IP:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.target_ip_entry = ctk.CTkEntry(config_frame, placeholder_text="192.168.1.1")
        self.target_ip_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        
        ctk.CTkLabel(config_frame, text="NVD API Key:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.api_key_entry = ctk.CTkEntry(config_frame, placeholder_text="Optional - leave blank to enter during scan", show="*")
        self.api_key_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
        
        scan_btn = ctk.CTkButton(config_frame, text="Start Scan", command=self.start_vulnerability_scan)
        scan_btn.grid(row=3, column=1, padx=10, pady=10, sticky="e")
        
        # Results Frame
        results_frame = ctk.CTkFrame(container)
        results_frame.grid(row=3, column=0, sticky="nsew", pady=10)
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(results_frame, text="Scan Results", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, pady=10)
        
        self.scan_results = ctk.CTkTextbox(results_frame, height=400)
        self.scan_results.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
    def show_about(self):
        """Show about information"""
        self.clear_right_panel()
        
        about_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        about_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        about_frame.grid_columnconfigure(0, weight=1)
        about_frame.grid_rowconfigure(0, weight=1)
        
        about_text = """
🛡️ Cyber-Suite v1.0

A comprehensive cybersecurity toolkit developed by NgCERT Interns

📋 Features:
• Password Generation & Encryption
• IP Address Generation & Masking Detection
• Network Vulnerability Scanning
• Modern GUI with CustomTkinter
• Cross-platform compatibility

🔧 Technologies:
• Python 3.x
• CustomTkinter for modern GUI
• Cryptography (Fernet) for encryption
• nmap for network scanning
• NVD API for vulnerability data

📝 Requirements:
• Python 3.7+
• customtkinter
• cryptography
• python-nmap
• requests

⚖️ Legal Notice:
This tool is for educational and authorized testing purposes only.
Users are responsible for complying with applicable laws and regulations.

🌟 GitHub: github.com/DanielUgoAli/Cyber-Suite
        """
        
        about_label = ctk.CTkLabel(
            about_frame,
            text=about_text,
            font=ctk.CTkFont(size=13),
            justify="left"
        )
        about_label.grid(row=0, column=0, pady=20)
        
    # Tool Functions
    def generate_password(self):
        """Generate a new password"""
        try:
            length = int(self.pw_length_entry.get() or "16")
            password = encrypted_ps_gen.generate_password(length)
            self.pw_result.delete("1.0", tk.END)
            self.pw_result.insert("1.0", f"Generated Password:\n{password}")
        except ValueError:
            messagebox.showerror("Error", "Invalid password length. Please enter a number.")
        except Exception as e:
            messagebox.showerror("Error", f"Password generation failed: {e}")
            
    def encrypt_password(self):
        """Encrypt a password"""
        try:
            password = self.encrypt_pw_entry.get()
            if not password:
                messagebox.showwarning("Warning", "Please enter a password to encrypt.")
                return
                
            key = encrypted_ps_gen.generate_key()
            encrypted = encrypted_ps_gen.encrypt_password(password, key)
            
            result = f"Encryption Key (SAVE THIS!):\n{key.decode()}\n\nEncrypted Password:\n{encrypted.decode()}"
            self.encrypt_result.delete("1.0", tk.END)
            self.encrypt_result.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
            
    def decrypt_password(self):
        """Decrypt a password"""
        try:
            encrypted_pw = self.decrypt_pw_entry.get()
            key = self.decrypt_key_entry.get()
            
            if not encrypted_pw or not key:
                messagebox.showwarning("Warning", "Please enter both encrypted password and key.")
                return
                
            decrypted = encrypted_ps_gen.decrypt_password(encrypted_pw.encode(), key.encode())
            self.decrypt_result.delete("1.0", tk.END)
            self.decrypt_result.insert("1.0", f"Decrypted Password:\n{decrypted}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
            
    def generate_ips(self):
        """Generate IP addresses"""
        try:
            count = int(self.ip_count_entry.get() or "10")
            version = self.ip_version_var.get()
            compare_ips_str = self.compare_ips_entry.get()
            
            # Parse comparison IPs
            user_ips = set()
            if compare_ips_str:
                user_ips = set(ip.strip() for ip in compare_ips_str.replace(",", " ").split() if ip.strip())
            
            # Generate IPs using ipgen.py function
            generated, flagged = ip.generate_and_compare(count, version, user_ips)
            
            # Format results
            result = "=== Generated IP Addresses ===\n"
            for ip_addr, ip_type in generated:
                status = " [FLAGGED]" if (ip_addr, ip_type) in flagged else ""
                result += f"• {ip_addr} [{ip_type}]{status}\n"
            
            result += f"\n=== Summary ===\n"
            result += f"Total IPs Generated: {len(generated)}\n"
            result += f"Flagged IPs Detected: {len(flagged)}\n"
            
            if flagged:
                result += f"\nFlagged IPs:\n"
                for ip_addr, ip_type in flagged:
                    result += f"• {ip_addr} [{ip_type}]\n"
            else:
                result += "\n✅ No flagged IPs found.\n"
                
            self.ip_results.delete("1.0", tk.END)
            self.ip_results.insert("1.0", result)
            
        except ValueError:
            messagebox.showerror("Error", "Invalid IP count. Please enter a number.")
        except Exception as e:
            messagebox.showerror("Error", f"IP generation failed: {e}")
            
    def start_vulnerability_scan(self):
        """Start vulnerability scan in a separate thread"""
        target_ip = self.target_ip_entry.get()
        if not target_ip:
            messagebox.showwarning("Warning", "Please enter a target IP address.")
            return
            
        # Clear previous results
        self.scan_results.delete("1.0", tk.END)
        self.scan_results.insert("1.0", "Starting vulnerability scan...\n")
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=self.run_vulnerability_scan, args=(target_ip,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def run_vulnerability_scan(self, target_ip):
        """Run the vulnerability scan using vas.py components"""
        try:
            # Update GUI
            self.scan_results.insert(tk.END, f"Scanning target: {target_ip}\n")
            self.scan_results.insert(tk.END, "This may take a few minutes...\n\n")
            
            # Get API key using vas.py function
            api_key = self.api_key_entry.get()
            if not api_key:
                api_key = os.getenv("NVD_API_KEY", "")
                if not api_key:
                    self.scan_results.insert(tk.END, "No API key provided - CVE lookup will be skipped.\n")
            
            # Run port scan using vas.py function
            self.scan_results.insert(tk.END, "Running port scan...\n")
            self.scan_results.update_idletasks()  # Force GUI update
            
            # Use vas.py scan_services function
            services = vas.scan_services(target_ip)
            
            # Display results
            self.scan_results.insert(tk.END, f"\n=== Scan Results for {target_ip} ===\n")
            
            if not services:
                self.scan_results.insert(tk.END, "No open ports found.\n")
                return
                
            for port, banner in services:
                self.scan_results.insert(tk.END, f"\n[+] Port {port} | Service: {banner}\n")
                self.scan_results.update_idletasks()  # Force GUI update
                
                # CVE lookup if API key is available using vas.py function
                if api_key:
                    self.scan_results.insert(tk.END, "    Looking up vulnerabilities...\n")
                    self.scan_results.update_idletasks()  # Force GUI update
                    
                    cve_info = vas.search_cve(banner, api_key)
                    if cve_info:
                        self.scan_results.insert(tk.END, f"    CVE: {cve_info['cve_id']} | Score: {cve_info['score']} | Severity: {cve_info['severity']}\n")
                        self.scan_results.insert(tk.END, f"    Description: {cve_info['desc'][:100]}...\n")
                    else:
                        self.scan_results.insert(tk.END, "    No CVE found.\n")
                else:
                    self.scan_results.insert(tk.END, "    (CVE lookup skipped - no API key)\n")
            
            self.scan_results.insert(tk.END, "\n=== Scan Complete ===\n")
            
        except ImportError as e:
            self.scan_results.insert(tk.END, f"Error: Missing required package - {e}\n")
            self.scan_results.insert(tk.END, "Install with: pip install python-nmap\n")
        except Exception as e:
            self.scan_results.insert(tk.END, f"Scan error: {e}\n")
            
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

def main():
    """Main function to run the GUI"""
    try:
        app = CyberSuiteGUI()
        app.run()
    except ImportError as e:
        print(f"Missing required package: {e}")
        print("Please install required packages:")
        print("pip install customtkinter cryptography python-nmap requests")
    except Exception as e:
        print(f"Application error: {e}")

if __name__ == "__main__":
    main()
