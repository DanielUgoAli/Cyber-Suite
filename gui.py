import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, scrolledtext
import encrypted_ps_gen
import ipgen
import vas
import threading
import webbrowser
import platform
import os
from datetime import datetime

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class CyberSuiteGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cyber-Suite GUI")
        self.geometry("800x600")
        self.resizable(True, True)
        self.minsize(600, 400)  # Set minimum window size
        
        # Configure row and column weights for resizing
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.tabview = ctk.CTkTabview(self, width=780, height=560)
        self.tabview.pack(padx=10, pady=10, fill="both", expand=True)
        
        self.password_tab = self.tabview.add("Password Tool")
        self.ip_tab = self.tabview.add("IP Generator")
        self.vas_tab = self.tabview.add("Vulnerability Scanner")
        self.about_tab = self.tabview.add("About")
        
        # Store current scan data for vulnerability scanner
        self.current_scan_data = None
        
        self.create_password_tab()
        self.create_ip_tab()
        self.create_vas_tab()
        self.create_about_tab()
        
        # Bind mousewheel to scrollable frames
        self.bind_mousewheel_to_frames()

    def create_password_tab(self):
        """Create the password tab with generator, encryption, and decryption sections"""
        # Create a scrollable frame for the password tab
        scrollable_frame = ctk.CTkScrollableFrame(self.password_tab)
        scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create a master frame to hold all components
        master_frame = ctk.CTkFrame(scrollable_frame)
        master_frame.pack(pady=5, padx=5, fill="both", expand=True)
        
        # Title for the password tab
        title_label = ctk.CTkLabel(master_frame, text="Password Security Tools", 
                                  font=ctk.CTkFont(size=18, weight="bold"))
        title_label.pack(pady=(15, 20))
        
        # === Password Generator Section ===
        gen_frame = ctk.CTkFrame(master_frame)
        gen_frame.pack(pady=10, padx=20, fill="x")
        
        gen_title = ctk.CTkLabel(gen_frame, text="Password Generator", 
                               font=ctk.CTkFont(size=16, weight="bold"))
        gen_title.pack(pady=(10, 15), anchor="w")
        
        # Controls row
        controls_frame = ctk.CTkFrame(gen_frame)
        controls_frame.pack(fill="x", padx=10, pady=5)
        
        # Password length
        self.pw_length_label = ctk.CTkLabel(controls_frame, text="Password Length:")
        self.pw_length_label.pack(side="left", padx=5)
        
        self.pw_length_entry = ctk.CTkEntry(controls_frame, width=60)
        self.pw_length_entry.insert(0, "16")
        self.pw_length_entry.pack(side="left", padx=5)
        
        # Password options - for future expansion
        self.include_symbols_var = tk.BooleanVar(value=True)
        self.include_symbols = ctk.CTkCheckBox(controls_frame, text="Symbols", 
                                             variable=self.include_symbols_var)
        self.include_symbols.pack(side="left", padx=10)
        
        self.include_numbers_var = tk.BooleanVar(value=True)
        self.include_numbers = ctk.CTkCheckBox(controls_frame, text="Numbers", 
                                             variable=self.include_numbers_var)
        self.include_numbers.pack(side="left", padx=10)
        
        # Generate button and result
        gen_result_frame = ctk.CTkFrame(gen_frame)
        gen_result_frame.pack(fill="x", padx=10, pady=10)
        
        self.generate_pw_btn = ctk.CTkButton(gen_result_frame, text="Generate Secure Password", 
                                           command=self.generate_password)
        self.generate_pw_btn.pack(side="left", padx=(0, 10), pady=10)
        
        self.generated_pw = ctk.CTkEntry(gen_result_frame, width=350)
        self.generated_pw.pack(side="left", fill="x", expand=True, pady=10)
        
        # Copy button for generated password
        self.copy_gen_btn = ctk.CTkButton(gen_result_frame, text="Copy", width=60,
                                        command=lambda: self.copy_to_clipboard(self.generated_pw.get()))
        self.copy_gen_btn.pack(side="right", padx=10, pady=10)
        
        # === Encryption Section ===
        encrypt_frame = ctk.CTkFrame(master_frame)
        encrypt_frame.pack(pady=10, padx=20, fill="x")
        
        encrypt_title = ctk.CTkLabel(encrypt_frame, text="Password Encryption", 
                                   font=ctk.CTkFont(size=16, weight="bold"))
        encrypt_title.pack(pady=(10, 15), anchor="w")
        
        # Input row
        input_frame = ctk.CTkFrame(encrypt_frame)
        input_frame.pack(fill="x", padx=10, pady=5)
        
        self.encrypt_label = ctk.CTkLabel(input_frame, text="Password to Encrypt:")
        self.encrypt_label.pack(side="left", padx=5)
        
        self.encrypt_entry = ctk.CTkEntry(input_frame, width=350)
        self.encrypt_entry.pack(side="left", fill="x", expand=True, padx=10)
        
        # Encrypt button
        self.encrypt_btn = ctk.CTkButton(encrypt_frame, text="Generate Encrypted Password", 
                                       command=self.encrypt_password)
        self.encrypt_btn.pack(pady=(10, 5), padx=10, anchor="w")
        
        # Output frames
        encrypted_output_frame = ctk.CTkFrame(encrypt_frame)
        encrypted_output_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(encrypted_output_frame, text="Encrypted Password:").pack(side="left", padx=5)
        
        self.encrypted_pw = ctk.CTkEntry(encrypted_output_frame, width=350)
        self.encrypted_pw.pack(side="left", fill="x", expand=True, padx=10)
        
        self.copy_enc_btn = ctk.CTkButton(encrypted_output_frame, text="Copy", width=60,
                                        command=lambda: self.copy_to_clipboard(self.encrypted_pw.get()))
        self.copy_enc_btn.pack(side="right", padx=5)
        
        # Key frame
        key_output_frame = ctk.CTkFrame(encrypt_frame)
        key_output_frame.pack(fill="x", padx=10, pady=(5, 10))
        
        ctk.CTkLabel(key_output_frame, text="Encryption Key:").pack(side="left", padx=5)
        
        self.encryption_key = ctk.CTkEntry(key_output_frame, width=350)
        self.encryption_key.pack(side="left", fill="x", expand=True, padx=10)
        
        self.copy_key_btn = ctk.CTkButton(key_output_frame, text="Copy", width=60,
                                        command=lambda: self.copy_to_clipboard(self.encryption_key.get()))
        self.copy_key_btn.pack(side="right", padx=5)
        
        # === Decryption Section ===
        decrypt_frame = ctk.CTkFrame(master_frame)
        decrypt_frame.pack(pady=10, padx=20, fill="x")
        
        decrypt_title = ctk.CTkLabel(decrypt_frame, text="Password Decryption", 
                                   font=ctk.CTkFont(size=16, weight="bold"))
        decrypt_title.pack(pady=(10, 15), anchor="w")
        
        # Encrypted password input
        encrypted_input_frame = ctk.CTkFrame(decrypt_frame)
        encrypted_input_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(encrypted_input_frame, text="Encrypted Password:").pack(side="left", padx=5)
        
        self.decrypt_pw_entry = ctk.CTkEntry(encrypted_input_frame, width=400)
        self.decrypt_pw_entry.pack(side="left", fill="x", expand=True, padx=10)
        
        # Key input
        key_input_frame = ctk.CTkFrame(decrypt_frame)
        key_input_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(key_input_frame, text="Encryption Key:").pack(side="left", padx=5)
        
        self.decrypt_key_entry = ctk.CTkEntry(key_input_frame, width=400)
        self.decrypt_key_entry.pack(side="left", fill="x", expand=True, padx=10)
        
        # Decrypt button and result
        decrypt_result_frame = ctk.CTkFrame(decrypt_frame)
        decrypt_result_frame.pack(fill="x", padx=10, pady=(10, 15))
        
        self.decrypt_btn = ctk.CTkButton(decrypt_result_frame, text="Decrypt Password", 
                                       command=self.decrypt_password)
        self.decrypt_btn.pack(side="left", padx=(0, 10), pady=5)
        
        ctk.CTkLabel(decrypt_result_frame, text="Original Password:").pack(side="left", padx=5)
        
        self.decrypted_pw = ctk.CTkEntry(decrypt_result_frame, width=300)
        self.decrypted_pw.pack(side="left", fill="x", expand=True, padx=10)
        
        self.copy_dec_btn = ctk.CTkButton(decrypt_result_frame, text="Copy", width=60,
                                        command=lambda: self.copy_to_clipboard(self.decrypted_pw.get()))
        self.copy_dec_btn.pack(side="right", padx=5)

    def generate_password(self):
        try:
            length = int(self.pw_length_entry.get())
        except ValueError:
            length = 16
            
        # Take into account the checkbox settings
        include_symbols = self.include_symbols_var.get()
        include_numbers = self.include_numbers_var.get()
            
        # For now, we'll keep using the existing function, but in the future
        # these parameters could be passed to the password generator
        pw = encrypted_ps_gen.generate_password(length)
        self.generated_pw.delete(0, tk.END)
        self.generated_pw.insert(0, pw)

    def encrypt_password(self):
        pw = self.encrypt_entry.get()
        if not pw:
            messagebox.showwarning("Input Required", "Please enter a password to encrypt.")
            return
            
        key = encrypted_ps_gen.generate_key()
        encrypted = encrypted_ps_gen.encrypt_password(pw, key, save=False)
        self.encrypted_pw.delete(0, tk.END)
        self.encrypted_pw.insert(0, encrypted.decode())
        self.encryption_key.delete(0, tk.END)
        self.encryption_key.insert(0, key.decode())

    def decrypt_password(self):
        encrypted_pw = self.decrypt_pw_entry.get()
        key = self.decrypt_key_entry.get()
        try:
            decrypted = encrypted_ps_gen.decrypt_password(encrypted_pw, key)
            self.decrypted_pw.delete(0, tk.END)
            self.decrypted_pw.insert(0, decrypted)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            
    def copy_to_clipboard(self, text):
        """Copy the provided text to the clipboard"""
        self.clipboard_clear()
        self.clipboard_append(text)
        # Show a small tooltip or flash effect to indicate successful copy
        messagebox.showinfo("Copied", "Text copied to clipboard!")
        
    def bind_mousewheel_to_frames(self):
        """Bind mousewheel events to all scrollable frames"""
        def _on_mousewheel(event, widget):
            if platform.system() == "Windows":
                widget._parent_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            elif platform.system() == "Darwin":  # macOS
                widget._parent_canvas.yview_scroll(int(-1*event.delta), "units")
            else:  # Linux
                if event.num == 4:
                    widget._parent_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    widget._parent_canvas.yview_scroll(1, "units")
        
        # Find and bind all CTkScrollableFrame widgets
        for tab in [self.password_tab, self.ip_tab, self.vas_tab, self.about_tab]:
            for child in tab.winfo_children():
                if isinstance(child, ctk.CTkScrollableFrame):
                    # Bind for Windows and macOS
                    child.bind_all("<MouseWheel>", lambda e, w=child: _on_mousewheel(e, w))
                    # Bind for Linux
                    child.bind_all("<Button-4>", lambda e, w=child: _on_mousewheel(e, w))
                    child.bind_all("<Button-5>", lambda e, w=child: _on_mousewheel(e, w))

    def create_ip_tab(self):
        # Create a notebook inside the tab for multiple IP tools
        self.ip_notebook = ctk.CTkTabview(self.ip_tab, width=760, height=540)
        self.ip_notebook.pack(padx=10, pady=10, fill="both", expand=True)
        
        self.ip_analyzer_tab = self.ip_notebook.add("IP Analyzer")
        self.ip_generator_tab = self.ip_notebook.add("IP Generator")
        
        # === IP Analyzer Tab ===
        # Create a scrollable frame for the IP analyzer tab
        analyzer_scrollable_frame = ctk.CTkScrollableFrame(self.ip_analyzer_tab)
        analyzer_scrollable_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.analyzer_frame = ctk.CTkFrame(analyzer_scrollable_frame)
        self.analyzer_frame.pack(pady=5, padx=5, fill="both", expand=True)
        
        self.analyzer_label = ctk.CTkLabel(self.analyzer_frame, 
                                          text="Enter IPs to analyze (supports CIDR notation, e.g., 192.168.1.0/24):")
        self.analyzer_label.pack(pady=(10, 0), padx=10, anchor="w")
        self.analyzer_entry = ctk.CTkEntry(self.analyzer_frame, width=700)
        self.analyzer_entry.pack(pady=5, padx=10, fill="x")
        
        self.scan_ports_var = tk.BooleanVar(value=False)
        self.scan_ports_check = ctk.CTkCheckBox(self.analyzer_frame, text="Scan common ports", 
                                               variable=self.scan_ports_var)
        self.scan_ports_check.pack(pady=5, padx=10, anchor="w")
        
        self.analyze_btn = ctk.CTkButton(self.analyzer_frame, text="Analyze IPs", 
                                        command=self.analyze_ips)
        self.analyze_btn.pack(pady=10)
        
        self.analyzer_result = scrolledtext.ScrolledText(self.analyzer_frame, width=90, height=22)
        self.analyzer_result.pack(pady=5, padx=10, fill="both", expand=True)
        
        # === IP Generator Tab ===
        # Create a scrollable frame for the IP generator tab
        generator_scrollable_frame = ctk.CTkScrollableFrame(self.ip_generator_tab)
        generator_scrollable_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.generator_frame = ctk.CTkFrame(generator_scrollable_frame)
        self.generator_frame.pack(pady=5, padx=5, fill="both", expand=True)
        
        self.ip_label = ctk.CTkLabel(self.generator_frame, text="Enter IPs to flag (supports CIDR notation):")
        self.ip_label.pack(pady=(10, 0), padx=10, anchor="w")
        self.ip_entry = ctk.CTkEntry(self.generator_frame, width=700)
        self.ip_entry.pack(pady=5, padx=10, fill="x")
        
        # Control frame for generator settings
        control_frame = ctk.CTkFrame(self.generator_frame)
        control_frame.pack(pady=5, padx=10, fill="x")
        
        # Count entry
        count_frame = ctk.CTkFrame(control_frame)
        count_frame.pack(side="left", padx=10, fill="y")
        self.count_label = ctk.CTkLabel(count_frame, text="Number of IPs:")
        self.count_label.pack(pady=5)
        self.count_entry = ctk.CTkEntry(count_frame, width=80)
        self.count_entry.insert(0, "10")
        self.count_entry.pack(pady=5)
        
        # Version radio buttons
        version_frame = ctk.CTkFrame(control_frame)
        version_frame.pack(side="left", padx=10, fill="y")
        self.version_label = ctk.CTkLabel(version_frame, text="IP Version:")
        self.version_label.pack(pady=5)
        self.version_var = tk.StringVar(value="both")
        self.ipv4_radio = ctk.CTkRadioButton(version_frame, text="IPv4", 
                                           variable=self.version_var, value="ipv4")
        self.ipv6_radio = ctk.CTkRadioButton(version_frame, text="IPv6", 
                                           variable=self.version_var, value="ipv6")
        self.both_radio = ctk.CTkRadioButton(version_frame, text="Both", 
                                           variable=self.version_var, value="both")
        self.ipv4_radio.pack(side="left", padx=5)
        self.ipv6_radio.pack(side="left", padx=5)
        self.both_radio.pack(side="left", padx=5)
        
        # Generate button
        self.generate_ip_btn = ctk.CTkButton(self.generator_frame, text="Generate & Check", 
                                            command=self.generate_and_check_ips)
        self.generate_ip_btn.pack(pady=10)
        
        # Results area
        self.ip_result = scrolledtext.ScrolledText(self.generator_frame, width=90, height=22)
        self.ip_result.pack(pady=5, padx=10, fill="both", expand=True)

    def generate_and_check_ips(self):
        """Generate random IPs and check against user-provided IPs"""
        # Parse IP input, supporting CIDR notation
        user_ips = set(ipgen.parse_ip_input(self.ip_entry.get()))
        
        try:
            count = int(self.count_entry.get())
        except ValueError:
            count = 10
            
        version = self.version_var.get()
        
        # Show a "processing" message
        self.ip_result.config(state="normal")
        self.ip_result.delete(1.0, tk.END)
        self.ip_result.insert(tk.END, "Generating IPs...\n")
        self.ip_result.config(state="disabled")
        self.update_idletasks()
        
        # Generate and compare IPs
        generated, flagged = ipgen.generate_and_compare(count, version, user_ips)
        
        # Display results
        self.ip_result.config(state="normal")
        self.ip_result.delete(1.0, tk.END)
        
        self.ip_result.insert(tk.END, "=== Generated IP Addresses ===\n", "heading")
        for ip_addr, ip_type in generated:
            tag = "flagged" if (ip_addr, ip_type) in flagged else "normal"
            self.ip_result.insert(tk.END, f"- {ip_addr} [{ip_type}]\n", tag)
        
        self.ip_result.insert(tk.END, f"\n=== Summary Report ===\n", "heading")
        self.ip_result.insert(tk.END, f"Total IPs Generated: {len(generated)}\n")
        self.ip_result.insert(tk.END, f"Total Flagged IPs Detected: {len(flagged)}\n")
        
        if flagged:
            self.ip_result.insert(tk.END, "\n=== Flagged IPs ===\n", "heading")
            for ip_addr, ip_type in flagged:
                self.ip_result.insert(tk.END, f"- {ip_addr} [{ip_type}]\n", "flagged")
        
        # Configure tags for colored text
        self.ip_result.tag_configure("heading", font=("TkDefaultFont", 10, "bold"))
        self.ip_result.tag_configure("flagged", foreground="red")
        self.ip_result.config(state="disabled")
        
    def analyze_ips(self):
        """Analyze IP addresses with security and geolocation features"""
        # Parse IP input, supporting CIDR notation
        ip_list = ipgen.parse_ip_input(self.analyzer_entry.get())
        scan_ports = self.scan_ports_var.get()
        
        if not ip_list:
            messagebox.showerror("Error", "No valid IP addresses entered")
            return
            
        # Show a "processing" message
        self.analyzer_result.config(state="normal")
        self.analyzer_result.delete(1.0, tk.END)
        self.analyzer_result.insert(tk.END, f"Analyzing {len(ip_list)} IP addresses...\nPlease wait, this may take a moment...\n")
        self.analyzer_result.config(state="disabled")
        self.update_idletasks()
        
        # Run the analysis in a separate thread
        threading.Thread(target=self._run_ip_analysis, args=(ip_list, scan_ports), daemon=True).start()
    
    def _run_ip_analysis(self, ip_list, scan_ports):
        """Run IP analysis in background thread"""
        try:
            # Analyze IPs
            results = ipgen.analyze_ips(ip_list, scan_ports)
            
            # Display results in the text area
            self.analyzer_result.config(state="normal")
            self.analyzer_result.delete(1.0, tk.END)
            
            for result in results:
                ip = result.get("ip", "Unknown")
                version = result.get("version", "Unknown")
                classification = result.get("classification", {})
                
                # IP and classification
                self.analyzer_result.insert(tk.END, f"\nIP: {ip} [{version}]\n", "ip")
                
                # Classification flags
                if classification.get("potentially_malicious", False):
                    self.analyzer_result.insert(tk.END, "⚠️  POTENTIALLY MALICIOUS\n", "alert")
                    
                if classification.get("private", False):
                    self.analyzer_result.insert(tk.END, "🏠 PRIVATE NETWORK\n", "info")
                elif classification.get("loopback", False):
                    self.analyzer_result.insert(tk.END, "🔄 LOOPBACK\n", "info")
                elif classification.get("reserved", False):
                    self.analyzer_result.insert(tk.END, "🚫 RESERVED\n", "info")
                else:
                    self.analyzer_result.insert(tk.END, "🌐 PUBLIC IP\n", "info")
                
                # Geolocation info
                geo = result.get("geolocation", {})
                self.analyzer_result.insert(tk.END, "\nGeolocation:\n", "heading")
                if geo.get("status") == "success":
                    self.analyzer_result.insert(tk.END, f"  Country: {geo.get('country', 'Unknown')}\n")
                    self.analyzer_result.insert(tk.END, f"  Region: {geo.get('regionName', 'Unknown')}\n")
                    self.analyzer_result.insert(tk.END, f"  City: {geo.get('city', 'Unknown')}\n")
                    self.analyzer_result.insert(tk.END, f"  ISP: {geo.get('isp', 'Unknown')}\n")
                    self.analyzer_result.insert(tk.END, f"  Organization: {geo.get('org', 'Unknown')}\n")
                else:
                    self.analyzer_result.insert(tk.END, "  Unable to retrieve geolocation data\n")
                
                # Port information
                ports = result.get("ports", {})
                open_ports = ports.get("open_ports", [])
                if scan_ports:
                    self.analyzer_result.insert(tk.END, "\nPort Scan:\n", "heading")
                    if open_ports:
                        self.analyzer_result.insert(tk.END, f"  Open ports: {', '.join(map(str, open_ports))}\n", "alert")
                    else:
                        self.analyzer_result.insert(tk.END, "  No open ports detected\n")
                
                # Separator
                self.analyzer_result.insert(tk.END, "-" * 50 + "\n")
            
            # Configure tags for colored text
            self.analyzer_result.tag_configure("ip", font=("TkDefaultFont", 10, "bold"))
            self.analyzer_result.tag_configure("heading", font=("TkDefaultFont", 10, "bold"))
            self.analyzer_result.tag_configure("alert", foreground="red")
            self.analyzer_result.tag_configure("info", foreground="blue")
            
        except Exception as e:
            self.analyzer_result.config(state="normal")
            self.analyzer_result.delete(1.0, tk.END)
            self.analyzer_result.insert(tk.END, f"Error during analysis: {str(e)}")
            
        finally:
            self.analyzer_result.config(state="disabled")
        
    def create_vas_tab(self):
        # Create a scrollable frame for the vulnerability scanner tab
        vas_scrollable_frame = ctk.CTkScrollableFrame(self.vas_tab)
        vas_scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Main frame for VAS
        vas_frame = ctk.CTkFrame(vas_scrollable_frame)
        vas_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        # Input section
        input_frame = ctk.CTkFrame(vas_frame)
        input_frame.pack(pady=5, padx=10, fill="x")
        
        self.vas_label = ctk.CTkLabel(input_frame, text="Enter Target IP Address:")
        self.vas_label.pack(pady=5, side="left", padx=10)
        self.vas_ip_entry = ctk.CTkEntry(input_frame, width=200)
        self.vas_ip_entry.pack(pady=5, side="left", padx=10)
        
        api_frame = ctk.CTkFrame(vas_frame)
        api_frame.pack(pady=5, padx=10, fill="x")
        
        self.vas_api_label = ctk.CTkLabel(api_frame, text="NVD API Key (optional):")
        self.vas_api_label.pack(pady=5, side="left", padx=10)
        self.vas_api_entry = ctk.CTkEntry(api_frame, width=300)
        self.vas_api_entry.pack(pady=5, side="left", padx=10)
        
        # Button frame
        button_frame = ctk.CTkFrame(vas_frame)
        button_frame.pack(pady=10, padx=10, fill="x")
        
        # Scan button
        self.vas_scan_btn = ctk.CTkButton(
            button_frame, 
            text="Scan", 
            command=self.start_vas_scan,
            width=120
        )
        self.vas_scan_btn.pack(pady=5, side="left", padx=10)
        
        # Download frame for formatting options
        download_frame = ctk.CTkFrame(button_frame)
        download_frame.pack(pady=5, side="left", padx=10)
        
        # Format label
        format_label = ctk.CTkLabel(download_frame, text="Export format:")
        format_label.pack(side="left", padx=(0, 5))
        
        # Format selection
        self.export_format_var = tk.StringVar(value="json")
        json_radio = ctk.CTkRadioButton(
            download_frame, 
            text="JSON", 
            variable=self.export_format_var,
            value="json"
        )
        json_radio.pack(side="left", padx=5)
        
        html_radio = ctk.CTkRadioButton(
            download_frame, 
            text="HTML", 
            variable=self.export_format_var,
            value="html"
        )
        html_radio.pack(side="left", padx=5)
        
        # Download button (disabled initially)
        self.vas_download_btn = ctk.CTkButton(
            button_frame, 
            text="Download Results", 
            command=self.download_vas_results,
            width=120,
            state="disabled"
        )
        self.vas_download_btn.pack(pady=5, side="left", padx=10)
        
        # Results area
        self.vas_result = scrolledtext.ScrolledText(
            vas_frame, 
            width=90, 
            height=20, 
            state="normal"
        )
        self.vas_result.pack(pady=5, padx=10, fill="both", expand=True)
        
        # Store scan results for download
        self.current_scan_data = None

    def start_vas_scan(self):
        ip = self.vas_ip_entry.get().strip()
        api_key = self.vas_api_entry.get().strip() or None
        self.vas_result.config(state="normal")
        self.vas_result.delete(1.0, tk.END)
        self.vas_result.insert(tk.END, f"Scanning {ip}...\n")
        self.vas_result.config(state="disabled")
        threading.Thread(target=self.run_vas_scan, args=(ip, api_key), daemon=True).start()

    def run_vas_scan(self, ip, api_key):
        try:
            # Disable the download button during scan
            self.vas_download_btn.configure(state="disabled")
            # Reset stored scan data
            self.current_scan_data = None
            
            # Create scanner instance with API key
            scanner = vas.VulnerabilityScanner(api_key)
            
            if not scanner.validate_ip(ip):
                self.vas_result.config(state="normal")
                self.vas_result.insert(tk.END, "Invalid IP address.\n")
                self.vas_result.config(state="disabled")
                return
                
            # Use the scanner's methods for a more efficient scan
            self.vas_result.config(state="normal")
            self.vas_result.insert(tk.END, f"Starting port scan...\n")
            self.vas_result.config(state="disabled")
            
            # Run the scan
            scan_data = scanner.scan_target(ip)
            self.current_scan_data = scan_data  # Store scan results for download
            
            results = scan_data.get('results', [])
            
            if not results:
                self.vas_result.config(state="normal")
                self.vas_result.insert(tk.END, "No open ports found or scan failed.\n")
                self.vas_result.config(state="disabled")
                return
                
            # Display results
            self.vas_result.config(state="normal")
            self.vas_result.delete(1.0, tk.END)  # Clear previous results
            self.vas_result.insert(tk.END, f"Scan Results for {ip}:\n")
            self.vas_result.insert(tk.END, "-" * 50 + "\n")
            
            # Track total vulnerabilities
            total_vulns = 0
            
            for result in results:
                port = result.get('port', 'unknown')
                banner = result.get('banner', '')
                vulnerabilities = result.get('vulnerabilities', [])
                
                if isinstance(vulnerabilities, list):
                    total_vulns += len(vulnerabilities)
                
                self.vas_result.insert(tk.END, f"\nPort {port} - {banner}\n")
                
                if isinstance(vulnerabilities, list) and vulnerabilities:
                    self.vas_result.insert(tk.END, f"Found {len(vulnerabilities)} vulnerabilities:\n")
                    for i, cve in enumerate(vulnerabilities[:3]):
                        self.vas_result.insert(tk.END, f"  {i+1}. CVE: {cve['cve']} | Score: {cve['cvss_score']} | Severity: {cve['severity']}\n")
                        self.vas_result.insert(tk.END, f"     Description: {cve['description']}\n")
                    if len(vulnerabilities) > 3:
                        self.vas_result.insert(tk.END, f"  ...and {len(vulnerabilities)-3} more CVEs.\n")
                else:
                    self.vas_result.insert(tk.END, "  No vulnerabilities found.\n")
            
            self.vas_result.insert(tk.END, "\n" + "-" * 50 + "\n")
            self.vas_result.insert(tk.END, f"Scan Summary: {len(results)} open ports, {total_vulns} vulnerabilities found.\n")
            self.vas_result.insert(tk.END, "Scan completed. You can download the complete report.\n")
            self.vas_result.config(state="disabled")
            
            # Enable download button if we have results
            if results:
                self.vas_download_btn.configure(state="normal")
                
        except Exception as e:
            self.vas_result.config(state="normal")
            self.vas_result.insert(tk.END, f"\nError during scan: {str(e)}\n")
            self.vas_result.config(state="disabled")
    
    def download_vas_results(self):
        """Save the VAS scan results to a structured JSON file"""
        if not self.current_scan_data:
            messagebox.showerror("Error", "No scan results available to download")
            return
        
        try:
            from tkinter import filedialog
            import json
            from datetime import datetime
            import os
            
            # Get target IP for default filename
            ip = self.current_scan_data.get('target', 'unknown')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"vulnerability_scan_{ip.replace('.', '_')}_{timestamp}.json"
            
            # Get selected format
            selected_format = self.export_format_var.get()
            
            # Set default extension based on format
            if selected_format == "html":
                default_ext = ".html"
                default_filename = default_filename.replace(".json", ".html")
                filetypes = [("HTML Report", "*.html"), ("JSON Files", "*.json"), ("All Files", "*.*")]
            else:
                default_ext = ".json"
                filetypes = [("JSON Files", "*.json"), ("HTML Report", "*.html"), ("All Files", "*.*")]
                
            # Ask user where to save the file
            file_path = filedialog.asksaveasfilename(
                defaultextension=default_ext,
                filetypes=filetypes,
                initialfile=default_filename
            )
            
            if not file_path:  # User cancelled
                return
            
            # Get the selected format
            selected_format = self.export_format_var.get()
            
            # Check if the file extension matches the selected format
            _, ext = os.path.splitext(file_path)
            
            # If format doesn't match selection, append proper extension
            if (selected_format == 'html' and ext.lower() != '.html'):
                file_path += '.html'
            elif (selected_format == 'json' and ext.lower() != '.json'):
                file_path += '.json'
            
            # Create structured data format
            structured_data = self._structure_scan_data(self.current_scan_data)
            
            # Save in the selected format
            if selected_format == 'json' or (ext.lower() == '.json' and selected_format == 'json'):
                # Save as structured JSON
                with open(file_path, 'w') as f:
                    json.dump(structured_data, f, indent=2)
                
            elif selected_format == 'html' or (ext.lower() == '.html' and selected_format == 'html'):
                # Generate HTML report
                html_report = self._generate_html_report(structured_data)
                with open(file_path, 'w') as f:
                    f.write(html_report)
            
            messagebox.showinfo("Success", f"Scan results saved to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save scan results: {str(e)}")
    
    def _structure_scan_data(self, raw_data):
        """
        Structure and filter scan data into a more organized format
        """
        if not raw_data:
            return {}
            
        # Get scan timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_ip = raw_data.get('target', 'unknown')
        
        # Initialize structured report
        report = {
            "scan_summary": {
                "target": target_ip,
                "timestamp": timestamp,
                "scanner_version": "Cyber-Suite 1.0.0",
                "total_ports_scanned": 1000,  # Nmap default
                "open_ports": 0,
                "total_vulnerabilities": 0,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 0
            },
            "open_ports": [],
            "vulnerabilities": {}
        }
        
        # Process results
        results = raw_data.get('results', [])
        
        # Count vulnerabilities by severity
        all_vulns = []
        
        for port_data in results:
            port_num = port_data.get('port')
            banner = port_data.get('banner', '')
            vulns = port_data.get('vulnerabilities', [])
            
            # Skip if we don't have a valid port number
            if not port_num:
                continue
                
            # Update open port count
            report["scan_summary"]["open_ports"] += 1
            
            # Add to open ports list
            port_entry = {
                "port": port_num,
                "service": banner,
                "vulnerability_count": len(vulns) if isinstance(vulns, list) else 0
            }
            report["open_ports"].append(port_entry)
            
            # Process vulnerabilities
            if isinstance(vulns, list):
                for vuln in vulns:
                    # Skip if we don't have a valid CVE ID
                    cve_id = vuln.get('cve')
                    if not cve_id:
                        continue
                        
                    # Add to total count
                    report["scan_summary"]["total_vulnerabilities"] += 1
                    
                    # Count by severity
                    severity = vuln.get('severity', '').lower()
                    if severity == 'high' or severity == 'critical':
                        report["scan_summary"]["high_severity"] += 1
                    elif severity == 'medium':
                        report["scan_summary"]["medium_severity"] += 1
                    elif severity in ['low', 'none']:
                        report["scan_summary"]["low_severity"] += 1
                    
                    # Add vulnerability details
                    if cve_id not in report["vulnerabilities"]:
                        report["vulnerabilities"][cve_id] = {
                            "id": cve_id,
                            "cvss_score": vuln.get('cvss_score', 'N/A'),
                            "severity": vuln.get('severity', 'Unknown'),
                            "description": vuln.get('description', 'No description available'),
                            "affected_ports": [port_num]
                        }
                    else:
                        # If we've seen this CVE before, just add the port
                        if port_num not in report["vulnerabilities"][cve_id]["affected_ports"]:
                            report["vulnerabilities"][cve_id]["affected_ports"].append(port_num)
                    
                    # Add to all vulnerabilities list for summary
                    all_vulns.append(vuln)
        
        # Convert vulnerabilities dict to list for easier processing in many formats
        report["vulnerabilities"] = list(report["vulnerabilities"].values())
        
        return report
    
    def _generate_html_report(self, data):
        """Generate an HTML report from the structured scan data"""
        # Get summary data
        summary = data.get('scan_summary', {})
        target = summary.get('target', 'Unknown')
        timestamp = summary.get('timestamp', 'Unknown')
        open_ports = summary.get('open_ports', 0)
        total_vulns = summary.get('total_vulnerabilities', 0)
        high = summary.get('high_severity', 0)
        medium = summary.get('medium_severity', 0)
        low = summary.get('low_severity', 0)
        
        # Start building HTML content
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #34495e; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .summary-item {{ margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .high {{ color: #e74c3c; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #3498db; }}
        .footer {{ margin-top: 30px; text-align: center; font-size: 0.8em; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Scan Report</h1>
            <p>Generated by Cyber-Suite Security Toolkit</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-item"><strong>Target:</strong> {target}</div>
            <div class="summary-item"><strong>Scan Date:</strong> {timestamp}</div>
            <div class="summary-item"><strong>Open Ports:</strong> {open_ports}</div>
            <div class="summary-item"><strong>Total Vulnerabilities:</strong> {total_vulns}</div>
            <div class="summary-item">
                <strong>Severity Breakdown:</strong> 
                <span class="high">{high} High</span>, 
                <span class="medium">{medium} Medium</span>, 
                <span class="low">{low} Low</span>
            </div>
        </div>
        
        <h2>Open Ports</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Vulnerabilities</th>
            </tr>
        """
        
        # Add open ports to the table
        for port in data.get('open_ports', []):
            html += f"""
            <tr>
                <td>{port.get('port')}</td>
                <td>{port.get('service')}</td>
                <td>{port.get('vulnerability_count')}</td>
            </tr>"""
            
        html += """
        </table>
        
        <h2>Vulnerabilities</h2>
        <table>
            <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>CVSS Score</th>
                <th>Affected Ports</th>
                <th>Description</th>
            </tr>
        """
        
        # Add vulnerabilities to the table
        for vuln in data.get('vulnerabilities', []):
            severity_class = "medium"
            if vuln.get('severity', '').lower() in ['critical', 'high']:
                severity_class = "high"
            elif vuln.get('severity', '').lower() in ['low', 'none']:
                severity_class = "low"
                
            # Join affected ports as comma separated list
            ports_str = ", ".join(map(str, vuln.get('affected_ports', [])))
            
            html += f"""
            <tr>
                <td><a href="https://nvd.nist.gov/vuln/detail/{vuln.get('id')}" target="_blank">{vuln.get('id')}</a></td>
                <td class="{severity_class}">{vuln.get('severity')}</td>
                <td>{vuln.get('cvss_score')}</td>
                <td>{ports_str}</td>
                <td>{vuln.get('description')}</td>
            </tr>"""
            
        html += """
        </table>
        
        <div class="footer">
            <p>Generated by Cyber-Suite Security Toolkit | © 2025 DanielUgoAli</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def create_about_tab(self):
        """Create the About tab with application information"""
        # Create a scrollable frame for the about tab
        about_scrollable_frame = ctk.CTkScrollableFrame(self.about_tab)
        about_scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Logo/Banner (ASCII art)
        logo_frame = ctk.CTkFrame(about_scrollable_frame)
        logo_frame.pack(pady=20, padx=20, fill="x")
        
        logo_text = """
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ 
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
               SECURITY SUITE
        """
        
        logo_label = ctk.CTkLabel(logo_frame, text=logo_text, font=ctk.CTkFont(family="Courier", size=12))
        logo_label.pack()
        
        # App Info
        info_frame = ctk.CTkFrame(self.about_tab)
        info_frame.pack(pady=10, padx=20, fill="x")
        
        current_year = datetime.now().year
        version_text = "Version: 1.0.0"
        copyright_text = f"© {current_year} ngCERT Interns"
        description = "A comprehensive cybersecurity toolkit for password management, IP address generation, and vulnerability scanning."
        
        ctk.CTkLabel(info_frame, text=version_text, font=ctk.CTkFont(weight="bold")).pack(pady=5)
        ctk.CTkLabel(info_frame, text=copyright_text).pack(pady=2)
        ctk.CTkLabel(info_frame, text=description, wraplength=500).pack(pady=10)
        
        # Features
        features_frame = ctk.CTkFrame(self.about_tab)
        features_frame.pack(pady=10, padx=20, fill="x")
        
        features_text = """
        Key Features:
        • Password Generator & Encryption Tool
        • IP address analysis, generation and flag detection
        • Vulnerability Scanner with CVE Database Integration
        """
        
        ctk.CTkLabel(features_frame, text=features_text, justify="left").pack(pady=10)
        
        # Links
        links_frame = ctk.CTkFrame(self.about_tab)
        links_frame.pack(pady=10, padx=20, fill="x")
        
        def open_github():
            webbrowser.open("https://github.com/DanielUgoAli/Cyber-Suite")
        
        def open_docs():
            webbrowser.open("https://github.com/DanielUgoAli/Cyber-Suite#readme")
        
        github_btn = ctk.CTkButton(links_frame, text="GitHub Repository", command=open_github)
        github_btn.pack(pady=10, side="left", padx=10, expand=True)
        
        docs_btn = ctk.CTkButton(links_frame, text="Documentation", command=open_docs)
        docs_btn.pack(pady=10, side="left", padx=10, expand=True)


def main():
    app = CyberSuiteGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
