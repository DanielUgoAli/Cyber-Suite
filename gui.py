import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, scrolledtext, PhotoImage, ttk

import encrypted_ps_gen
import ip_scan
import vas

import os
import threading
import webbrowser
import platform
import ipaddress

from datetime import datetime

# Set the global appearance mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Define non-font styling constants
SECTION_PADDING = 15
ELEMENT_PADDING = 10

class CyberSuiteGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cyber-Suite - Cybersecurity Toolkit")
        self.geometry("900x650")  # Slightly larger default size for better readability
        self.resizable(True, True)
        self.minsize(700, 500)  # Increased minimum window size
        
        # Define font styling constants AFTER creating the root window
        self.HEADING_FONT = ctk.CTkFont(size=20, weight="bold")
        self.SUBHEADING_FONT = ctk.CTkFont(size=16, weight="bold")
        self.NORMAL_FONT = ctk.CTkFont(size=13)
        self.BUTTON_FONT = ctk.CTkFont(size=13, weight="bold")
        
        # Configure row and column weights for resizing
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Set application icon - looks for logo.png in the assets folder
        self.set_app_icon()
        
        # Create a status bar at the bottom
        self.status_bar = ctk.CTkFrame(self, height=25)
        self.status_bar.pack(side="bottom", fill="x")
        self.status_label = ctk.CTkLabel(self.status_bar, text="Ready", anchor="w", padx=10)
        self.status_label.pack(side="left", fill="x")
        
        # Create a main tabview with improved styling
        self.tabview = ctk.CTkTabview(self, width=880, height=610)
        self.tabview.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Add tabs with descriptive names
        self.password_tab = self.tabview.add("🔐 Password Tools")
        self.ip_tab = self.tabview.add("🌐 IP Tools")
        self.vas_tab = self.tabview.add("🔍 Vulnerability Scanner")
        self.db_tab = self.tabview.add("📊 Database Viewer")
        self.about_tab = self.tabview.add("ℹ️ About")
        
        # Apply consistent styling to the tabs
        for tab in [self.password_tab, self.ip_tab, self.vas_tab, self.db_tab, self.about_tab]:
            tab.configure(fg_color=("#f0f0f0", "#2d2d2d"))  # Light mode, dark mode colors
        
        # Store current scan data for vulnerability scanner
        self.current_scan_data = None
        
        # Setup tooltip manager for showing hover tips
        self.tooltip_texts = {}
        
        # Create the UI content for each tab
        self.create_password_tab()
        self.create_ip_tab()
        self.create_vas_tab()
        self.create_db_viewer_tab()
        self.create_about_tab()
        
        # Bind mousewheel to scrollable frames
        self.bind_mousewheel_to_frames()
        
    def show_tooltip(self, widget, text):
        """Create tooltip functionality for any widget"""
        def on_enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25
            
            # Create tooltip window
            self.tooltip = tk.Toplevel(widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            
            label = tk.Label(self.tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1, padx=5, pady=2)
            label.pack()
            
        def on_leave(event):
            if hasattr(self, "tooltip"):
                self.tooltip.destroy()
                
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)
        
    def update_status(self, message):
        """Update the status bar with a message"""
        self.status_label.configure(text=message)
        self.update_idletasks()

    def create_password_tab(self):
        """Create the password tab with generator, encryption, and decryption sections"""
        # Create a scrollable frame for the password tab
        scrollable_frame = ctk.CTkScrollableFrame(self.password_tab)
        scrollable_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Create a master frame to hold all components
        master_frame = ctk.CTkFrame(scrollable_frame)
        master_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        # Main title for the password tab with improved styling
        title_label = ctk.CTkLabel(master_frame, text="Password Security Tools", 
                                  font=self.HEADING_FONT,
                                  text_color=("black", "#ADD8E6"))  # Light blue in dark mode
        title_label.pack(pady=(20, 20))
        
        # --- Password Generator Section ---
        gen_section_frame = ctk.CTkFrame(master_frame, corner_radius=10)
        gen_section_frame.pack(pady=15, padx=20, fill="x")
        
        # Section header with icon
        gen_header_frame = ctk.CTkFrame(gen_section_frame, fg_color="transparent")
        gen_header_frame.pack(fill="x", pady=5, padx=10)
        
        gen_title = ctk.CTkLabel(gen_header_frame, text="🔑 Password Generator", 
                               font=self.SUBHEADING_FONT)
        gen_title.pack(pady=(10, 5), anchor="w")
        
        # Divider
        divider = ctk.CTkFrame(gen_section_frame, height=2, fg_color=("gray70", "gray30"))
        divider.pack(fill="x", padx=10, pady=(0, 10))
        
        # Options with better organized controls
        gen_frame = ctk.CTkFrame(gen_section_frame, fg_color="transparent")
        gen_frame.pack(fill="x", padx=15, pady=5)
        
        # Controls in a grid for better alignment
        controls_frame = ctk.CTkFrame(gen_frame, fg_color="transparent")
        controls_frame.pack(fill="x", pady=5)
        
        # Password length with slider for better UX
        length_label_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        length_label_frame.pack(fill="x", pady=5)
        
        self.pw_length_label = ctk.CTkLabel(length_label_frame, text="Password Length:", font=self.NORMAL_FONT)
        self.pw_length_label.pack(side="left", padx=5)
        
        self.pw_length_value = ctk.CTkLabel(length_label_frame, text="16", width=30, font=self.NORMAL_FONT)
        self.pw_length_value.pack(side="left", padx=5)
        
        # Length slider
        slider_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        slider_frame.pack(fill="x", pady=5)
        
        self.pw_length_slider = ctk.CTkSlider(slider_frame, from_=8, to=32, number_of_steps=24,
                                            command=self.update_length_value)
        self.pw_length_slider.set(16)
        self.pw_length_slider.pack(side="left", fill="x", expand=True, padx=5)
        
        # Password complexity options in their own frame
        options_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        options_frame.pack(fill="x", pady=10)
        
        options_label = ctk.CTkLabel(options_frame, text="Include:", font=self.NORMAL_FONT)
        options_label.pack(side="left", padx=5)
        
        self.include_uppercase_var = tk.BooleanVar(value=True)
        self.include_uppercase = ctk.CTkCheckBox(options_frame, text="Uppercase", 
                                               variable=self.include_uppercase_var)
        self.include_uppercase.pack(side="left", padx=10)
        
        self.include_lowercase_var = tk.BooleanVar(value=True)
        self.include_lowercase = ctk.CTkCheckBox(options_frame, text="Lowercase", 
                                               variable=self.include_lowercase_var)
        self.include_lowercase.pack(side="left", padx=10)
        
        self.include_symbols_var = tk.BooleanVar(value=True)
        self.include_symbols = ctk.CTkCheckBox(options_frame, text="Symbols", 
                                             variable=self.include_symbols_var)
        self.include_symbols.pack(side="left", padx=10)
        
        self.include_numbers_var = tk.BooleanVar(value=True)
        self.include_numbers = ctk.CTkCheckBox(options_frame, text="Numbers", 
                                             variable=self.include_numbers_var)
        self.include_numbers.pack(side="left", padx=10)
        
        # Generate button and result with improved layout
        gen_result_frame = ctk.CTkFrame(gen_frame, fg_color="transparent")
        gen_result_frame.pack(fill="x", pady=15)
        
        self.generate_pw_btn = ctk.CTkButton(gen_result_frame, text="Generate Secure Password", 
                                           command=self.generate_password,
                                           font=self.BUTTON_FONT,
                                           height=32)
        self.generate_pw_btn.pack(side="left", padx=(0, 10))
        
        # Result field with larger text and readability
        result_display_frame = ctk.CTkFrame(gen_result_frame)
        result_display_frame.pack(side="left", fill="x", expand=True, padx=5)
        
        self.generated_pw = ctk.CTkEntry(result_display_frame, width=350, height=32,
                                       font=ctk.CTkFont(size=13))
        self.generated_pw.pack(fill="both", expand=True)
        
        # Copy button with icon indicator
        self.copy_gen_btn = ctk.CTkButton(gen_result_frame, text="📋 Copy", width=80,
                                        command=lambda: self.copy_to_clipboard(self.generated_pw.get()),
                                        font=self.BUTTON_FONT)
        self.copy_gen_btn.pack(side="right", padx=10)
        
        # Add tooltip for copy button
        self.show_tooltip(self.copy_gen_btn, "Copy password to clipboard")
        
        # --- Password Encryption Section ---
        encrypt_section_frame = ctk.CTkFrame(master_frame, corner_radius=10)
        encrypt_section_frame.pack(pady=15, padx=20, fill="x")
        
        # Section header
        encrypt_header_frame = ctk.CTkFrame(encrypt_section_frame, fg_color="transparent")
        encrypt_header_frame.pack(fill="x", pady=5, padx=10)
        
        encrypt_title = ctk.CTkLabel(encrypt_header_frame, text="🔒 Password Encryption", 
                                   font=self.SUBHEADING_FONT)
        encrypt_title.pack(pady=(10, 5), anchor="w")
        
        # Divider
        divider = ctk.CTkFrame(encrypt_section_frame, height=2, fg_color=("gray70", "gray30"))
        divider.pack(fill="x", padx=10, pady=(0, 10))
        
        # Create the encryption content frame
        encrypt_frame = ctk.CTkFrame(encrypt_section_frame, fg_color="transparent")
        encrypt_frame.pack(fill="x", padx=15, pady=5)
        
        # Password input with better label
        input_frame = ctk.CTkFrame(encrypt_frame, fg_color="transparent")
        input_frame.pack(fill="x", pady=10)
        
        self.encrypt_label = ctk.CTkLabel(input_frame, text="Password to Encrypt:", font=self.NORMAL_FONT)
        self.encrypt_label.pack(side="left", padx=5)
        
        self.encrypt_entry = ctk.CTkEntry(input_frame, width=350, height=32, 
                                        font=ctk.CTkFont(size=13),
                                        placeholder_text="Enter password to encrypt")
        self.encrypt_entry.pack(side="left", fill="x", expand=True, padx=10)
        
        # Encrypt button with improved styling
        button_frame = ctk.CTkFrame(encrypt_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)
        
        self.encrypt_btn = ctk.CTkButton(button_frame, text="Encrypt Password", 
                                       command=self.encrypt_password,
                                       font=self.BUTTON_FONT,
                                       height=32,
                                       fg_color=("#3a7ebf", "#1f538d"))  # Darker blue for distinction
        self.encrypt_btn.pack(pady=(5, 15))
        
        # Output frames with better organization
        results_frame = ctk.CTkFrame(encrypt_frame, fg_color="transparent")
        results_frame.pack(fill="x", pady=5)
        
        # Encrypted password output
        encrypted_output_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
        encrypted_output_frame.pack(fill="x", pady=8)
        
        ctk.CTkLabel(encrypted_output_frame, text="Encrypted Password:", font=self.NORMAL_FONT).pack(side="left", padx=5)
        
        self.encrypted_pw = ctk.CTkEntry(encrypted_output_frame, width=350, height=32,
                                       font=ctk.CTkFont(size=13))
        self.encrypted_pw.pack(side="left", fill="x", expand=True, padx=10)
        
        self.copy_enc_btn = ctk.CTkButton(encrypted_output_frame, text="📋", width=40,
                                        command=lambda: self.copy_to_clipboard(self.encrypted_pw.get()))
        self.copy_enc_btn.pack(side="right", padx=5)
        
        # Key output with better visualization
        key_output_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
        key_output_frame.pack(fill="x", pady=8)
        
        ctk.CTkLabel(key_output_frame, text="Encryption Key:", font=self.NORMAL_FONT).pack(side="left", padx=5)
        
        self.encryption_key = ctk.CTkEntry(key_output_frame, width=350, height=32,
                                         font=ctk.CTkFont(size=13))
        self.encryption_key.pack(side="left", fill="x", expand=True, padx=10)
        
        self.copy_key_btn = ctk.CTkButton(key_output_frame, text="📋", width=40,
                                        command=lambda: self.copy_to_clipboard(self.encryption_key.get()))
        self.copy_key_btn.pack(side="right", padx=5)
        
        # Important note about key security
        note_frame = ctk.CTkFrame(encrypt_frame, fg_color="transparent")
        note_frame.pack(fill="x", pady=5)
        
        note_label = ctk.CTkLabel(note_frame, 
                                text="⚠️ Important: Keep your encryption key safe. Without it, you cannot recover your password.",
                                font=ctk.CTkFont(size=12),
                                text_color=("orange", "#ffcc00"))
        note_label.pack(pady=5)
        
        # --- Decryption Section ---
        decrypt_section_frame = ctk.CTkFrame(master_frame, corner_radius=10)
        decrypt_section_frame.pack(pady=15, padx=20, fill="x")
        
        # Section header
        decrypt_header_frame = ctk.CTkFrame(decrypt_section_frame, fg_color="transparent")
        decrypt_header_frame.pack(fill="x", pady=5, padx=10)
        
        decrypt_title = ctk.CTkLabel(decrypt_header_frame, text="🔓 Password Decryption", 
                                   font=self.SUBHEADING_FONT)
        decrypt_title.pack(pady=(10, 5), anchor="w")
        
        # Divider
        divider = ctk.CTkFrame(decrypt_section_frame, height=2, fg_color=("gray70", "gray30"))
        divider.pack(fill="x", padx=10, pady=(0, 10))
        
        # Decryption content
        decrypt_frame = ctk.CTkFrame(decrypt_section_frame, fg_color="transparent")
        decrypt_frame.pack(fill="x", padx=15, pady=5)
        
        # Encrypted password input
        encrypted_input_frame = ctk.CTkFrame(decrypt_frame, fg_color="transparent")
        encrypted_input_frame.pack(fill="x", pady=8)
        
        ctk.CTkLabel(encrypted_input_frame, text="Encrypted Password:", font=self.NORMAL_FONT).pack(side="left", padx=5)
        
        self.decrypt_pw_entry = ctk.CTkEntry(encrypted_input_frame, width=400, height=32,
                                           font=ctk.CTkFont(size=13),
                                           placeholder_text="Paste encrypted password here")
        self.decrypt_pw_entry.pack(side="left", fill="x", expand=True, padx=10)
        
        # Key input
        key_input_frame = ctk.CTkFrame(decrypt_frame, fg_color="transparent")
        key_input_frame.pack(fill="x", pady=8)
        
        ctk.CTkLabel(key_input_frame, text="Encryption Key:", font=self.NORMAL_FONT).pack(side="left", padx=5)
        
        self.decrypt_key_entry = ctk.CTkEntry(key_input_frame, width=400, height=32,
                                            font=ctk.CTkFont(size=13),
                                            placeholder_text="Paste your encryption key here")
        self.decrypt_key_entry.pack(side="left", fill="x", expand=True, padx=10)
        
        # Button with improved styling
        decrypt_btn_frame = ctk.CTkFrame(decrypt_frame, fg_color="transparent")
        decrypt_btn_frame.pack(fill="x", pady=10)
        
        self.decrypt_btn = ctk.CTkButton(decrypt_btn_frame, text="Decrypt Password", 
                                       command=self.decrypt_password,
                                       font=self.BUTTON_FONT,
                                       height=32,
                                       fg_color=("#3a7ebf", "#1f538d"))
        self.decrypt_btn.pack(pady=(5, 15))
        
        # Result display
        decrypt_result_frame = ctk.CTkFrame(decrypt_frame, fg_color="transparent")
        decrypt_result_frame.pack(fill="x", pady=8)
        
        ctk.CTkLabel(decrypt_result_frame, text="Original Password:", font=self.NORMAL_FONT).pack(side="left", padx=5)
        
        self.decrypted_pw = ctk.CTkEntry(decrypt_result_frame, width=300, height=32,
                                        font=ctk.CTkFont(size=13))
        self.decrypted_pw.pack(side="left", fill="x", expand=True, padx=10)
        
        self.copy_dec_btn = ctk.CTkButton(decrypt_result_frame, text="📋", width=40,
                                        command=lambda: self.copy_to_clipboard(self.decrypted_pw.get()))
        self.copy_dec_btn.pack(side="right", padx=5)
        
    def update_length_value(self, value):
        """Update the displayed password length value from slider"""
        # Round to nearest integer
        length = round(float(value))
        self.pw_length_value.configure(text=str(length))

    def generate_password(self):
        """Generate a secure password based on user preferences"""
        try:
            # Get password length from the slider value
            length = int(float(self.pw_length_slider.get()))
        except ValueError:
            length = 16
            
        # Take into account the checkbox settings
        include_uppercase = self.include_uppercase_var.get()
        include_lowercase = self.include_lowercase_var.get()
        include_symbols = self.include_symbols_var.get()
        include_numbers = self.include_numbers_var.get()
        
        # Validate that at least one character type is selected
        if not any([include_uppercase, include_lowercase, include_symbols, include_numbers]):
            messagebox.showwarning("Warning", "Please select at least one character type")
            # Default to lowercase if nothing selected
            self.include_lowercase_var.set(True)
            include_lowercase = True
            
        # For now, we'll keep using the existing function, but in the future
        # these parameters could be passed to the password generator
        pw = encrypted_ps_gen.generate_password(length)
        
        # Update the display
        self.generated_pw.delete(0, tk.END)
        self.generated_pw.insert(0, pw)
        
        # Update status bar
        self.update_status(f"Generated new {length}-character password")

    def encrypt_password(self):
        """Encrypt a password and display the result with the encryption key"""
        pw = self.encrypt_entry.get()
        if not pw:
            messagebox.showwarning("Input Required", "Please enter a password to encrypt.")
            return
            
        try:
            # Show working status
            self.update_status("Encrypting password...")
            self.encrypt_btn.configure(state="disabled")
            self.update_idletasks()
            
            # Generate key and encrypt
            key = encrypted_ps_gen.generate_key()
            encrypted = encrypted_ps_gen.encrypt_password(pw, key, save=False)
            
            # Display results
            self.encrypted_pw.delete(0, tk.END)
            self.encrypted_pw.insert(0, encrypted.decode())
            self.encryption_key.delete(0, tk.END)
            self.encryption_key.insert(0, key.decode())
            
            # Update status
            self.update_status("Password encrypted successfully")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.update_status("Encryption failed")
        finally:
            self.encrypt_btn.configure(state="normal")

    def decrypt_password(self):
        """Decrypt an encrypted password using the provided key"""
        encrypted_pw = self.decrypt_pw_entry.get()
        key = self.decrypt_key_entry.get()
        
        if not encrypted_pw or not key:
            messagebox.showwarning("Input Required", "Please enter both the encrypted password and key.")
            return
            
        try:
            # Show working status
            self.update_status("Decrypting password...")
            self.decrypt_btn.configure(state="disabled")
            self.update_idletasks()
            
            # Decrypt the password
            decrypted = encrypted_ps_gen.decrypt_password(encrypted_pw, key)
            
            # Display result
            self.decrypted_pw.delete(0, tk.END)
            self.decrypted_pw.insert(0, decrypted)
            
            # Update status
            self.update_status("Password decrypted successfully")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt: {str(e)}")
            self.update_status("Decryption failed - check your key and encrypted password")
        finally:
            self.decrypt_btn.configure(state="normal")
            
    def copy_to_clipboard(self, text):
        """Copy the provided text to the clipboard with visual feedback"""
        if not text:
            self.update_status("Nothing to copy - field is empty")
            return
            
        self.clipboard_clear()
        self.clipboard_append(text)
        
        # Update status bar instead of showing a popup
        self.update_status("Copied to clipboard!")
        
        # Flash the status bar briefly with a highlight color to provide visual feedback
        original_color = self.status_bar.cget("fg_color")
        self.status_bar.configure(fg_color=("#c3e6cb", "#28a745"))  # Green success color
        
        # Reset the color after a short delay
        def reset_color():
            self.status_bar.configure(fg_color=original_color)
            
        self.after(1000, reset_color)
        
    def set_app_icon(self):
        """Set the application icon using logo.png from the assets folder"""
        try:
            # Path to the logo file
            logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
            if os.path.exists(logo_path):
                logo = PhotoImage(file=logo_path)
                self.iconphoto(True, logo)
        except Exception:
            # Silently fail if icon can't be set
            pass

    
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
        self.ip_reputation_tab = self.ip_notebook.add("IP Reputation")
        
        # === IP Analyzer Tab ===
        # Create a scrollable frame for the IP analyzer tab
        analyzer_scrollable_frame = ctk.CTkScrollableFrame(self.ip_analyzer_tab)
        analyzer_scrollable_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.analyzer_frame = ctk.CTkFrame(analyzer_scrollable_frame)
        self.analyzer_frame.pack(pady=5, padx=5, fill="both", expand=True)
        
        # Title for the analyzer tab
        analyzer_title = ctk.CTkLabel(self.analyzer_frame, text="IP Analyzer", 
                                      font=ctk.CTkFont(size=16, weight="bold"))
        analyzer_title.pack(pady=(5, 10))
        
        self.analyzer_label = ctk.CTkLabel(self.analyzer_frame, 
                                          text="Enter IPs to analyze (supports CIDR notation, e.g., 192.168.1.0/24):")
        self.analyzer_label.pack(pady=(10, 0), padx=10, anchor="w")
        self.analyzer_entry = ctk.CTkEntry(self.analyzer_frame, width=700)
        self.analyzer_entry.pack(pady=5, padx=10, fill="x")
        
        # Options frame
        options_frame = ctk.CTkFrame(self.analyzer_frame)
        options_frame.pack(pady=5, padx=10, fill="x")
        
        self.scan_ports_var = tk.BooleanVar(value=False)
        self.scan_ports_check = ctk.CTkCheckBox(options_frame, text="Scan common ports", 
                                              variable=self.scan_ports_var)
        self.scan_ports_check.pack(pady=5, side="left", padx=10)
        
        self.analyze_btn = ctk.CTkButton(self.analyzer_frame, text="Analyze IPs", 
                                        command=self.analyze_ips)
        self.analyze_btn.pack(pady=10)
        
        # Results area with a title
        results_frame = ctk.CTkFrame(self.analyzer_frame)
        results_frame.pack(pady=5, padx=10, fill="both", expand=True)
        
        results_title = ctk.CTkLabel(results_frame, text="Analysis Results",
                                   font=ctk.CTkFont(weight="bold"))
        results_title.pack(pady=5)
        
        # Add an export button to save the analysis results
        export_btn = ctk.CTkButton(results_frame, text="Export Analysis", 
                                 command=self.export_analysis_results,
                                 width=120)
        export_btn.pack(pady=5)
        
        self.analyzer_result = scrolledtext.ScrolledText(results_frame, width=90, height=22)
        self.analyzer_result.pack(pady=5, padx=10, fill="both", expand=True)
        
        # === IP Reputation Tab ===
        # Create a scrollable frame for the IP reputation tab
        reputation_scrollable_frame = ctk.CTkScrollableFrame(self.ip_reputation_tab)
        reputation_scrollable_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.reputation_frame = ctk.CTkFrame(reputation_scrollable_frame)
        self.reputation_frame.pack(pady=5, padx=5, fill="both", expand=True)
        
        # Title for the reputation tab
        reputation_title = ctk.CTkLabel(self.reputation_frame, text="IP Reputation Scanner", 
                                      font=ctk.CTkFont(size=16, weight="bold"))
        reputation_title.pack(pady=(5, 10))
        
        # Description label
        description = ctk.CTkLabel(self.reputation_frame, 
                                 text="Check IP addresses against security databases (AbuseIPDB, VirusTotal, WHOIS)")
        description.pack(pady=(0, 10), padx=10)
        
        # IP input
        ip_frame = ctk.CTkFrame(self.reputation_frame)
        ip_frame.pack(pady=5, padx=10, fill="x")
        
        ip_label = ctk.CTkLabel(ip_frame, text="Enter IPs to check (comma/space separated):")
        ip_label.pack(pady=5, side="left", padx=(10, 5))
        
        self.reputation_ip_entry = ctk.CTkEntry(ip_frame, width=400)
        self.reputation_ip_entry.pack(pady=5, side="left", padx=5, expand=True, fill="x")
        
        # API Keys frame
        keys_frame = ctk.CTkFrame(self.reputation_frame)
        keys_frame.pack(pady=10, padx=10, fill="x")
        
        # AbuseIPDB key
        abuse_frame = ctk.CTkFrame(keys_frame)
        abuse_frame.pack(pady=5, fill="x")
        
        abuse_label = ctk.CTkLabel(abuse_frame, text="AbuseIPDB API Key (optional):")
        abuse_label.pack(pady=5, side="left", padx=10)
        
        self.abuse_key_entry = ctk.CTkEntry(abuse_frame, width=350, placeholder_text="Enter API key or leave empty")
        self.abuse_key_entry.pack(pady=5, side="left", padx=10, expand=True, fill="x")
        
        # VirusTotal key
        vt_frame = ctk.CTkFrame(keys_frame)
        vt_frame.pack(pady=5, fill="x")
        
        vt_label = ctk.CTkLabel(vt_frame, text="VirusTotal API Key (optional):")
        vt_label.pack(pady=5, side="left", padx=10)
        
        self.vt_key_entry = ctk.CTkEntry(vt_frame, width=350, placeholder_text="Enter API key or leave empty")
        self.vt_key_entry.pack(pady=5, side="left", padx=10, expand=True, fill="x")
        
        # Help button
        help_frame = ctk.CTkFrame(keys_frame, fg_color="transparent")
        help_frame.pack(pady=5, fill="x")
        
        def show_api_help():
            messagebox.showinfo(
                "API Keys Information", 
                "API keys are not strictly necessary but are recommended for better results.\n\n"
                "Without API keys, only WHOIS information will be available.\n\n"
                "You can get free API keys from:\n"
                "- AbuseIPDB: https://www.abuseipdb.com/register\n"
                "- VirusTotal: https://www.virustotal.com/gui/join-us\n\n"
                "Note: Using the free tier of the api will lag a bit compared to the premium accounts"
            )
            
        help_btn = ctk.CTkButton(
            help_frame,
            text="API Key Information",
            command=show_api_help,
            width=150
        )
        help_btn.pack(pady=5, side="left", padx=10)
        
        # Scan button
        self.scan_ip_btn = ctk.CTkButton(
            self.reputation_frame,
            text="Check IP Reputation",
            command=self.check_ip_reputation,
            width=180
        )
        self.scan_ip_btn.pack(pady=10)
        
        # Export options
        export_frame = ctk.CTkFrame(self.reputation_frame)
        export_frame.pack(pady=5, padx=10, fill="x")
        
        export_label = ctk.CTkLabel(export_frame, text="Export Format:")
        export_label.pack(pady=5, side="left", padx=10)
        
        self.export_var = tk.StringVar(value="txt")
        
        txt_radio = ctk.CTkRadioButton(
            export_frame,
            text="Text",
            variable=self.export_var,
            value="txt"
        )
        txt_radio.pack(pady=5, side="left", padx=10)
        
        json_radio = ctk.CTkRadioButton(
            export_frame,
            text="JSON",
            variable=self.export_var,
            value="json"
        )
        json_radio.pack(pady=5, side="left", padx=10)
        
        # Export button (initially disabled)
        self.export_btn = ctk.CTkButton(
            export_frame,
            text="Export Results",
            command=self.export_reputation_results,
            state="disabled",
            width=120
        )
        self.export_btn.pack(pady=5, side="left", padx=20)
        
        # Results area with a title
        results_title_frame = ctk.CTkFrame(self.reputation_frame)
        results_title_frame.pack(pady=5, padx=10, fill="x")
        
        results_title = ctk.CTkLabel(results_title_frame, text="Scan Results",
                                   font=ctk.CTkFont(weight="bold"))
        results_title.pack(pady=5)
        
        self.reputation_result = scrolledtext.ScrolledText(self.reputation_frame, width=90, height=20)
        self.reputation_result.pack(pady=5, padx=10, fill="both", expand=True)
        
        # Store results for export
        self.reputation_data = {
            "all_results": [],
            "whois_results": {}
        }

    def check_ip_reputation(self):
        """Check IP addresses against security databases (AbuseIPDB, VirusTotal)"""
        ip_input = self.reputation_ip_entry.get().strip()
        
        if not ip_input:
            messagebox.showerror("Error", "Please enter IP addresses to check")
            return
        
        # Parse IPs properly using the IP scanner module
        ip_list = ip_scan.parse_ip_input(ip_input)
        if not ip_list:
            messagebox.showerror("Error", "No valid IP addresses found")
            return
        
        abuse_key = self.abuse_key_entry.get().strip() or None
        vt_key = self.vt_key_entry.get().strip() or None
        
        if not abuse_key and not vt_key:
            response = messagebox.askyesno(
                "No API Keys", 
                "You haven't provided any API keys. Only basic IP analysis will be performed.\n\n"
                "Would you like to continue?"
            )
            if not response:
                return
                
        # Show processing message
        self.reputation_result.config(state="normal")
        self.reputation_result.delete(1.0, tk.END)
        self.reputation_result.insert(tk.END, f"Checking {len(ip_list)} IP address(es)...\n")
        self.reputation_result.insert(tk.END, "This may take a moment...\n\n")
        self.reputation_result.config(state="disabled")
        self.update_idletasks()
        
        # Run scan in background thread
        self.scan_ip_btn.configure(state="disabled")
        threading.Thread(
            target=self._run_reputation_check, 
            args=(ip_list, abuse_key, vt_key), 
            daemon=True
        ).start()
    
    def _run_reputation_check(self, ips, abuse_key, vt_key):
        """Run the IP reputation check in a background thread"""
        try:
            # Initialize results storage
            all_results = []
            
            # Initialize the database
            ip_scan.init_db()
            
            # Process each IP
            for ip in ips:
                # Check AbuseIPDB
                if abuse_key:
                    result = ip_scan.check_abuseipdb(ip, abuse_key)
                    if result:
                        all_results.append(result)
                        ip_scan.save_result(result)
                        
                        # Update UI
                        self.reputation_result.config(state="normal")
                        self.reputation_result.insert(
                            tk.END, 
                            f"[AbuseIPDB] {ip} - {result['risk']} (Score: {result['score']})\n",
                            self._get_risk_tag(result['risk'])
                        )
                        self.reputation_result.config(state="disabled")
                        self.update_idletasks()
                        
                # Check VirusTotal
                if vt_key:
                    result = ip_scan.check_virustotal(ip, vt_key)
                    if result:
                        all_results.append(result)
                        ip_scan.save_result(result)
                        
                        # Update UI
                        self.reputation_result.config(state="normal")
                        self.reputation_result.insert(
                            tk.END, 
                            f"[VirusTotal] {ip} - {result['risk']} (Score: {result['score']})\n",
                            self._get_risk_tag(result['risk'])
                        )
                        self.reputation_result.config(state="disabled")
                        self.update_idletasks()
                
                # Add IP classification
                ip_obj = ipaddress.ip_address(ip)
                status = "❓ UNKNOWN"
                tag = "whois"
                
                if ip_obj.is_private:
                    status = "🏠 PRIVATE"
                    tag = "safe"
                elif ip_obj.is_loopback:
                    status = "🔄 LOOPBACK"
                    tag = "safe"
                else:
                    status = "🌐 PUBLIC"
                    tag = "whois"
                    
                self.reputation_result.insert(
                    tk.END,
                    f"[Classification] {status}\n",
                    tag
                )
                
                self.reputation_result.insert(tk.END, "---\n\n")
                self.reputation_result.config(state="disabled")
                self.update_idletasks()
            
            # Store results for export
            self.reputation_data = {
                "all_results": all_results
            }
            
            # Summary
            summary = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0}
            for r in all_results:
                summary[r["risk"].capitalize()] += 1
                
            self.reputation_result.config(state="normal")
            self.reputation_result.insert(tk.END, "\n=== Scan Summary ===\n", "heading")
            self.reputation_result.insert(tk.END, f"High   : {summary['High']}\n", "high_risk")
            self.reputation_result.insert(tk.END, f"Medium : {summary['Medium']}\n", "medium_risk")
            self.reputation_result.insert(tk.END, f"Low    : {summary['Low']}\n", "low_risk")
            self.reputation_result.insert(tk.END, f"Safe   : {summary['Safe']}\n", "safe")
            self.reputation_result.config(state="disabled")
            
            # Configure text tags
            self.reputation_result.tag_configure("heading", font=("TkDefaultFont", 10, "bold"))
            self.reputation_result.tag_configure("high_risk", foreground="red")
            self.reputation_result.tag_configure("medium_risk", foreground="orange")
            self.reputation_result.tag_configure("low_risk", foreground="blue")
            self.reputation_result.tag_configure("safe", foreground="green")
            self.reputation_result.tag_configure("whois", foreground="purple")
            
            # Enable export button
            self.export_btn.configure(state="normal")
            
        except Exception as e:
            self.reputation_result.config(state="normal")
            self.reputation_result.insert(tk.END, f"\nError during scan: {str(e)}\n")
            self.reputation_result.config(state="disabled")
            
        finally:
            # Re-enable scan button
            self.scan_ip_btn.configure(state="normal")
    
    def export_reputation_results(self):
        """Export IP reputation results to file"""
        if not self.reputation_data["all_results"] and not self.reputation_data["geo_results"]:
            messagebox.showerror("Error", "No data to export")
            return
            
        fmt = self.export_var.get()
        
        try:
            ip_scan.export_results(
                self.reputation_data["all_results"], 
                self.reputation_data["geo_results"], 
                fmt=fmt
            )
            messagebox.showinfo("Success", f"Results exported to scan_results.{fmt}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {str(e)}")
    
    def export_analysis_results(self):
        """Export IP analysis results to file"""
        # Get the content from the analyzer result text widget
        content = self.analyzer_result.get(1.0, tk.END)
        if not content.strip():
            messagebox.showerror("Error", "No analysis data to export")
            return
            
        # Get current timestamp for unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ip_analysis_{timestamp}.txt"
        
        try:
            # Save content to file
            with open(filename, "w") as f:
                # Add a header
                f.write("IP ANALYZER RESULTS\n")
                f.write(f"Exported on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                # Write the main content (strip formatting tags)
                f.write(content)
                
            messagebox.showinfo("Success", f"Analysis results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {str(e)}")
    
    def _get_risk_tag(self, risk):
        """Get the appropriate tag for coloring risk levels"""
        risk = risk.lower()
        if risk == "high":
            return "high_risk"
        elif risk == "medium":
            return "medium_risk"
        elif risk == "low":
            return "low_risk"
        else:
            return "safe"
        
    def analyze_ips(self):
        """Analyze IP addresses with security and geolocation features"""
        # Parse IP input, supporting CIDR notation
        ip_input = self.analyzer_entry.get().strip()
        
        if not ip_input:
            messagebox.showwarning("Input Required", "Please enter IP addresses to analyze.")
            return
        
        # Update status and UI
        self.update_status(f"Parsing IP addresses from input...")
        self.analyze_btn.configure(state="disabled")
        self.update_idletasks()
        
        # Parse the IPs
        ip_list = ip_scan.parse_ip_input(ip_input)
        scan_ports = self.scan_ports_var.get()
        
        if not ip_list:
            messagebox.showerror("Error", "No valid IP addresses found in your input")
            self.analyze_btn.configure(state="normal")
            self.update_status("Analysis canceled - no valid IPs")
            return
            
        # Show a "processing" message with count and options information
        self.analyzer_result.config(state="normal")
        self.analyzer_result.delete(1.0, tk.END)
        
        # Format the header with more information
        self.analyzer_result.insert(tk.END, "🔍 IP ANALYSIS STARTED\n", "header")
        self.analyzer_result.insert(tk.END, "-" * 50 + "\n")
        self.analyzer_result.insert(tk.END, f"Analyzing {len(ip_list)} IP address(es)\n")
        self.analyzer_result.insert(tk.END, f"Port scanning: {'Enabled' if scan_ports else 'Disabled'}\n")
        self.analyzer_result.insert(tk.END, f"Started at: {datetime.now().strftime('%H:%M:%S')}\n")
        self.analyzer_result.insert(tk.END, "-" * 50 + "\n\n")
        self.analyzer_result.insert(tk.END, "Please wait, this may take a moment...\n")
        
        # Set up tags for the header
        self.analyzer_result.tag_configure("header", font=("TkDefaultFont", 12, "bold"))
        self.analyzer_result.config(state="disabled")
        
        # Update the status bar
        self.update_status(f"Analyzing {len(ip_list)} IP addresses...")
        self.update_idletasks()
        
        # Run the analysis in a separate thread
        threading.Thread(target=self._run_ip_analysis, args=(ip_list, scan_ports), daemon=True).start()
    
    def _run_ip_analysis(self, ip_list, scan_ports):
        """Run IP analysis in background thread"""
        start_time = datetime.now()
        
        try:
            # Create analyzer directly to avoid redundant object creation
            analyzer = ip_scan.IPAnalyzer()
            
            # Analyze IPs - use analyzer directly instead of the redundant function
            results = analyzer.analyze_ips(ip_list, scan_ports)
            
            # Calculate elapsed time
            elapsed_time = datetime.now() - start_time
            elapsed_seconds = elapsed_time.total_seconds()
            
            # Display results in the text area with improved formatting
            self.analyzer_result.config(state="normal")
            self.analyzer_result.delete(1.0, tk.END)
            
            # Add a professional summary header with improved visual styling
            self.analyzer_result.insert(tk.END, "� IP ANALYSIS RESULTS 📊\n", "header")
            self.analyzer_result.insert(tk.END, "═" * 60 + "\n\n")
            
            # Time information
            self.analyzer_result.insert(tk.END, f"Analysis completed in {elapsed_seconds:.2f} seconds\n", "timestamp")
            self.analyzer_result.insert(tk.END, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n", "timestamp")
            
            # Count different IP types
            ip_types = {"public": 0, "private": 0, "malicious": 0, "other": 0}
            
            # Process each result with better formatting
            for i, result in enumerate(results):
                ip = result.get("ip", "Unknown")
                version = result.get("version", "Unknown")
                classification = result.get("classification", {})
                
                # Count IP types
                if classification.get("potentially_malicious", False):
                    ip_types["malicious"] += 1
                elif classification.get("private", False):
                    ip_types["private"] += 1
                elif classification.get("global", False):
                    ip_types["public"] += 1
                else:
                    ip_types["other"] += 1
                
                # Create IP header with card-style formatting
                self.analyzer_result.insert(tk.END, f"\n╔═ IP #{i+1} ", "card_header")
                self.analyzer_result.insert(tk.END, f"of {len(results)} ═╗\n", "card_header")
                
                # IP address with prominent display
                self.analyzer_result.insert(tk.END, f"║ ", "card_border")
                self.analyzer_result.insert(tk.END, f"Address: {ip}", "ip_bold")
                self.analyzer_result.insert(tk.END, f" [{version}]", "ip_version")
                self.analyzer_result.insert(tk.END, f" {' ' * (45 - len(ip) - len(version))}║\n", "card_border")
                
                # Status line with clear visual indicators
                self.analyzer_result.insert(tk.END, "║ Status: ", "card_border")
                
                # Classification with better icons and color-coding
                if classification.get("potentially_malicious", False):
                    self.analyzer_result.insert(tk.END, "⚠️  POTENTIALLY MALICIOUS", "alert_text")
                    classification_icon = "⚠️"
                elif classification.get("private", False):
                    self.analyzer_result.insert(tk.END, "🏠 PRIVATE NETWORK", "private_text")
                    classification_icon = "🏠"
                elif classification.get("loopback", False):
                    self.analyzer_result.insert(tk.END, "🔄 LOOPBACK", "loopback_text")
                    classification_icon = "🔄"
                elif classification.get("reserved", False):
                    self.analyzer_result.insert(tk.END, "🚫 RESERVED", "reserved_text")
                    classification_icon = "🚫"
                elif classification.get("global", False):
                    self.analyzer_result.insert(tk.END, "🌐 PUBLIC IP", "public_text")
                    classification_icon = "🌐"
                else:
                    self.analyzer_result.insert(tk.END, "❓ UNKNOWN TYPE", "unknown_text")
                    classification_icon = "❓"
                
                # Complete the card border
                self.analyzer_result.insert(tk.END, f"{' ' * 30}║\n", "card_border")
                
                # Geolocation section with card-style formatting
                geo = result.get("geolocation", {})
                self.analyzer_result.insert(tk.END, "╠═ Geolocation Info ", "card_section")
                self.analyzer_result.insert(tk.END, "═" * 30, "card_section")
                self.analyzer_result.insert(tk.END, "╣\n", "card_section")
                
                # Create a more organized geolocation display with card-style formatting
                if geo.get("status") == "success":
                    # Country & region
                    country = geo.get('country', 'Unknown')
                    region = geo.get('regionName', 'Unknown')
                    city = geo.get('city', 'Unknown')
                    location = f"{city}, {region}, {country}".replace(", Unknown", "")
                    
                    self.analyzer_result.insert(tk.END, "║  ", "card_border")
                    self.analyzer_result.insert(tk.END, "📍 Location: ", "geo_label")
                    self.analyzer_result.insert(tk.END, f"{location}", "geo_value")
                    self.analyzer_result.insert(tk.END, f"{' ' * (37 - len(location))}║\n", "card_border")
                    
                    # Network info
                    isp = geo.get('isp', 'Unknown')
                    org = geo.get('org', 'Unknown') if geo.get('org') != geo.get('isp') else ''
                    network_info = f"{isp}{' / ' + org if org else ''}"
                    
                    self.analyzer_result.insert(tk.END, "║  ", "card_border")
                    self.analyzer_result.insert(tk.END, "🌐 Network: ", "geo_label")
                    self.analyzer_result.insert(tk.END, f"{network_info[:35]}", "geo_value")
                    if len(network_info) > 35:
                        padding = 0
                        self.analyzer_result.insert(tk.END, "...", "geo_value")
                    else:
                        padding = 35 - len(network_info)
                    self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "card_border")
                else:
                    self.analyzer_result.insert(tk.END, "║  ", "card_border")
                    self.analyzer_result.insert(tk.END, "⚠️ Unable to retrieve geolocation data", "warning")
                    self.analyzer_result.insert(tk.END, f"{' ' * 13}║\n", "card_border")
                
                # Port scan information with card-style formatting
                ports = result.get("ports", {})
                open_ports = ports.get("open_ports", [])
                if scan_ports:
                    self.analyzer_result.insert(tk.END, "╠═ Port Scan Results ", "card_section")
                    self.analyzer_result.insert(tk.END, "═" * 28, "card_section")
                    self.analyzer_result.insert(tk.END, "╣\n", "card_section")
                    
                    if open_ports:
                        # Show open ports count
                        self.analyzer_result.insert(tk.END, "║  ", "card_border")
                        self.analyzer_result.insert(tk.END, f"Found {len(open_ports)} open port", "ports_header")
                        if len(open_ports) != 1:
                            self.analyzer_result.insert(tk.END, "s", "ports_header")
                        self.analyzer_result.insert(tk.END, f"{' ' * (37 - len(str(len(open_ports))) - 17)}║\n", "card_border")
                        
                        # List open ports
                        ports_str = ", ".join(map(str, sorted(open_ports)))
                        self.analyzer_result.insert(tk.END, "║  ", "card_border")
                        self.analyzer_result.insert(tk.END, "🔓 Open: ", "port_label")
                        self.analyzer_result.insert(tk.END, f"{ports_str[:40]}", "alert")
                        if len(ports_str) > 40:
                            padding = 0
                            self.analyzer_result.insert(tk.END, "...", "alert")
                        else:
                            padding = 40 - len(ports_str)
                        self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "card_border")
                        
                        # Add common service suggestions for well-known ports
                        common_ports = {
                            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
                            80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-Alt"
                        }
                        
                        services = []
                        for port in open_ports:
                            if port in common_ports:
                                services.append(f"{port}/{common_ports[port]}")
                        
                        if services:
                            services_str = ", ".join(services)
                            self.analyzer_result.insert(tk.END, "║  ", "card_border")
                            self.analyzer_result.insert(tk.END, "🔌 Services: ", "port_label")
                            self.analyzer_result.insert(tk.END, f"{services_str[:37]}", "service_info")
                            if len(services_str) > 37:
                                padding = 0
                                self.analyzer_result.insert(tk.END, "...", "service_info")
                            else:
                                padding = 37 - len(services_str)
                            self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "card_border")
                    else:
                        self.analyzer_result.insert(tk.END, "║  ", "card_border")
                        self.analyzer_result.insert(tk.END, "✓ No open ports detected", "secure_port")
                        self.analyzer_result.insert(tk.END, f"{' ' * 25}║\n", "card_border")
                
                # Add a visually appealing card bottom
                self.analyzer_result.insert(tk.END, "╚" + "═" * 58 + "╝\n\n")
            
            # Add summary section with card-style formatting
            self.analyzer_result.insert(tk.END, "\n╔" + "═" * 58 + "╗\n", "summary_border")
            self.analyzer_result.insert(tk.END, "║" + " " * 18 + "📊 ANALYSIS SUMMARY" + " " * 18 + "║\n", "summary_header")
            self.analyzer_result.insert(tk.END, "╠" + "═" * 58 + "╣\n", "summary_border")
            
            # Create a more visually structured summary with card-style formatting
            self.analyzer_result.insert(tk.END, "║ ", "summary_border")
            self.analyzer_result.insert(tk.END, f"Total IPs analyzed: {len(ip_list)}", "summary_total")
            padding = 38 - len(f"Total IPs analyzed: {len(ip_list)}")
            self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "summary_border")
            
            # IP Classification header
            self.analyzer_result.insert(tk.END, "║ ", "summary_border")
            self.analyzer_result.insert(tk.END, "IP Classification:", "summary_section")
            self.analyzer_result.insert(tk.END, f"{' ' * 39}║\n", "summary_border")
            
            # IP type counts with appropriate styling
            self.analyzer_result.insert(tk.END, "║   ", "summary_border")
            self.analyzer_result.insert(tk.END, f"• Public IPs: {ip_types['public']}", "public_ip")
            padding = 40 - len(f"• Public IPs: {ip_types['public']}")
            self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "summary_border")
            
            self.analyzer_result.insert(tk.END, "║   ", "summary_border")
            self.analyzer_result.insert(tk.END, f"• Private IPs: {ip_types['private']}", "private_ip")
            padding = 40 - len(f"• Private IPs: {ip_types['private']}")
            self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "summary_border")
            
            self.analyzer_result.insert(tk.END, "║   ", "summary_border")
            self.analyzer_result.insert(tk.END, f"• Other IPs: {ip_types['other']}", "other_ip")
            padding = 40 - len(f"• Other IPs: {ip_types['other']}")
            self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "summary_border")
            
            # Highlight malicious IPs if found with different styling based on count
            malicious_style = "malicious_alert" if ip_types['malicious'] > 0 else "summary_normal"
            self.analyzer_result.insert(tk.END, "║   ", "summary_border")
            self.analyzer_result.insert(tk.END, f"• Potentially malicious: {ip_types['malicious']}", malicious_style)
            padding = 40 - len(f"• Potentially malicious: {ip_types['malicious']}")
            self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "summary_border")
            
            # Port summary if port scanning was enabled
            if scan_ports:
                all_open_ports = set()
                for result in results:
                    ports = result.get("ports", {})
                    all_open_ports.update(ports.get("open_ports", []))
                
                # Port scan header
                self.analyzer_result.insert(tk.END, "║ ", "summary_border")
                self.analyzer_result.insert(tk.END, "Port Scan Summary:", "summary_section")
                self.analyzer_result.insert(tk.END, f"{' ' * 39}║\n", "summary_border")
                
                if all_open_ports:
                    self.analyzer_result.insert(tk.END, "║   ", "summary_border")
                    self.analyzer_result.insert(tk.END, f"• Unique open ports: {len(all_open_ports)}", "summary_normal")
                    padding = 40 - len(f"• Unique open ports: {len(all_open_ports)}")
                    self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "summary_border")
                    
                    # Format ports list to fit in the card
                    ports_str = ", ".join(map(str, sorted(all_open_ports)))
                    if len(ports_str) > 50:
                        ports_str = ports_str[:47] + "..."
                    
                    self.analyzer_result.insert(tk.END, "║   ", "summary_border")
                    self.analyzer_result.insert(tk.END, f"• Open ports: {ports_str}", "ports_list")
                    padding = 40 - len(f"• Open ports: {ports_str}")
                    if padding < 0:
                        padding = 0
                    self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "summary_border")
                else:
                    self.analyzer_result.insert(tk.END, "║   ", "summary_border")
                    self.analyzer_result.insert(tk.END, "• No open ports detected across all IPs", "summary_normal")
                    padding = 40 - len("• No open ports detected across all IPs")
                    if padding < 0:
                        padding = 0
                    self.analyzer_result.insert(tk.END, f"{' ' * padding}║\n", "summary_border")
            
            # Summary footer
            self.analyzer_result.insert(tk.END, "╚" + "═" * 58 + "╝\n", "summary_border")
            
            # Add export reminder
            # self.analyzer_result.insert(tk.END, "\n💡 Tip: You can save this report using the Export button below\n", "tip")
            
            # Configure text tags with enhanced styling for card-based layout
            # Header tags
            self.analyzer_result.tag_configure("header", font=("Arial", 14, "bold"), foreground="#3366cc")
            self.analyzer_result.tag_configure("timestamp", font=("Arial", 9), foreground="#777777")
            
            # Card structure tags
            self.analyzer_result.tag_configure("card_header", foreground="#3366cc", font=("Courier", 10, "bold"))
            self.analyzer_result.tag_configure("card_border", foreground="#3366cc")
            self.analyzer_result.tag_configure("card_section", foreground="#0099cc", font=("Courier", 10))
            self.analyzer_result.tag_configure("summary_border", foreground="#6600cc")
            self.analyzer_result.tag_configure("summary_header", foreground="white", background="#6600cc", font=("Arial", 12, "bold"))
            
            # IP and classification tags
            self.analyzer_result.tag_configure("index", foreground="gray", font=("Arial", 10))
            self.analyzer_result.tag_configure("ip_bold", foreground="#000066", font=("Arial", 11, "bold"))
            self.analyzer_result.tag_configure("ip_version", foreground="#3366cc", font=("Arial", 10))
            
            # Classification tags with enhanced colors
            self.analyzer_result.tag_configure("classification", foreground="#660066", font=("Arial", 10, "bold"))
            self.analyzer_result.tag_configure("alert_text", foreground="#cc0000", font=("Arial", 10, "bold"))
            self.analyzer_result.tag_configure("private_text", foreground="#006633", font=("Arial", 10))
            self.analyzer_result.tag_configure("public_text", foreground="#0066cc", font=("Arial", 10))
            self.analyzer_result.tag_configure("loopback_text", foreground="#666633", font=("Arial", 10))
            self.analyzer_result.tag_configure("reserved_text", foreground="#666699", font=("Arial", 10))
            self.analyzer_result.tag_configure("unknown_text", foreground="#666666", font=("Arial", 10))
            
            # Geolocation tags
            self.analyzer_result.tag_configure("geo_label", foreground="#666699", font=("Arial", 9, "bold"))
            self.analyzer_result.tag_configure("geo_value", foreground="#000099", font=("Arial", 10))
            self.analyzer_result.tag_configure("warning", foreground="#cc6600", font=("Arial", 10))
            
            # Port scanning tags
            self.analyzer_result.tag_configure("ports_header", foreground="#663399", font=("Arial", 9, "bold"))
            self.analyzer_result.tag_configure("port_label", foreground="#660066", font=("Arial", 9, "bold"))
            self.analyzer_result.tag_configure("alert", foreground="#cc0000", font=("Arial", 10))
            self.analyzer_result.tag_configure("secure_port", foreground="#006600", font=("Arial", 10))
            self.analyzer_result.tag_configure("service_info", foreground="#339933", font=("Arial", 10))
            self.analyzer_result.tag_configure("normal", font=("Arial", 10))
            
            # Summary section tags
            self.analyzer_result.tag_configure("summary_total", font=("Arial", 11, "bold"), foreground="#000066")
            self.analyzer_result.tag_configure("summary_section", font=("Arial", 11, "bold"), foreground="#333399")
            self.analyzer_result.tag_configure("public_ip", font=("Arial", 10), foreground="#339933")
            self.analyzer_result.tag_configure("private_ip", font=("Arial", 10), foreground="#0066cc")
            self.analyzer_result.tag_configure("other_ip", font=("Arial", 10), foreground="#9900cc")
            self.analyzer_result.tag_configure("malicious_alert", font=("Arial", 10, "bold"), foreground="#cc0000")
            self.analyzer_result.tag_configure("summary_normal", font=("Arial", 10))
            self.analyzer_result.tag_configure("ports_list", font=("Arial", 10), foreground="#cc6600")
            self.analyzer_result.tag_configure("tip", font=("Arial", 10, "italic"), foreground="#777777")
            
            # Update status bar with completion message
            self.update_status(f"Analysis completed - {len(ip_list)} IPs analyzed in {elapsed_seconds:.2f} seconds")
            
        except Exception as e:
            self.analyzer_result.config(state="normal")
            self.analyzer_result.delete(1.0, tk.END)
            self.analyzer_result.insert(tk.END, "❌ ERROR DURING ANALYSIS\n\n", "error_header")
            self.analyzer_result.insert(tk.END, f"An error occurred while analyzing IP addresses:\n{str(e)}\n\n", "error_text")
            self.analyzer_result.insert(tk.END, "Please check your input and try again.", "error_help")
            
            # Configure error styles
            self.analyzer_result.tag_configure("error_header", font=("Arial", 12, "bold"), foreground="#cc0000")
            self.analyzer_result.tag_configure("error_text", font=("Arial", 10))
            self.analyzer_result.tag_configure("error_help", font=("Arial", 10, "italic"))
            
            # Update status bar with error message
            self.update_status(f"Analysis failed: {str(e)}")
            
        finally:
            self.analyzer_result.config(state="disabled")
            # Re-enable the analyze button
            self.analyze_btn.configure(state="normal")
        
    def create_vas_tab(self):
        """Create and configure the Vulnerability Assessment Scanner tab"""
        # Create a scrollable frame for the vulnerability scanner tab
        vas_scrollable_frame = ctk.CTkScrollableFrame(self.vas_tab)
        vas_scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # --- Header Section ---
        header_frame = ctk.CTkFrame(vas_scrollable_frame, fg_color="transparent")
        header_frame.pack(pady=(5, 15), padx=10, fill="x")
        
        header_label = ctk.CTkLabel(
            header_frame, 
            text="🔍 Vulnerability Assessment Scanner", 
            font=self.HEADING_FONT
        )
        header_label.pack(anchor="w")
        
        description = ctk.CTkLabel(
            header_frame,
            text="Scan target systems for open ports and potential vulnerabilities using NVD database",
            font=self.NORMAL_FONT,
            text_color=("gray50", "gray70")
        )
        description.pack(anchor="w", pady=(0, 5))
        
        # Add a divider
        divider = ctk.CTkFrame(vas_scrollable_frame, height=2, fg_color=("gray70", "gray30"))
        divider.pack(fill="x", padx=10, pady=(0, 15))
        
        # --- Input Section ---
        input_section = ctk.CTkFrame(vas_scrollable_frame, corner_radius=10)
        input_section.pack(pady=10, padx=10, fill="x")
        
        # Section title
        input_header = ctk.CTkLabel(
            input_section, 
            text="📌 Target Configuration", 
            font=self.SUBHEADING_FONT
        )
        input_header.pack(pady=(10, 5), padx=15, anchor="w")
        
        # IP Address input with better layout
        ip_frame = ctk.CTkFrame(input_section, fg_color="transparent")
        ip_frame.pack(pady=10, padx=15, fill="x")
        
        self.vas_label = ctk.CTkLabel(
            ip_frame, 
            text="Target IP Address:",
            font=self.NORMAL_FONT,
            width=150,
            anchor="w"
        )
        self.vas_label.pack(pady=5, side="left")
        
        self.vas_ip_entry = ctk.CTkEntry(
            ip_frame, 
            width=250,
            height=32,
            font=self.NORMAL_FONT,
            placeholder_text="Enter IP address (e.g., 192.168.1.1)"
        )
        self.vas_ip_entry.pack(pady=5, side="left", padx=10, expand=True, fill="x")
        
        # API Key input with better layout
        api_frame = ctk.CTkFrame(input_section, fg_color="transparent")
        api_frame.pack(pady=10, padx=15, fill="x")
        
        self.vas_api_label = ctk.CTkLabel(
            api_frame, 
            text="NVD API Key:",
            font=self.NORMAL_FONT,
            width=150,
            anchor="w"
        )
        self.vas_api_label.pack(pady=5, side="left")
        
        self.vas_api_entry = ctk.CTkEntry(
            api_frame, 
            width=350,
            height=32,
            font=self.NORMAL_FONT,
            placeholder_text="Optional: Enter API key to improve results"
        )
        self.vas_api_entry.pack(pady=5, side="left", padx=10, expand=True, fill="x")
        
        # Help button with tooltip
        help_btn = ctk.CTkButton(
            api_frame, 
            text="?", 
            width=30, 
            height=30, 
            command=lambda: messagebox.showinfo(
                "NVD API Key Information", 
                "An API key is not strictly necessary but is recommended for better results.\n\n"
                "Without an API key, you may encounter rate limiting or less accurate results.\n\n"
                "You can get a free API key from the NVD website:\n"
                "https://nvd.nist.gov/developers/request-an-api-key"
            ),
            corner_radius=15,
            fg_color=("gray70", "gray40"),
            hover_color=("gray50", "gray30")
        )
        help_btn.pack(side="right", padx=5)
        self.show_tooltip(help_btn, "Learn about NVD API keys")
        
        # Note about the API key
        note_frame = ctk.CTkFrame(input_section, fg_color=("gray95", "gray15"), corner_radius=5)
        note_frame.pack(pady=(0, 10), padx=15, fill="x")
        
        note_text = ctk.CTkLabel(
            note_frame,
            text="💡 A National Vulnerability Database (NVD) API key will improve scan accuracy and avoid rate limits",
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray70")
        )
        note_text.pack(pady=8, padx=10)
        
        # --- Controls Section ---
        controls_frame = ctk.CTkFrame(vas_scrollable_frame, corner_radius=10)
        controls_frame.pack(pady=10, padx=10, fill="x")
        
        # Controls header
        controls_header = ctk.CTkLabel(
            controls_frame, 
            text="🎮 Scan Controls", 
            font=self.SUBHEADING_FONT
        )
        controls_header.pack(pady=(10, 5), padx=15, anchor="w")
        
        # Button and options row with better organization
        button_row = ctk.CTkFrame(controls_frame, fg_color="transparent")
        button_row.pack(pady=10, padx=15, fill="x")
        
        # Left side - Scan button with icon
        self.vas_scan_btn = ctk.CTkButton(
            button_row, 
            text="🔍 Start Scan", 
            command=self.start_vas_scan,
            width=150,
            height=38,
            font=self.BUTTON_FONT,
            fg_color=("#3a7ebf", "#1f538d")
        )
        self.vas_scan_btn.pack(pady=5, side="left", padx=(0, 20))
        self.show_tooltip(self.vas_scan_btn, "Begin port scanning and vulnerability assessment")
        
        # Right side - Export options
        export_frame = ctk.CTkFrame(button_row, fg_color="transparent")
        export_frame.pack(pady=5, side="right", fill="x", expand=True)
        
        # Format selection with label
        format_frame = ctk.CTkFrame(export_frame, fg_color="transparent")
        format_frame.pack(side="left", fill="x")
        
        format_label = ctk.CTkLabel(
            format_frame, 
            text="Export format:",
            font=self.NORMAL_FONT
        )
        format_label.pack(side="left", padx=(0, 10))
        
        # Radio buttons with better styling
        self.export_format_var = tk.StringVar(value="json")
        
        # JSON option
        json_radio = ctk.CTkRadioButton(
            format_frame, 
            text="JSON", 
            variable=self.export_format_var,
            value="json",
            font=self.NORMAL_FONT
        )
        json_radio.pack(side="left", padx=5)
        self.show_tooltip(json_radio, "Export as structured JSON data")
        
        # HTML option
        html_radio = ctk.CTkRadioButton(
            format_frame, 
            text="HTML Report", 
            variable=self.export_format_var,
            value="html",
            font=self.NORMAL_FONT
        )
        html_radio.pack(side="left", padx=5)
        self.show_tooltip(html_radio, "Export as formatted HTML report")
        
        # Export button
        self.vas_download_btn = ctk.CTkButton(
            button_row, 
            text="💾 Export Results", 
            command=self.download_vas_results,
            width=150,
            height=38,
            font=self.BUTTON_FONT,
            state="disabled",
            fg_color=("#45a049", "#2e6830")
        )
        self.vas_download_btn.pack(pady=5, side="right", padx=10)
        self.show_tooltip(self.vas_download_btn, "Save scan results to file")
        
        # --- Results Section ---
        results_section = ctk.CTkFrame(vas_scrollable_frame, corner_radius=10)
        results_section.pack(pady=10, padx=10, fill="both", expand=True)
        
        # Results header
        results_header = ctk.CTkLabel(
            results_section, 
            text="📊 Scan Results", 
            font=self.SUBHEADING_FONT
        )
        results_header.pack(pady=(10, 5), padx=15, anchor="w")
        
        # Styled text area for results
        results_frame = ctk.CTkFrame(results_section, fg_color="transparent")
        results_frame.pack(pady=10, padx=15, fill="both", expand=True)
        
        # Results area with better styling
        self.vas_result = scrolledtext.ScrolledText(
            results_frame, 
            width=90, 
            height=25, 
            font=("Consolas", 11),
            bg="#f5f5f5" if ctk.get_appearance_mode() == "light" else "#1e1e1e",
            fg="#333333" if ctk.get_appearance_mode() == "light" else "#e0e0e0",
            state="normal",
            wrap=tk.WORD,
            padx=10,
            pady=10
        )
        self.vas_result.pack(pady=5, padx=0, fill="both", expand=True)
        
        # Add initial instructions in the results area
        self.vas_result.insert(tk.END, "📝 Instructions:\n\n")
        self.vas_result.insert(tk.END, "1. Enter a target IP address to scan\n")
        self.vas_result.insert(tk.END, "2. Optionally add an NVD API key for better results\n")
        self.vas_result.insert(tk.END, "3. Click 'Start Scan' to begin vulnerability assessment\n")
        self.vas_result.insert(tk.END, "4. Results will appear here when the scan completes\n\n")
        self.vas_result.insert(tk.END, "⚠️ Note: Use responsibly and only scan systems you have permission to test\n")
        self.vas_result.config(state="disabled")
        
        # Store scan results for download
        self.current_scan_data = None

    def start_vas_scan(self):
        """Start vulnerability scanning in a background thread"""
        # Get input values
        ip = self.vas_ip_entry.get().strip()
        api_key = self.vas_api_entry.get().strip() or None
        
        # Validate IP address format
        if not ip:
            messagebox.showwarning("Missing Input", "Please enter a target IP address")
            return
        
        # Update status and disable scan button to prevent multiple scans
        self.update_status(f"Preparing to scan {ip}...")
        self.vas_scan_btn.configure(state="disabled")
        
        # Start scan in background thread
        threading.Thread(target=self.run_vas_scan, args=(ip, api_key), daemon=True).start()

    def run_vas_scan(self, ip, api_key):
        """Execute vulnerability scan in background thread"""
        start_time = datetime.now()
        
        try:
            # Update UI to scanning state
            self.vas_scan_btn.configure(state="disabled")
            self.vas_download_btn.configure(state="disabled")
            self.current_scan_data = None
            self.update_status(f"Scanning {ip} for vulnerabilities...")
            
            # Initialize result display
            self.vas_result.config(state="normal")
            self.vas_result.delete(1.0, tk.END)
            
            # Create stylish header for scan
            self.vas_result.insert(tk.END, "🔍 VULNERABILITY SCAN STARTED\n", "scan_header")
            self.vas_result.insert(tk.END, "═" * 70 + "\n\n", "separator")
            self.vas_result.insert(tk.END, f"Target IP: {ip}\n", "target_info")
            self.vas_result.insert(tk.END, f"Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n", "timestamp")
            self.vas_result.insert(tk.END, f"API Key: {'Provided ✓' if api_key else 'Not provided ✗'}\n\n", "api_info")
            
            # Create scanner instance with API key
            scanner = vas.VulnerabilityScanner(api_key)
            
            # Validate IP address
            if not scanner.validate_ip(ip):
                self.vas_result.insert(tk.END, "❌ ERROR: Invalid IP address format\n\n", "error")
                self.vas_result.insert(tk.END, "Please enter a valid IPv4 address (e.g., 192.168.1.1)\n", "error_details")
                self.vas_result.config(state="disabled")
                self.vas_scan_btn.configure(state="normal")
                self.update_status("Scan failed: Invalid IP address")
                return
            
            # Show scanning progress
            self.vas_result.insert(tk.END, "📡 SCANNING PROGRESS\n", "section_header")
            self.vas_result.insert(tk.END, "─" * 70 + "\n\n", "separator")
            
            # Port scanning phase
            self.vas_result.insert(tk.END, "➤ Initiating port scan...\n", "progress")
            self.vas_result.config(state="disabled")
            self.update()  # Force UI update
            
            # Run the scan
            scan_data = scanner.scan_target(ip)
            self.current_scan_data = scan_data  # Store scan results for download
            
            # Continue updating results
            self.vas_result.config(state="normal")
            results = scan_data.get('results', [])
            
            if not results:
                self.vas_result.insert(tk.END, "✓ Port scan completed - No open ports found\n\n", "info")
                self.vas_result.insert(tk.END, "📝 SCAN SUMMARY\n", "summary_header")
                self.vas_result.insert(tk.END, "─" * 70 + "\n\n", "separator")
                self.vas_result.insert(tk.END, "No open ports were detected on the target system.\n", "summary_detail")
                self.vas_result.insert(tk.END, "The host may be offline, protected by a firewall, or not running any services.\n", "summary_detail")
                
                elapsed_time = datetime.now() - start_time
                self.vas_result.insert(tk.END, f"\nScan completed in {elapsed_time.total_seconds():.2f} seconds\n", "timestamp")
                self.vas_result.config(state="disabled")
                self.vas_scan_btn.configure(state="normal")
                self.update_status(f"Scan completed - No open ports found on {ip}")
                return
            
            # Show port scan results
            self.vas_result.insert(tk.END, f"✓ Port scan completed - Found {len(results)} open ports\n", "success")
            self.vas_result.insert(tk.END, "➤ Checking for vulnerabilities...\n\n", "progress")
            
            # Create vulnerability results section
            self.vas_result.insert(tk.END, "🛡️ VULNERABILITY ASSESSMENT\n", "section_header")
            self.vas_result.insert(tk.END, "─" * 70 + "\n\n", "separator")
            
            # Track vulnerabilities by severity
            total_vulns = 0
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
            
            # Process and display each port
            for i, result in enumerate(results):
                port = result.get('port', 'unknown')
                service = result.get('service', '')
                banner = result.get('banner', '')
                vulnerabilities = result.get('vulnerabilities', [])
                
                # Format port information with more structure
                port_header = f"PORT {port}"
                if service:
                    port_header += f" - {service}"
                
                self.vas_result.insert(tk.END, f"[{i+1}/{len(results)}] {port_header}\n", "port_header")
                
                if banner:
                    self.vas_result.insert(tk.END, f"  Banner: {banner}\n", "banner_info")
                
                # Count and categorize vulnerabilities
                if isinstance(vulnerabilities, list):
                    vuln_count = len(vulnerabilities)
                    total_vulns += vuln_count
                    
                    # Group by severity
                    for cve in vulnerabilities:
                        severity = cve.get('severity', 'None')
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                
                # Display vulnerability information
                if isinstance(vulnerabilities, list) and vulnerabilities:
                    # Format based on severity
                    if any(v.get('severity') in ['Critical', 'High'] for v in vulnerabilities):
                        severity_indicator = "⚠️ HIGH RISK"
                        tag = "critical_header"
                    elif any(v.get('severity') == 'Medium' for v in vulnerabilities):
                        severity_indicator = "⚠ MEDIUM RISK"
                        tag = "medium_header"
                    else:
                        severity_indicator = "ℹ️ LOW RISK"
                        tag = "low_header"
                        
                    self.vas_result.insert(tk.END, f"  {severity_indicator}: {vuln_count} vulnerabilities found\n", tag)
                    
                    # Show top vulnerabilities with details
                    for i, cve in enumerate(sorted(
                        vulnerabilities, 
                        key=lambda x: float(x.get('cvss_score', 0) or 0), 
                        reverse=True
                    )[:3]):
                        # Select tag based on severity
                        if cve.get('severity') in ['Critical', 'High']:
                            score_tag = "high_score"
                        elif cve.get('severity') == 'Medium':
                            score_tag = "medium_score"
                        else:
                            score_tag = "low_score"
                        
                        # CVE ID and score
                        self.vas_result.insert(tk.END, f"    • {cve['cve']} - ", "cve_id")
                        self.vas_result.insert(tk.END, f"Score: {cve['cvss_score']} ", score_tag)
                        self.vas_result.insert(tk.END, f"({cve['severity']})\n", score_tag)
                        
                        # Description with cleaner formatting
                        description = cve.get('description', 'No description available')
                        # Truncate long descriptions for readability
                        if len(description) > 150:
                            description = description[:147] + "..."
                        self.vas_result.insert(tk.END, f"      {description}\n", "description")
                    
                    # Indicate if there are more vulnerabilities
                    if len(vulnerabilities) > 3:
                        self.vas_result.insert(tk.END, f"      ...and {len(vulnerabilities)-3} more CVEs (see detailed report)\n", "more_cves")
                else:
                    self.vas_result.insert(tk.END, "  ✓ No known vulnerabilities for this port/service\n", "secure")
                
                # Add separator between ports for readability
                self.vas_result.insert(tk.END, "\n")
            
            # Create detailed summary section
            elapsed_time = datetime.now() - start_time
            
            self.vas_result.insert(tk.END, "📊 SCAN SUMMARY\n", "summary_header")
            self.vas_result.insert(tk.END, "═" * 70 + "\n\n", "separator")
            
            # Overview stats with visual indicators
            self.vas_result.insert(tk.END, f"Target: {ip}\n", "summary_item")
            self.vas_result.insert(tk.END, f"Scan duration: {elapsed_time.total_seconds():.2f} seconds\n", "summary_item")
            self.vas_result.insert(tk.END, f"Open ports: {len(results)}\n", "summary_item")
            self.vas_result.insert(tk.END, f"Total vulnerabilities: {total_vulns}\n\n", "summary_item")
            
            # Show severity breakdown
            self.vas_result.insert(tk.END, "Vulnerabilities by severity:\n", "severity_header")
            
            # Format each severity level with appropriate styling
            if severity_counts["Critical"] > 0:
                self.vas_result.insert(tk.END, f"  • Critical: {severity_counts['Critical']}\n", "critical_count")
            if severity_counts["High"] > 0:
                self.vas_result.insert(tk.END, f"  • High: {severity_counts['High']}\n", "high_count")
            if severity_counts["Medium"] > 0:
                self.vas_result.insert(tk.END, f"  • Medium: {severity_counts['Medium']}\n", "medium_count")
            if severity_counts["Low"] > 0:
                self.vas_result.insert(tk.END, f"  • Low: {severity_counts['Low']}\n", "low_count")
            if severity_counts["None"] > 0:
                self.vas_result.insert(tk.END, f"  • Unrated: {severity_counts['None']}\n", "none_count")
            
            # Security recommendation based on findings
            self.vas_result.insert(tk.END, "\n📋 RECOMMENDATION\n", "recommendation_header")
            
            if severity_counts["Critical"] > 0 or severity_counts["High"] > 0:
                self.vas_result.insert(tk.END, "Critical or high severity vulnerabilities detected. Immediate remediation is strongly recommended.\n", "critical_recommendation")
            elif severity_counts["Medium"] > 0:
                self.vas_result.insert(tk.END, "Medium severity vulnerabilities detected. Remediation should be planned soon.\n", "medium_recommendation")
            elif total_vulns > 0:
                self.vas_result.insert(tk.END, "Only low severity vulnerabilities detected. Address these issues during routine maintenance.\n", "low_recommendation")
            else:
                self.vas_result.insert(tk.END, "No vulnerabilities detected on open ports. Continue regular security monitoring.\n", "good_recommendation")
            
            # Export reminder
            self.vas_result.insert(tk.END, "\n💡 Tip: Use the 'Export Results' button to save a detailed report\n", "tip")
            
            # Configure text styles for rich formatting
            self._configure_vas_text_styles()
            
            # Update status and enable buttons
            self.vas_scan_btn.configure(state="normal")
            self.vas_download_btn.configure(state="normal" if results else "disabled")
            self.update_status(f"Scan completed - {len(results)} ports and {total_vulns} vulnerabilities found on {ip}")
                
        except Exception as e:
            # Error handling with better formatting
            self.vas_result.config(state="normal")
            self.vas_result.insert(tk.END, "\n❌ SCAN ERROR\n", "error_header")
            self.vas_result.insert(tk.END, "─" * 70 + "\n\n", "separator")
            self.vas_result.insert(tk.END, f"An error occurred during the vulnerability scan:\n", "error")
            self.vas_result.insert(tk.END, f"{str(e)}\n\n", "error_details")
            
            # Provide possible solutions
            self.vas_result.insert(tk.END, "Possible solutions:\n", "solutions_header")
            self.vas_result.insert(tk.END, "• Verify the target IP is correct and online\n", "solution")
            self.vas_result.insert(tk.END, "• Check your internet connection\n", "solution")
            self.vas_result.insert(tk.END, "• Ensure you have permission to scan the target\n", "solution")
            self.vas_result.insert(tk.END, "• Try again with a valid NVD API key\n", "solution")
            
            # Configure error styles
            self._configure_vas_text_styles()
            
            # Re-enable scan button and update status
            self.vas_scan_btn.configure(state="normal")
            self.update_status(f"Scan failed: {str(e)}")
        
        finally:
            # Ensure text area is read-only
            self.vas_result.config(state="disabled")
    
    def _configure_vas_text_styles(self):
        """Configure text styles for vulnerability scanner output"""
        # Headers and sections
        self.vas_result.tag_configure("scan_header", font=("Arial", 14, "bold"), foreground="#4a86e8")
        self.vas_result.tag_configure("section_header", font=("Arial", 12, "bold"), foreground="#4a86e8")
        self.vas_result.tag_configure("summary_header", font=("Arial", 14, "bold"), foreground="#4a86e8")
        self.vas_result.tag_configure("recommendation_header", font=("Arial", 12, "bold"), foreground="#4a86e8")
        self.vas_result.tag_configure("severity_header", font=("Arial", 11, "bold"))
        
        # General information
        self.vas_result.tag_configure("separator", foreground="#888888")
        self.vas_result.tag_configure("timestamp", font=("Arial", 9), foreground="#777777")
        self.vas_result.tag_configure("target_info", font=("Arial", 11, "bold"))
        self.vas_result.tag_configure("api_info", font=("Arial", 10))
        self.vas_result.tag_configure("progress", font=("Arial", 10), foreground="#888888")
        self.vas_result.tag_configure("success", font=("Arial", 10, "bold"), foreground="#339933")
        self.vas_result.tag_configure("info", font=("Arial", 10))
        
        # Port information
        self.vas_result.tag_configure("port_header", font=("Arial", 11, "bold"))
        self.vas_result.tag_configure("banner_info", font=("Arial", 10), foreground="#555555")
        
        # Vulnerability severity indicators
        self.vas_result.tag_configure("critical_header", font=("Arial", 10, "bold"), foreground="#cc0000", background="#ffe6e6")
        self.vas_result.tag_configure("medium_header", font=("Arial", 10, "bold"), foreground="#ff9900", background="#fff6e6")
        self.vas_result.tag_configure("low_header", font=("Arial", 10, "bold"), foreground="#3366cc", background="#e6f0ff")
        
        # CVE details
        self.vas_result.tag_configure("cve_id", font=("Arial", 10, "bold"))
        self.vas_result.tag_configure("high_score", font=("Arial", 10), foreground="#cc0000")
        self.vas_result.tag_configure("medium_score", font=("Arial", 10), foreground="#ff9900")
        self.vas_result.tag_configure("low_score", font=("Arial", 10), foreground="#3366cc")
        self.vas_result.tag_configure("description", font=("Arial", 10))
        self.vas_result.tag_configure("more_cves", font=("Arial", 9, "italic"), foreground="#555555")
        self.vas_result.tag_configure("secure", font=("Arial", 10), foreground="#339933")
        
        # Summary section
        self.vas_result.tag_configure("summary_item", font=("Arial", 11))
        self.vas_result.tag_configure("summary_detail", font=("Arial", 10))
        self.vas_result.tag_configure("critical_count", font=("Arial", 10, "bold"), foreground="#cc0000")
        self.vas_result.tag_configure("high_count", font=("Arial", 10), foreground="#cc0000")
        self.vas_result.tag_configure("medium_count", font=("Arial", 10), foreground="#ff9900")
        self.vas_result.tag_configure("low_count", font=("Arial", 10), foreground="#3366cc")
        self.vas_result.tag_configure("none_count", font=("Arial", 10), foreground="#555555")
        
        # Recommendations
        self.vas_result.tag_configure("critical_recommendation", font=("Arial", 10), foreground="#cc0000")
        self.vas_result.tag_configure("medium_recommendation", font=("Arial", 10), foreground="#ff9900")
        self.vas_result.tag_configure("low_recommendation", font=("Arial", 10), foreground="#3366cc")
        self.vas_result.tag_configure("good_recommendation", font=("Arial", 10), foreground="#339933")
        self.vas_result.tag_configure("tip", font=("Arial", 10, "italic"), foreground="#777777")
        
        # Error states
        self.vas_result.tag_configure("error_header", font=("Arial", 12, "bold"), foreground="#cc0000")
        self.vas_result.tag_configure("error", font=("Arial", 10, "bold"), foreground="#cc0000")
        self.vas_result.tag_configure("error_details", font=("Arial", 10), foreground="#cc0000")
        self.vas_result.tag_configure("solutions_header", font=("Arial", 11, "bold"))
        self.vas_result.tag_configure("solution", font=("Arial", 10))
    
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
        .header h1 {{ color: white; }}
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
            <p>Generated by Cyber-Suite Toolkit | © 2025 </p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
        
    def create_db_viewer_tab(self):
        """Create the database viewer tab for viewing scan results"""
        # Create a scrollable frame for the database tab
        scrollable_frame = ctk.CTkScrollableFrame(self.db_tab)
        scrollable_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Create a master frame to hold all components
        master_frame = ctk.CTkFrame(scrollable_frame)
        master_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        # Main title for the database viewer tab
        title_label = ctk.CTkLabel(master_frame, text="Scan Results Database", 
                                  font=self.HEADING_FONT,
                                  text_color=("black", "#ADD8E6"))
        title_label.pack(pady=(20, 20))
        
        # --- Filtering Section ---
        filter_section = ctk.CTkFrame(master_frame, corner_radius=10)
        filter_section.pack(pady=10, padx=20, fill="x")
        
        # Section header
        filter_header = ctk.CTkLabel(filter_section, text="🔍 Filter Results", 
                                   font=self.SUBHEADING_FONT)
        filter_header.pack(pady=10, padx=15, anchor="w")
        
        # Filter options in a grid for better organization
        filter_frame = ctk.CTkFrame(filter_section, fg_color="transparent")
        filter_frame.pack(fill="x", padx=15, pady=5)
        
        # Source filter
        source_frame = ctk.CTkFrame(filter_frame, fg_color="transparent")
        source_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(source_frame, text="Source:", font=self.NORMAL_FONT).pack(side="left", padx=5)
        
        self.source_var = ctk.StringVar(value="All")
        self.source_combo = ctk.CTkComboBox(
            source_frame, 
            values=["All", "AbuseIPDB", "VirusTotal", "Vulnerability Scan", "Local Scan"], 
            variable=self.source_var,
            width=150
        )
        self.source_combo.pack(side="left", padx=10)
        
        # Risk level filter
        risk_frame = ctk.CTkFrame(filter_frame, fg_color="transparent")
        risk_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(risk_frame, text="Risk Level:", font=self.NORMAL_FONT).pack(side="left", padx=5)
        
        self.risk_var = ctk.StringVar(value="All")
        self.risk_combo = ctk.CTkComboBox(
            risk_frame, 
            values=["All", "HIGH", "MEDIUM", "LOW", "SAFE"], 
            variable=self.risk_var,
            width=150
        )
        self.risk_combo.pack(side="left", padx=10)
        
        # Date range filter (can be expanded in future)
        date_frame = ctk.CTkFrame(filter_frame, fg_color="transparent")
        date_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(date_frame, text="Date Range:", font=self.NORMAL_FONT).pack(side="left", padx=5)
        
        self.date_var = ctk.StringVar(value="All Time")
        self.date_combo = ctk.CTkComboBox(
            date_frame, 
            values=["All Time", "Today", "Last 7 Days", "Last 30 Days"], 
            variable=self.date_var,
            width=150
        )
        self.date_combo.pack(side="left", padx=10)
        
        # Filter and Clear buttons
        button_frame = ctk.CTkFrame(filter_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)
        
        self.apply_filter_btn = ctk.CTkButton(
            button_frame, 
            text="Apply Filter", 
            command=self.apply_filter,
            font=self.BUTTON_FONT,
            height=32
        )
        self.apply_filter_btn.pack(side="left", padx=10)
        
        self.clear_filter_btn = ctk.CTkButton(
            button_frame, 
            text="Clear Filter", 
            command=self.clear_filter,
            font=self.BUTTON_FONT,
            height=32
        )
        self.clear_filter_btn.pack(side="left", padx=10)
        
        # --- Results Section ---
        results_section = ctk.CTkFrame(master_frame, corner_radius=10)
        results_section.pack(pady=15, padx=20, fill="both", expand=True)
        
        # Section header
        results_header = ctk.CTkLabel(results_section, text="📊 Results", 
                                    font=self.SUBHEADING_FONT)
        results_header.pack(pady=10, padx=15, anchor="w")
        
        # Statistics frame
        stats_frame = ctk.CTkFrame(results_section, fg_color="transparent")
        stats_frame.pack(fill="x", padx=15, pady=5)
        
        self.stats_label = ctk.CTkLabel(
            stats_frame, 
            text="Loading statistics...", 
            font=self.NORMAL_FONT
        )
        self.stats_label.pack(pady=5)
        
        # Create a frame for the treeview and its scrollbar
        tree_frame = ctk.CTkFrame(results_section)
        tree_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Create the Treeview with styled ttk
        style = ttk.Style()
        style.configure("Treeview", 
                        background="#333333", 
                        foreground="white", 
                        fieldbackground="#333333", 
                        rowheight=25)
        style.map('Treeview', 
                 background=[('selected', '#1f538d')])
        
        # Scrollbar for the treeview
        tree_scrolly = ttk.Scrollbar(tree_frame)
        tree_scrolly.pack(side="right", fill="y")
        
        tree_scrollx = ttk.Scrollbar(tree_frame, orient="horizontal")
        tree_scrollx.pack(side="bottom", fill="x")
        
        # Create the treeview with appropriate columns
        self.results_tree = ttk.Treeview(
            tree_frame,
            columns=("id", "ip", "source", "risk", "score", "isp", "country", "timestamp"),
            show="headings",
            height=15,
            yscrollcommand=tree_scrolly.set,
            xscrollcommand=tree_scrollx.set
        )
        self.results_tree.pack(fill="both", expand=True)
        
        # Configure the scrollbars
        tree_scrolly.config(command=self.results_tree.yview)
        tree_scrollx.config(command=self.results_tree.xview)
        
        # Define the columns
        self.results_tree.heading("id", text="ID")
        self.results_tree.heading("ip", text="IP Address")
        self.results_tree.heading("source", text="Source")
        self.results_tree.heading("risk", text="Risk Level")
        self.results_tree.heading("score", text="Score")
        self.results_tree.heading("isp", text="ISP")
        self.results_tree.heading("country", text="Country")
        self.results_tree.heading("timestamp", text="Date")
        
        # Configure column widths
        self.results_tree.column("id", width=50, minwidth=50)
        self.results_tree.column("ip", width=150, minwidth=100)
        self.results_tree.column("source", width=100, minwidth=80)
        self.results_tree.column("risk", width=100, minwidth=80)
        self.results_tree.column("score", width=70, minwidth=70)
        self.results_tree.column("isp", width=150, minwidth=100)
        self.results_tree.column("country", width=100, minwidth=80)
        self.results_tree.column("timestamp", width=150, minwidth=120)
        
        # Bind double-click event to show record details
        self.results_tree.bind("<Double-1>", self.show_record_details)
        
        # Action buttons for the results
        action_frame = ctk.CTkFrame(results_section, fg_color="transparent")
        action_frame.pack(fill="x", padx=15, pady=10)
        
        self.export_btn = ctk.CTkButton(
            action_frame, 
            text="Export to CSV", 
            command=self.export_to_csv,
            font=self.BUTTON_FONT,
            height=32
        )
        self.export_btn.pack(side="left", padx=10)
        
        self.delete_btn = ctk.CTkButton(
            action_frame, 
            text="Delete Selected", 
            command=self.delete_selected_record,
            font=self.BUTTON_FONT,
            height=32,
            fg_color=("#E57373", "#B71C1C")  # Red color for delete button
        )
        self.delete_btn.pack(side="left", padx=10)
        
        # Database management buttons
        db_mgmt_frame = ctk.CTkFrame(action_frame, fg_color="transparent")
        db_mgmt_frame.pack(side="right", padx=10)
        
        self.rebuild_db_btn = ctk.CTkButton(
            db_mgmt_frame,
            text="Rebuild DB",
            command=self.rebuild_database,
            font=self.BUTTON_FONT,
            height=32,
            fg_color="#1E90FF",
            hover_color="#0066CC"
        )
        self.rebuild_db_btn.pack(side="left", padx=5)
        
        self.delete_db_btn = ctk.CTkButton(
            db_mgmt_frame,
            text="Delete All Data",
            command=self.delete_database,
            font=self.BUTTON_FONT,
            height=32,
            fg_color="#B22222",
            hover_color="#8B0000"
        )
        self.delete_db_btn.pack(side="left", padx=5)
        
        # Load data initially
        self.load_database_data()
    
    def load_database_data(self):
        """Load data from the database into the treeview"""
        try:
            import sqlite3
            from datetime import datetime, timedelta
            
            # Clear existing data
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            
            # Connect to the database
            conn = sqlite3.connect("scan_results.db")
            cursor = conn.cursor()
            
            # Build query based on filters
            query = "SELECT * FROM scans"
            conditions = []
            params = []
            
            # Source filter
            if hasattr(self, 'source_var') and self.source_var.get() != "All":
                conditions.append("source = ?")
                params.append(self.source_var.get())
                
            # Risk level filter
            if hasattr(self, 'risk_var') and self.risk_var.get() != "All":
                conditions.append("risk_level = ?")
                params.append(self.risk_var.get())
                
            # Date range filter
            if hasattr(self, 'date_var') and self.date_var.get() != "All Time":
                today = datetime.now()
                if self.date_var.get() == "Today":
                    date_threshold = today.strftime("%Y-%m-%d")
                    conditions.append("timestamp >= ?")
                    params.append(date_threshold)
                elif self.date_var.get() == "Last 7 Days":
                    date_threshold = (today - timedelta(days=7)).strftime("%Y-%m-%d")
                    conditions.append("timestamp >= ?")
                    params.append(date_threshold)
                elif self.date_var.get() == "Last 30 Days":
                    date_threshold = (today - timedelta(days=30)).strftime("%Y-%m-%d")
                    conditions.append("timestamp >= ?")
                    params.append(date_threshold)
            
            # Combine conditions if any
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
                
            # Order by timestamp, most recent first
            query += " ORDER BY timestamp DESC"
            
            # Execute the query
            cursor.execute(query, params)
            records = cursor.fetchall()
            
            # Insert data into treeview
            for record in records:
                record_id = record[0]
                item_id = self.results_tree.insert("", "end", values=record)
                self.apply_risk_color(item_id, record[3])  # Apply color based on risk level
            
            # Update statistics
            self.update_statistics()
            
            # Update status
            self.update_status(f"Loaded {len(records)} records from database")
            
            conn.close()
            
        except sqlite3.Error as e:
            self.update_status(f"Database error: {e}")
        except Exception as e:
            self.update_status(f"Error loading data: {e}")
    
    def apply_filter(self, load_only=False):
        """Apply selected filters to the database query"""
        if not load_only:
            self.update_status("Applying filters...")
            
        self.load_database_data()
    
    def clear_filter(self):
        """Reset all filters to default values and reload data"""
        self.source_var.set("All")
        self.risk_var.set("All")
        self.date_var.set("All Time")
        
        self.update_status("Filters cleared")
        self.load_database_data()
    
    def apply_risk_color(self, item_id, risk_level):
        """Apply color to a treeview row based on risk level"""
        if risk_level == "HIGH":
            self.results_tree.tag_configure('high_risk', background='#4d1f1f')
            self.results_tree.item(item_id, tags=('high_risk',))
        elif risk_level == "MEDIUM":
            self.results_tree.tag_configure('medium_risk', background='#4d3a1f')
            self.results_tree.item(item_id, tags=('medium_risk',))
        elif risk_level == "LOW":
            self.results_tree.tag_configure('low_risk', background='#424d1f')
            self.results_tree.item(item_id, tags=('low_risk',))
        else:
            self.results_tree.tag_configure('safe', background='#1f4d20')
            self.results_tree.item(item_id, tags=('safe',))
    
    def update_statistics(self):
        """Update the statistics display with counts by risk level"""
        try:
            import sqlite3
            
            conn = sqlite3.connect("scan_results.db")
            cursor = conn.cursor()
            
            # Get total count
            cursor.execute("SELECT COUNT(*) FROM scans")
            total = cursor.fetchone()[0]
            
            # Get risk level counts
            cursor.execute("SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level")
            risk_counts = cursor.fetchall()
            
            # Create statistics dictionary
            stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
            for risk, count in risk_counts:
                if risk in stats:
                    stats[risk] = count
            
            # Update statistics label
            stats_text = (f"Total: {total} records | "
                          f"High Risk: {stats['HIGH']} | "
                          f"Medium Risk: {stats['MEDIUM']} | "
                          f"Low Risk: {stats['LOW']} | "
                          f"Safe: {stats['SAFE']}")
            
            self.stats_label.configure(text=stats_text)
            
            conn.close()
            
        except sqlite3.Error as e:
            self.update_status(f"Database error: {e}")
        except Exception as e:
            self.update_status(f"Error updating statistics: {e}")
    
    def show_record_details(self, event=None):
        """Show detailed information for the selected record"""
        try:
            # Get the selected item
            selection = self.results_tree.selection()
            if not selection:
                return
                
            # Get the values of the selected item
            item = self.results_tree.item(selection[0])
            values = item['values']
            
            # Create a details window
            details_window = ctk.CTkToplevel(self)
            details_window.title(f"Record Details - {values[1]}")  # IP address
            details_window.geometry("500x400")
            details_window.resizable(True, True)
            details_window.grab_set()  # Make the window modal
            
            # Create a scrollable frame for the details
            scroll_frame = ctk.CTkScrollableFrame(details_window)
            scroll_frame.pack(fill="both", expand=True, padx=15, pady=15)
            
            # Header with IP and risk level
            header_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
            header_frame.pack(fill="x", pady=5)
            
            # Show risk level with appropriate color
            risk_level = values[3]  # "risk" column
            risk_color = "#1f4d20"  # Default green for SAFE
            if risk_level == "HIGH":
                risk_color = "#4d1f1f"  # Dark red
            elif risk_level == "MEDIUM":
                risk_color = "#4d3a1f"  # Orange-brown
            elif risk_level == "LOW":
                risk_color = "#424d1f"  # Yellow-green
                
            ip_label = ctk.CTkLabel(
                header_frame, 
                text=f"IP: {values[1]}",
                font=ctk.CTkFont(size=18, weight="bold")
            )
            ip_label.pack(pady=5)
            
            risk_label = ctk.CTkLabel(
                header_frame,
                text=f"Risk Level: {risk_level}",
                font=ctk.CTkFont(size=16, weight="bold"),
                fg_color=risk_color,
                corner_radius=5,
                padx=10
            )
            risk_label.pack(pady=5)
            
            # Display all record details in a formatted way
            details_frame = ctk.CTkFrame(scroll_frame)
            details_frame.pack(fill="both", expand=True, pady=10)
            
            # Field labels and values
            fields = [
                ("ID", values[0]),
                ("Source", values[2]),
                ("Risk Score", values[4]),
                ("Flagged", "Yes" if values[4] > 0 else "No"),
                ("ISP", values[5]),
                ("Country", values[6]),
                ("Date", values[7])
            ]
            
            for i, (field, value) in enumerate(fields):
                row_frame = ctk.CTkFrame(details_frame, fg_color=("gray85", "gray25"))
                row_frame.pack(fill="x", pady=2)
                
                ctk.CTkLabel(
                    row_frame,
                    text=field,
                    font=ctk.CTkFont(weight="bold"),
                    width=100,
                    anchor="w"
                ).pack(side="left", padx=10, pady=5)
                
                ctk.CTkLabel(
                    row_frame,
                    text=str(value),
                    anchor="w"
                ).pack(side="left", fill="x", expand=True, padx=10, pady=5)
            
            # Close button
            close_btn = ctk.CTkButton(
                details_window,
                text="Close",
                command=details_window.destroy,
                width=100
            )
            close_btn.pack(pady=15)
            
        except Exception as e:
            self.update_status(f"Error displaying details: {e}")
    
    def delete_selected_record(self):
        """Delete the selected record from the database"""
        try:
            import sqlite3
            
            # Get the selected item
            selection = self.results_tree.selection()
            if not selection:
                self.update_status("No record selected for deletion")
                return
                
            # Get the ID of the selected item
            item = self.results_tree.item(selection[0])
            record_id = item['values'][0]  # First column is ID
            
            # Confirm deletion
            confirm = messagebox.askyesno(
                "Confirm Deletion",
                f"Are you sure you want to delete record #{record_id}?",
                parent=self
            )
            
            if not confirm:
                return
                
            # Delete from database
            conn = sqlite3.connect("scan_results.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?", (record_id,))
            conn.commit()
            conn.close()
            
            # Remove from treeview
            self.results_tree.delete(selection[0])
            
            # Update statistics
            self.update_statistics()
            
            # Update status
            self.update_status(f"Record #{record_id} deleted successfully")
            
        except sqlite3.Error as e:
            self.update_status(f"Database error during deletion: {e}")
        except Exception as e:
            self.update_status(f"Error deleting record: {e}")
    
    def export_to_csv(self):
        """Export the current database view to a CSV file"""
        try:
            import csv
            from tkinter import filedialog
            from datetime import datetime
            
            # Ask for file location
            default_filename = f"cyber_suite_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=default_filename,
                title="Export to CSV"
            )
            
            if not file_path:
                return  # User cancelled
                
            # Get all visible items in the treeview
            items = self.results_tree.get_children()
            if not items:
                self.update_status("No data to export")
                return
                
            # Column headers
            headers = ["ID", "IP Address", "Source", "Risk Level", "Score", "ISP", "Country", "Timestamp"]
            
            # Write to CSV
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                
                for item in items:
                    values = self.results_tree.item(item, 'values')
                    writer.writerow(values)
            
            self.update_status(f"Data exported to {file_path}")
            
        except Exception as e:
            self.update_status(f"Error exporting data: {e}")
    
    # Dashboard-related functions removed to simplify the database viewer tab
            
    def perform_vulnerability_scan(self):
        """Scan target IP for vulnerabilities"""
        target_ip = self.vuln_ip_entry.get().strip()
        api_key = self.vuln_api_entry.get().strip()
        
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP address.")
            return
        
        def scan_thread():
            try:
                self.update_status(f"Starting vulnerability scan on {target_ip}...")
                
                # Create the vulnerability scanner
                scanner = vas.VulnerabilityScanner(target_ip, api_key=api_key if api_key else None)
                
                # Perform the scan
                results = scanner.scan()
                
                # Process and save results
                if results:
                    # Get the highest severity for risk level
                    severity_map = {
                        'CRITICAL': 'High',
                        'HIGH': 'High',
                        'MEDIUM': 'Medium',
                        'LOW': 'Low',
                        'NONE': 'Safe'
                    }
                    
                    highest_severity = 'NONE'
                    for vuln in results.get('vulnerabilities', []):
                        if vas.severity_value(vuln.get('severity', 'NONE')) > vas.severity_value(highest_severity):
                            highest_severity = vuln.get('severity', 'NONE')
                    
                    risk_level = severity_map.get(highest_severity, 'Safe')
                    
                    # Save to database
                    db_result = {
                        'ip': target_ip,
                        'source': 'Vulnerability Scan',
                        'score': len(results.get('vulnerabilities', [])),
                        'risk': risk_level,
                        'details': results
                    }
                    ip_scan.save_result(db_result)
                    
                    # Display results in the vulnerability results section
                    if not self.vuln_results_text:
                        self.vuln_results_text = ctk.CTkTextbox(self.vuln_scan_frame, height=200)
                        self.vuln_results_text.pack(fill="x", padx=10, pady=10)
                    
                    self.vuln_results_text.configure(state="normal")
                    self.vuln_results_text.delete("1.0", tk.END)
                    
                    # Format results
                    text = f"Vulnerability Scan Results for {target_ip}\n\n"
                    text += f"Open Ports: {', '.join(map(str, results.get('open_ports', [])))} \n\n"
                    text += f"Found {len(results.get('vulnerabilities', []))} potential vulnerabilities\n\n"
                    
                    for i, vuln in enumerate(results.get('vulnerabilities', []), 1):
                        text += f"{i}. {vuln.get('cve_id', 'Unknown CVE')}: {vuln.get('severity', 'Unknown')} severity\n"
                        text += f"   {vuln.get('description', 'No description available')}\n\n"
                    
                    self.vuln_results_text.insert("1.0", text)
                    self.vuln_results_text.configure(state="disabled")
                    
                    # Refresh the database view
                    self.load_database_data()
                    
                    self.update_status(f"Vulnerability scan completed on {target_ip}. Found {len(results.get('vulnerabilities', []))} vulnerabilities.")
                else:
                    if not self.vuln_results_text:
                        self.vuln_results_text = ctk.CTkTextbox(self.vuln_scan_frame, height=200)
                        self.vuln_results_text.pack(fill="x", padx=10, pady=10)
                    
                    self.vuln_results_text.configure(state="normal")
                    self.vuln_results_text.delete("1.0", tk.END)
                    self.vuln_results_text.insert("1.0", f"No vulnerabilities found on {target_ip}.")
                    self.vuln_results_text.configure(state="disabled")
                    
                    # Save safe result to database
                    db_result = {
                        'ip': target_ip,
                        'source': 'Vulnerability Scan',
                        'score': 0,
                        'risk': 'Safe',
                        'details': {'message': 'No vulnerabilities found'}
                    }
                    ip_scan.save_result(db_result)
                    
                    # Refresh the database view
                    self.load_database_data()
                    
                    self.update_status(f"Vulnerability scan completed on {target_ip}. No vulnerabilities found.")
            
            except Exception as e:
                self.update_status(f"Error during vulnerability scan: {str(e)}")
        
        # Start scan in a separate thread
        threading.Thread(target=scan_thread).start()
        
    def delete_database(self):
        """Delete the entire database after confirmation"""
        # First confirmation
        if not messagebox.askyesno("Confirm Delete", 
                                  "⚠️ WARNING: This will delete ALL scan data in the database. This action cannot be undone.\n\nAre you sure you want to proceed?"):
            return
        
        # Second confirmation with verification
        verify_dialog = ctk.CTkInputDialog(
            text="Type DELETE in all caps to confirm database deletion:",
            title="Verify Database Deletion"
        )
        verification = verify_dialog.get_input()
        
        if verification != "DELETE":
            messagebox.showinfo("Cancelled", "Database deletion cancelled.")
            return
        
        try:
            # Delete the database file
            if os.path.exists('scan_results.db'):
                os.remove('scan_results.db')
                
            # Clear the treeview
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
                
            # Update statistics
            self.update_statistics()
            
            self.update_status("Database deleted successfully.")
            messagebox.showinfo("Success", "Database has been completely deleted.")
            
        except Exception as e:
            self.update_status(f"Error deleting database: {str(e)}")
            messagebox.showerror("Error", f"Failed to delete database: {str(e)}")
    
    def rebuild_database(self):
        """Rebuild the database structure"""
        if not messagebox.askyesno("Confirm Rebuild", 
                                  "This will rebuild the database structure. If the database exists, all data will be lost.\n\nAre you sure you want to proceed?"):
            return
        
        try:
            # Delete existing database if it exists
            if os.path.exists('scan_results.db'):
                os.remove('scan_results.db')
            
            # Initialize a new database
            ip_scan.init_db()
            
            # Clear the treeview
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
                
            # Update status
            self.update_status("Database rebuilt successfully.")
            messagebox.showinfo("Success", "Database structure has been rebuilt.")
            
            # Reload data (which will be empty)
            self.load_database_data()
            
        except Exception as e:
            self.update_status(f"Error rebuilding database: {str(e)}")
            messagebox.showerror("Error", f"Failed to rebuild database: {str(e)}")
    
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
               SUITE
        """
        
        logo_label = ctk.CTkLabel(logo_frame, text=logo_text, font=ctk.CTkFont(family="Courier", size=12))
        logo_label.pack()
        
        # App Info
        info_frame = ctk.CTkFrame(about_scrollable_frame)
        info_frame.pack(pady=10, padx=20, fill="x")
        
        current_year = datetime.now().year
        version_text = "Version: 1.0.0"
        copyright_text = f"© {current_year} All Rights Reserved."
        description = "A comprehensive cybersecurity toolkit for password management, IP address generation, and vulnerability scanning."
        
        ctk.CTkLabel(info_frame, text=version_text, font=ctk.CTkFont(weight="bold")).pack(pady=5)
        ctk.CTkLabel(info_frame, text=copyright_text).pack(pady=2)
        ctk.CTkLabel(info_frame, text=description, wraplength=500).pack(pady=10)
        
        # Features
        features_frame = ctk.CTkFrame(about_scrollable_frame)
        features_frame.pack(pady=10, padx=20, fill="x")
        
        features_text = """
        Key Features:
        • Password Generator & Encryption Tool
        • IP tools
        • Vulnerability Scanner with CVE Database Integration
        """
        
        ctk.CTkLabel(features_frame, text=features_text, justify="left").pack(pady=10)
        
        # Additional Info - VAS API Key
        vas_info_frame = ctk.CTkFrame(about_scrollable_frame)
        vas_info_frame.pack(pady=10, padx=20, fill="x")
        
        vas_info_text = """
        Notes on Vulnerability Scanner:
        
        • The scanner uses the National Vulnerability Database (NVD) API to retrieve vulnerability information
        • You can use the scanner without an API key, but you may experience rate limiting
        • For more accurate results and faster scanning, it's recommended to get a free API key from the NVD website
        • Visit: https://nvd.nist.gov/developers/request-an-api-key
        """
        
        ctk.CTkLabel(vas_info_frame, text="Vulnerability Scanner Information", font=ctk.CTkFont(weight="bold")).pack(pady=(10, 5))
        ctk.CTkLabel(vas_info_frame, text=vas_info_text, justify="left").pack(pady=10)
        
        # Links
        links_frame = ctk.CTkFrame(about_scrollable_frame)
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