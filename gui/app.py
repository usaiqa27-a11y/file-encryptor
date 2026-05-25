import threading
import time
from pathlib import Path
from typing import Optional
import customtkinter as ctk
from tkinter import filedialog, messagebox
from utils.helpers import validate_password_strength, generate_secure_password, secure_delete, create_backup
from crypto.engine import CryptoEngine

# Theme configuration
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("dark-blue")

class SecureCryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ZeroTrust File Encryptor")
        self.geometry("720x580")  # Extended slightly for optimal clean spacing
        self.resizable(False, False)

        self.selected_file: Optional[Path] = None
        self.failed_attempts = 0
        self.lockout_time = 0.0

        self.init_ui()

    def init_ui(self):
        # ------------------ Header Area ------------------
        self.header_label = ctk.CTkLabel(
            self, text="ZERO-TRUST CRYPTO BLOCK", 
            font=ctk.CTkFont(family="Courier", size=24, weight="bold"), text_color="#1a365d"
        )
        self.header_label.pack(pady=(25, 10))

        # ------------------ Main Container ------------------
        self.main_frame = ctk.CTkFrame(self, corner_radius=12)
        self.main_frame.pack(fill="both", expand=True, padx=30, pady=10)

        # Configure Grid Columns to stretch beautifully
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=2)

        # ------------------ Row 0: Passphrase Entry ------------------
        self.pass_label = ctk.CTkLabel(
            self.main_frame, text="Cryptographic Passphrase:", 
            font=ctk.CTkFont(size=13, weight="bold"), anchor="w"
        )
        self.pass_label.grid(row=0, column=0, padx=(20, 10), pady=(25, 5), sticky="w")

        self.pass_entry = ctk.CTkEntry(self.main_frame, show="*", placeholder_text="Enter secure password...")
        self.pass_entry.grid(row=0, column=1, padx=(10, 20), pady=(25, 5), sticky="ew")
        self.pass_entry.bind("<KeyRelease>", self.check_password_strength)

        # ------------------ Row 1: Show Password Option ------------------
        self.show_pass_var = ctk.StringVar(value="off")
        self.show_pass_cb = ctk.CTkCheckBox(
            self.main_frame, text="Show Plaintext Passphrase", variable=self.show_pass_var, 
            onvalue="on", offvalue="off", command=self.toggle_password_visibility, text_color="#4a5568"
        )
        self.show_pass_cb.grid(row=1, column=1, padx=(10, 20), pady=(2, 5), sticky="w")

        # ------------------ Row 2: Password Strength Meter ------------------
        self.strength_label = ctk.CTkLabel(
            self.main_frame, text="Strength: Unknown", 
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#718096"
        )
        self.strength_label.grid(row=2, column=1, padx=(10, 20), pady=(2, 15), sticky="w")

        # ------------------ Row 3: Utility Password Generator ------------------
        self.gen_btn = ctk.CTkButton(
            self.main_frame, text="Generate Secure Key", command=self.generate_key_util, 
            fg_color="#4b5563", hover_color="#374151"
        )
        self.gen_btn.grid(row=3, column=0, padx=(20, 10), pady=10, sticky="ew")

        # Separator line placeholder feel or matching option space
        self.dummy_label = ctk.CTkLabel(self.main_frame, text="← Use generated or custom key", text_color="#a0aec0", font=ctk.CTkFont(size=11, slant="italic"))
        self.dummy_label.grid(row=3, column=1, padx=(10, 20), pady=10, sticky="w")

        # ------------------ Row 4: File Selector (Shifted Down!) ------------------
        self.file_btn = ctk.CTkButton(
            self.main_frame, text="SELECT TARGET FILE", command=self.select_file, 
            fg_color="#8e080b", hover_color="#720707", font=ctk.CTkFont(weight="bold")
        )
        self.file_btn.grid(row=4, column=0, padx=(20, 10), pady=(20, 10), sticky="ew")

        self.file_label = ctk.CTkLabel(
            self.main_frame, text="No active file selected", 
            text_color="#4a5568", anchor="w", font=ctk.CTkFont(slant="italic")
        )
        self.file_label.grid(row=4, column=1, padx=(10, 20), pady=(20, 10), sticky="ew")

        # ------------------ Row 5: Secure Shred Option ------------------
        self.shred_var = ctk.StringVar(value="off")
        self.shred_cb = ctk.CTkCheckBox(
            self.main_frame, text="Secure Shred File Post-Execution", 
            variable=self.shred_var, onvalue="on", offvalue="off", text_color="#dc2626"
        )
        self.shred_cb.grid(row=5, column=1, padx=(10, 20), pady=(5, 15), sticky="w")

        # ------------------ Row 6: Action Buttons (Encrypt/Decrypt) ------------------
        self.action_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.action_frame.grid(row=6, column=0, columnspan=2, padx=20, pady=(20, 15), sticky="nsew")
        
        self.action_frame.grid_columnconfigure(0, weight=1)
        self.action_frame.grid_columnconfigure(1, weight=1)

        self.encrypt_btn = ctk.CTkButton(
            self.action_frame, text="LOCK DATA ASSET", command=self.start_encrypt, 
            fg_color="#b91c1c", hover_color="#991b1b", height=40, font=ctk.CTkFont(size=14, weight="bold")
        )
        self.encrypt_btn.grid(row=0, column=0, padx=(0, 15), sticky="ew")

        self.decrypt_btn = ctk.CTkButton(
            self.action_frame, text="UNLOCK DATA ASSET", command=self.start_decrypt, 
            fg_color="#15803d", hover_color="#166534", height=40, font=ctk.CTkFont(size=14, weight="bold")
        )
        self.decrypt_btn.grid(row=0, column=1, padx=(15, 0), sticky="ew")

        # ------------------ Progress Bar ------------------
        self.progress_bar = ctk.CTkProgressBar(self, width=660)
        self.progress_bar.pack(pady=(15, 5), padx=30)
        self.progress_bar.set(0)

        # ------------------ Footer Status Strip ------------------
        self.status_label = ctk.CTkLabel(
            self, text="SYSTEM STATUS: IDLE / SECURE", 
            font=ctk.CTkFont(family="Courier", size=11, weight="bold"), text_color="#15803d"
        )
        self.status_label.pack(side="bottom", pady=15)

    # ================== Functionalities & Event Handlers ==================

    def select_file(self):
        file_selected = filedialog.askopenfilename()
        if file_selected:
            self.selected_file = Path(file_selected)
            display_name = self.selected_file.name if len(self.selected_file.name) < 40 else f"...{self.selected_file.name[-37:]}"
            self.file_label.configure(
                text=f"{display_name} ({self.selected_file.stat().st_size / 1024:.2f} KB)", 
                text_color="#1a202c"
            )
            self.update_status(f"Target selected: {self.selected_file.name}")

    def toggle_password_visibility(self):
        if self.show_pass_var.get() == "on":
            self.pass_entry.configure(show="")
        else:
            self.pass_entry.configure(show="*")

    def check_password_strength(self, event=None):
        pwd = self.pass_entry.get()
        if not pwd:
            self.strength_label.configure(text="Strength: Empty", text_color="#718096")
            return
        is_strong, msg = validate_password_strength(pwd)
        if is_strong:
            self.strength_label.configure(text="Strength: STABLE (Secure)", text_color="#16a34a")
        else:
            self.strength_label.configure(text=f"Weak: {msg}", text_color="#dc2626")

    def generate_key_util(self):
        generated = generate_secure_password()
        self.pass_entry.delete(0, 'end')
        self.pass_entry.insert(0, generated)
        self.show_pass_var.set("on")
        self.pass_entry.configure(show="")
        self.check_password_strength()
        messagebox.showinfo("Generated Cipher Key", f"Secure Key Created:\n\n{generated}\n\nKey copied directly to input box.")

    def update_status(self, text: str, color: str = "#1e3a8a"):
        self.status_label.configure(text=f"SYSTEM STATUS: {text.upper()}", text_color=color)

    def enforce_rate_limiting(self) -> bool:
        if time.time() < self.lockout_time:
            remaining = int(self.lockout_time - time.time())
            messagebox.showerror("Brute-Force Lockout", f"Security restriction in progress. Re-try access in {remaining} seconds.")
            return False
        return True

    def handle_failure_count(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 3:
            delay = 30 * (self.failed_attempts - 2)
            self.lockout_time = time.time() + delay
            self.update_status(f"ACCESS LOCKED OUT FOR {delay} SECONDS", "#dc2626")
            messagebox.showerror("Security Warning", f"Multiple authentication errors logged. Intercept delay applied: {delay}s.")

    def run_crypto_thread(self, target_func, success_message, is_decryption=False):
        self.progress_bar.set(0)
        
        def wrapper():
            backup_file = None
            try:
                if not is_decryption and self.selected_file:
                    backup_file = create_backup(self.selected_file)

                result_path = target_func()
                
                if self.shred_var.get() == "on" and self.selected_file:
                    secure_delete(self.selected_file)
                    self.selected_file = None
                    self.file_label.configure(text="No active file selected", text_color="#9ca3af")

                if backup_file and backup_file.exists():
                    backup_file.unlink()

                self.failed_attempts = 0 
                self.progress_bar.set(1.0)
                self.update_status("Task completed successfully.", "#16a34a")
                messagebox.showinfo("Operation Success", f"{success_message}\nSaved as: {result_path.name}")
            
            except Exception as e:
                if backup_file and backup_file.exists() and self.selected_file:
                    if not self.selected_file.exists():
                        shutil.copy2(backup_file, self.selected_file)
                    backup_file.unlink()

                self.progress_bar.set(0)
                self.update_status("Operation Interrupted / Failed", "#dc2626")
                if is_decryption:
                    self.handle_failure_count()
                messagebox.showerror("Execution Fault Exception", str(e))
            finally:
                self.toggle_ui_state("normal")

        self.toggle_ui_state("disabled")
        threading.Thread(target=wrapper, daemon=True).start()

    def toggle_ui_state(self, state: str):
        self.encrypt_btn.configure(state=state)
        self.decrypt_btn.configure(state=state)
        self.file_btn.configure(state=state)
        self.gen_btn.configure(state=state)

    def start_encrypt(self):
        if not self.selected_file:
            return messagebox.showerror("Error", "No target file selected.")
        password = self.pass_entry.get()
        is_valid, msg = validate_password_strength(password)
        if not is_valid:
            return messagebox.showerror("Security Policy Violation", f"Passphrase does not satisfy compliance standards:\n\n{msg}")
        if not self.enforce_rate_limiting():
            return

        self.update_status("Running Layer 256-Bit GCM Pipeline Encryption...")
        self.run_crypto_thread(
            target_func=lambda: CryptoEngine.encrypt_file(self.selected_file, password, self.progress_bar.set),
            success_message="File targeted encryption finalized successfully."
        )

    def start_decrypt(self):
        if not self.selected_file:
            return messagebox.showerror("Error", "No valid asset file specified.")
        password = self.pass_entry.get()
        if not password:
            return messagebox.showerror("Authentication Error", "Passphrase missing from verification container.")
        if not self.enforce_rate_limiting():
            return

        self.update_status("Verifying Signatures and Decrypting...", "#b45309")
        self.run_crypto_thread(
            target_func=lambda: CryptoEngine.decrypt_file(self.selected_file, password, self.progress_bar.set),
            success_message="Authentication success. Output document initialized.",
            is_decryption=True
        )