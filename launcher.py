import customtkinter as ctk
import subprocess
import sys
import os
import signal
import threading
import time
import webbrowser

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("dark-blue")  # Themes: "blue" (standard), "green", "dark-blue"

class OmniSecureLauncher(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("OmniSecure Control Center")
        self.geometry("600x500") # Increased height slightly for better spacing
        self.resizable(False, False)
        
        # Process Handles
        self.backend_process = None
        self.dashboard_process = None

        # --- LAYOUT CONSTRUCTION ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0) # Title
        self.grid_rowconfigure(1, weight=1) # Status Area
        self.grid_rowconfigure(2, weight=0) # Buttons
        self.grid_rowconfigure(3, weight=0) # Footer

        # 1. HEADER TITLE
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="#ffffff")
        self.header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="🛡️ OmniSecure Defense System", 
            font=("Roboto Medium", 24),
            text_color="#3B8ED0" # Cyan Blue
        )
        self.title_label.pack(pady=20)

        # 2. STATUS DISPLAY (The "Pulse")
        self.status_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.status_frame.grid(row=1, column=0)
        
        self.status_label = ctk.CTkLabel(
            self.status_frame, 
            text="SYSTEM STATUS", 
            font=("Roboto", 12, "bold"),
            text_color="gray"
        )
        self.status_label.pack()

        self.status_indicator = ctk.CTkLabel(
            self.status_frame, 
            text="🔴 DISCONNECTED", 
            font=("Roboto Medium", 28),
            text_color="#FF4B4B" # Red
        )
        self.status_indicator.pack(pady=10)

        # 3. CONTROL BUTTONS
        self.button_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.button_frame.grid(row=2, column=0, pady=20)

        # START BUTTON
        self.btn_start = ctk.CTkButton(
            self.button_frame, 
            text="▶  ACTIVATE PROTECTION", 
            font=("Roboto Medium", 16),
            height=50,
            width=280,
            fg_color="#2CC985", # Cyber Green
            hover_color="#229A65",
            command=self.start_system
        )
        self.btn_start.pack(pady=10)

        # DASHBOARD BUTTON (Secondary)
        self.btn_dash = ctk.CTkButton(
            self.button_frame, 
            text="📊 Open Live Dashboard", 
            font=("Roboto", 14),
            height=40,
            width=280,
            fg_color="#3B8ED0", # Blue
            hover_color="#2C6E9F",
            command=self.open_dashboard
        )
        self.btn_dash.pack(pady=10)
        
        # STOP BUTTON
        self.btn_stop = ctk.CTkButton(
            self.button_frame, 
            text="⏹  TERMINATE ENGINE", 
            font=("Roboto", 14),
            height=40,
            width=280,
            fg_color="#C0392B", # Deep Red
            hover_color="#962D22",
            state="disabled",
            command=self.stop_system
        )
        self.btn_stop.pack(pady=10)

        # 4. FOOTER
        self.footer = ctk.CTkLabel(self, text="v1.0.5 | Secure Email Gateway Project", text_color="gray60")
        self.footer.grid(row=3, column=0, pady=10)

    # --- LOGIC ---

    def start_system(self):
        if self.backend_process is None:
            # Update UI
            self.status_indicator.configure(text="🟢 SYSTEM ACTIVE", text_color="#2CC985")
            self.btn_start.configure(state="disabled", fg_color="gray40")
            self.btn_stop.configure(state="normal", fg_color="#C0392B")
            
            # Start Main Backend (The AI Engine)
            # using sys.executable ensures we use the same python interpreter
            try:
                self.backend_process = subprocess.Popen([sys.executable, "main.py"])
                
                # Start Dashboard (Streamlit)
                self.dashboard_process = subprocess.Popen(
                    [sys.executable, "-m", "streamlit", "run", "dashboard.py"],
                    stdout=subprocess.DEVNULL, # Hide Streamlit logs to keep it clean
                    stderr=subprocess.DEVNULL
                )
                print("[*] OmniSecure Started.")
            except Exception as e:
                print(f"[!] Error starting system: {e}")

    def stop_system(self):
        # Update UI
        self.status_indicator.configure(text="🔴 DISCONNECTED", text_color="#FF4B4B")
        self.btn_start.configure(state="normal", fg_color="#2CC985")
        self.btn_stop.configure(state="disabled", fg_color="gray40")

        # Kill Backend
        if self.backend_process:
            self.backend_process.terminate()
            self.backend_process = None
        
        # Kill Dashboard
        if self.dashboard_process:
            self.dashboard_process.terminate()
            self.dashboard_process = None
            
        print("[!] OmniSecure Stopped.")

    def open_dashboard(self):
        # Manually opens the browser just in case
        webbrowser.open("http://localhost:8501")

    def on_closing(self):
        self.stop_system()
        self.destroy()

if __name__ == "__main__":
    app = OmniSecureLauncher()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()