import tkinter as tk
from tkinter import ttk
import threading
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "core"))

from packet_capture import get_network_interfaces, start_capture
from threat_detector import analyze_packet
from alert_system import log_threat

class NetGuardDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard — Network Threat Detector")
        self.root.geometry("700x700")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")
        
        self.is_monitoring = False
        self.threat_count = 0
        self.high_count = 0
        self.medium_count = 0
        
        self.build_ui()

    def build_ui(self):
        # Title
        tk.Label(
            self.root,
            text="🛡️ NetGuard — Network Threat Detector",
            font=("Helvetica", 16, "bold"),
            bg="#1e1e2e",
            fg="#89b4fa"
        ).pack(pady=15)

        # Top Control Frame
        control_frame = tk.Frame(self.root, bg="#313244")
        control_frame.pack(fill="x", padx=20, pady=5)

        tk.Label(
            control_frame,
            text="Interface:",
            font=("Helvetica", 10),
            bg="#313244",
            fg="#cdd6f4"
        ).pack(side="left", padx=10, pady=10)

        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(
            control_frame,
            textvariable=self.interface_var,
            width=25,
            state="readonly"
        )
        interfaces = get_network_interfaces()
        self.interface_dropdown["values"] = interfaces
        if interfaces:
            self.interface_dropdown.current(0)
        self.interface_dropdown.pack(side="left", padx=10, pady=10)

        self.start_btn = tk.Button(
            control_frame,
            text="▶ START",
            command=self.toggle_monitoring,
            bg="#a6e3a1",
            fg="#1e1e2e",
            font=("Helvetica", 10, "bold"),
            relief="flat",
            padx=15,
            pady=5,
            cursor="hand2"
        )
        self.start_btn.pack(side="left", padx=10, pady=10)

        self.status_var = tk.StringVar(value="⚪ Idle")
        tk.Label(
            control_frame,
            textvariable=self.status_var,
            font=("Helvetica", 10),
            bg="#313244",
            fg="#cdd6f4"
        ).pack(side="right", padx=15)

        # Threats Frame
        threats_frame = tk.Frame(self.root, bg="#1e1e2e")
        threats_frame.pack(fill="both", expand=True, padx=20, pady=10)

        tk.Label(
            threats_frame,
            text="THREATS DETECTED:",
            font=("Helvetica", 11, "bold"),
            bg="#1e1e2e",
            fg="#cdd6f4"
        ).pack(anchor="w", pady=5)

        self.threat_display = tk.Text(
            threats_frame,
            font=("Courier", 10),
            bg="#181825",
            fg="#cdd6f4",
            relief="flat",
            state="disabled",
            wrap="word"
        )
        self.threat_display.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(threats_frame, command=self.threat_display.yview)
        scrollbar.pack(side="right", fill="y")
        self.threat_display.config(yscrollcommand=scrollbar.set)

        # Stats Bar
        stats_frame = tk.Frame(self.root, bg="#313244")
        stats_frame.pack(fill="x", padx=20, pady=5)

        self.total_var = tk.StringVar(value="Total: 0")
        self.high_var = tk.StringVar(value="🚨 HIGH: 0")
        self.medium_var = tk.StringVar(value="⚠️ MEDIUM: 0")

        tk.Label(
            stats_frame,
            textvariable=self.total_var,
            font=("Helvetica", 10, "bold"),
            bg="#313244",
            fg="#cdd6f4"
        ).pack(side="left", padx=15, pady=8)

        tk.Label(
            stats_frame,
            textvariable=self.high_var,
            font=("Helvetica", 10, "bold"),
            bg="#313244",
            fg="#f38ba8"
        ).pack(side="left", padx=15, pady=8)

        tk.Label(
            stats_frame,
            textvariable=self.medium_var,
            font=("Helvetica", 10, "bold"),
            bg="#313244",
            fg="#fab387"
        ).pack(side="left", padx=15, pady=8)

        # Buttons Frame
        btn_frame = tk.Frame(self.root, bg="#1e1e2e")
        btn_frame.pack(fill="x", padx=20, pady=5)

        tk.Button(
            btn_frame,
            text="🗑️ CLEAR",
            command=self.clear_threats,
            bg="#313244",
            fg="#cdd6f4",
            font=("Helvetica", 10, "bold"),
            relief="flat",
            padx=15,
            pady=5,
            cursor="hand2"
        ).pack(side="left", padx=5)

        tk.Button(
            btn_frame,
            text="📄 EXPORT LOG",
            command=self.export_log,
            bg="#313244",
            fg="#cdd6f4",
            font=("Helvetica", 10, "bold"),
            relief="flat",
            padx=15,
            pady=5,
            cursor="hand2"
        ).pack(side="left", padx=5)

    def toggle_monitoring(self):
        if self.is_monitoring:
            self.is_monitoring = False
            self.start_btn.config(text="▶ START", bg="#a6e3a1")
            self.status_var.set("⚪ Idle")
        else:
            self.is_monitoring = True
            self.start_btn.config(text="⏹ STOP", bg="#f38ba8")
            self.status_var.set("🟢 Monitoring...")
            thread = threading.Thread(
                target=self.start_monitoring,
                daemon=True
            )
            thread.start()

    def start_monitoring(self):
        interface = self.interface_var.get()
        start_capture(interface, self.packet_handler)

    def packet_handler(self, packet):
        threats = analyze_packet(packet)
        for threat in threats:
            log_threat(threat)
            self.root.after(0, self.display_threat, threat)

    def display_threat(self, threat):
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")

        if threat['severity'] == "HIGH":
            prefix = "🚨 HIGH"
            self.high_count += 1
            self.high_var.set(f"🚨 HIGH: {self.high_count}")
        else:
            prefix = "⚠️  MEDIUM"
            self.medium_count += 1
            self.medium_var.set(f"⚠️ MEDIUM: {self.medium_count}")

        self.threat_count += 1
        self.total_var.set(f"Total: {self.threat_count}")

        self.threat_display.config(state="normal")
        self.threat_display.insert("end",
            f"[{timestamp}] {prefix}: {threat['threat']} — {threat['details']}\n")
        self.threat_display.see("end")
        self.threat_display.config(state="disabled")

    def clear_threats(self):
        self.threat_display.config(state="normal")
        self.threat_display.delete("1.0", "end")
        self.threat_display.config(state="disabled")
        self.threat_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.total_var.set("Total: 0")
        self.high_var.set("🚨 HIGH: 0")
        self.medium_var.set("⚠️ MEDIUM: 0")

    def export_log(self):
        import shutil
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_src = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs", "threats.log"
        )
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        export_path = os.path.join(desktop, f"netguard_report_{timestamp}.txt")
        if os.path.exists(log_src):
            shutil.copy(log_src, export_path)
            self.status_var.set("✅ Exported!")
        else:
            self.status_var.set("❌ No log found!")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetGuardDashboard(root)
    root.mainloop()