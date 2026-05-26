# 🛡️ NetGuard — Real-Time Network Threat Detector

A powerful Python-based **real-time network security monitoring tool** that detects cyber threats by analyzing live network packets. Built with Scapy, Tkinter, and industry-standard detection techniques.

---

## ✨ Features

- 🚨 **ICMP Flood Detection** — Detects ping flood / DDoS attempts
- 🔍 **Port Scan Detection** — Identifies network reconnaissance
- 🦠 **ARP Spoofing Detection** — Catches Man-in-the-Middle attacks
- 🌐 **DNS Spoofing Detection** — Identifies fake DNS responses
- ⚠️ **Suspicious Port Detection** — Flags known malicious ports (Metasploit, Backdoors, Botnets)
- 📍 **IP Geolocation** — Locates attacking public IPs in real-time
- 🔔 **Desktop Notifications** — Instant popup alerts on threat detection
- 📊 **Real-time GUI Dashboard** — Dark themed live monitoring dashboard
- 🗑️ **Clear Threats** — One click to clear threat display
- 📄 **Export Log** — Save threat report to Desktop

---

## 🛠️ Tech Stack

| Library | Purpose |
|---------|---------|
| `scapy` | Live packet capture and analysis |
| `tkinter` | GUI Dashboard |
| `psutil` | Network interface detection |
| `plyer` | Desktop notifications |
| `requests` | IP Geolocation API |
| `ip-api.com` | Free geolocation service |

---

## 📁 Project Structure

```
netguard/
├── core/
│   ├── __init__.py
│   ├── packet_capture.py    # Network packet sniffing
│   ├── threat_detector.py   # All threat detection logic
│   ├── alert_system.py      # Alerts, logging, notifications
│   └── geo_lookup.py        # IP geolocation lookup
├── gui/
│   ├── __init__.py
│   └── dashboard.py         # Real-time Tkinter dashboard
├── logs/                    # Auto-created threat logs
├── main.py                  # CLI entry point
├── requirements.txt         # Dependencies
└── README.md
```

---

## 🚨 Threats Detected

| Threat | Severity | Detection Logic |
|--------|----------|----------------|
| ICMP Flood | 🔴 HIGH | 20+ ICMP packets in 1 second from same IP |
| ARP Spoofing | 🔴 HIGH | Same IP mapped to different MAC address |
| DNS Spoofing | 🔴 HIGH | Public domain resolving to private IP |
| Port Scan | 🟡 MEDIUM | 10+ unique ports scanned in 2 seconds |
| Suspicious Port | 🟡 MEDIUM | Traffic on known malicious ports (4444, 1337, 31337, etc.) |

---

## ⚙️ Installation & Usage

---

### 🪟 Windows

#### ✅ Prerequisites
- Python 3.8+ installed — [Download here](https://www.python.org/downloads/)
- **Npcap** installed (required for Scapy on Windows) — [Download here](https://npcap.com/#download)
- VS Code or any terminal
- **Run as Administrator** (required for packet capture)

#### Step 1 — Clone the Repository
```bash
git clone https://github.com/Ketan65/netguard.git
cd netguard
```

#### Step 2 — Install Dependencies
```bash
python -m pip install -r requirements.txt
```

#### Step 3 — Run as Administrator

> ⚠️ **Important:** Packet capture requires Administrator privileges on Windows!

Right-click on Terminal / VS Code → **"Run as Administrator"**

#### Step 4 — Launch GUI Dashboard
```bash
python gui/dashboard.py
```

#### Step 5 — OR Launch CLI Version
```bash
python main.py
```

#### Step 6 — Using the Dashboard
1. Select your **Network Interface** from dropdown (e.g., Wi-Fi, Ethernet)
2. Click **▶ START** to begin monitoring
3. Threats will appear in real-time with timestamps
4. Click **⏹ STOP** to stop monitoring
5. Click **🗑️ CLEAR** to clear the display
6. Click **📄 EXPORT LOG** to save report to Desktop

---

### 🐧 Kali Linux / Ubuntu

#### ✅ Prerequisites
- Python 3.8+ (usually pre-installed)
- `sudo` / root access (required for packet capture)
- Tkinter (may need separate install)

#### Step 1 — Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2 — Install Tkinter
```bash
sudo apt install python3-tk -y
```

#### Step 3 — Clone the Repository
```bash
git clone https://github.com/Ketan65/netguard.git
cd netguard
```

#### Step 4 — Install Dependencies
```bash
pip install -r requirements.txt
```

> If you get **externally-managed-environment** error:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Step 5 — Launch GUI Dashboard
```bash
sudo python3 gui/dashboard.py
```

#### Step 6 — OR Launch CLI Version
```bash
sudo python3 main.py
```

#### Step 7 — Using the Dashboard
1. Select your **Network Interface** from dropdown (e.g., eth0, wlan0)
2. Click **▶ START** to begin monitoring
3. Threats appear in real-time with timestamps + IP geolocation
4. Click **⏹ STOP** to stop
5. Click **🗑️ CLEAR** to clear display
6. Click **📄 EXPORT LOG** — saves report to Desktop

---

## 📍 IP Geolocation

When a **public IP** is detected in a threat:
- Country and City are automatically fetched
- ISP information is displayed
- Details are added to the threat log

> Note: Geolocation works only for **public IPs**. Local IPs (192.168.x.x, 127.0.0.1) are skipped automatically.

---

## 📄 Log File

Threats are automatically saved to:
```
netguard/logs/threats.log
```

Format:
```
[2026-05-26 15:07:15] [HIGH] ICMP FLOOD — IP 127.0.0.1 — 80 pings in 1 second
[2026-05-26 15:07:16] [MEDIUM] PORT SCAN — IP 192.168.1.5 — 12 ports scanned in 2 seconds
```

You can also export logs directly to Desktop using the **📄 EXPORT LOG** button.

---

## 🧪 Testing

### Test ICMP Flood:

**Windows:**
```powershell
for ($i=0; $i -lt 50; $i++) { ping 127.0.0.1 -n 1 -w 1 }
```

**Kali Linux:**
```bash
sudo hping3 -1 --flood 127.0.0.1
```

### Test Port Scan:
```bash
nmap -sS 127.0.0.1
```

---

## ⚠️ Legal Disclaimer

> This tool is developed for **educational purposes and authorized security testing only.**
> Do **NOT** use this tool on networks or systems you do not own or have explicit permission to test.
> The developer is **not responsible** for any misuse of this tool.

---

## 👨‍💻 Author

**Ketan Verma**
B.Tech Computer Science (Cyber Security)
GLA University, Mathura, Uttar Pradesh
GitHub: [@Ketan65](https://github.com/Ketan65)
