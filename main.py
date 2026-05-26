import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "core"))

from packet_capture import get_network_interfaces, start_capture
from threat_detector import analyze_packet
from alert_system import log_threat

def packet_handler(packet):
    threats = analyze_packet(packet)
    for threat in threats:
        log_threat(threat)

def main():
    print("=" * 50)
    print("        NETGUARD — Network Threat Detector")
    print("=" * 50)
    
    # Interfaces dikhao
    interfaces = get_network_interfaces()
    print("\nAvailable Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  {i+1}. {iface}")
    
    # User se interface choose karwao
    choice = int(input("\nInterface number choose karo: ")) - 1
    selected = interfaces[choice]
    
    print(f"\n[*] Starting NetGuard on: {selected}")
    print("[*] Press Ctrl+C to stop\n")
    
    # Capture start karo
    start_capture(selected, packet_handler)

if __name__ == "__main__":
    main()