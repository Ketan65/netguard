from scapy.all import sniff, get_if_list
import psutil

def get_network_interfaces():
    interfaces = []
    
    stats = psutil.net_if_stats()
    
    for iface, stat in stats.items():
        if stat.isup:
            interfaces.append(iface)
    
    return interfaces

def start_capture(interface, packet_handler, count=0):
    print(f"[*] Capturing on: {interface}")
    sniff(
        iface=interface,
        prn=packet_handler,
        count=count,
        store=False
    )