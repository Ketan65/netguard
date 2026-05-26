from scapy.all import ARP, IP, ICMP, TCP, DNS, DNSRR, UDP
from collections import defaultdict
import time

# ARP table — IP: MAC mapping store karo
arp_table = {}

# Connection tracking
connection_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)

# Thresholds
PORT_SCAN_THRESHOLD = 10   # 10 ports in 2 seconds
ICMP_FLOOD_THRESHOLD = 20  # 20 pings in 1 second

def detect_arp_spoof(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]
        
        if arp.op == 2:  # ARP reply
            ip = arp.psrc
            mac = arp.hwsrc
            
            if ip in arp_table:
                if arp_table[ip] != mac:
                    return {
                        "threat": "ARP SPOOFING",
                        "severity": "HIGH",
                        "details": f"IP {ip} — MAC changed from {arp_table[ip]} to {mac}"
                    }
            else:
                arp_table[ip] = mac
    
    return None

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        port = packet[TCP].dport
        current_time = time.time()
        
        # Last 2 seconds ki connections track karo
        connection_tracker[ip].append((port, current_time))
        connection_tracker[ip] = [
            (p, t) for p, t in connection_tracker[ip]
            if current_time - t < 2
        ]
        
        # Unique ports count karo
        unique_ports = set(p for p, t in connection_tracker[ip])
        
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            return {
                "threat": "PORT SCAN",
                "severity": "MEDIUM",
                "details": f"IP {ip} — {len(unique_ports)} ports scanned in 2 seconds"
            }
    
    return None

def detect_icmp_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        ip = packet[IP].src
        current_time = time.time()
        
        # Last 1 second ke pings track karo
        icmp_tracker[ip].append(current_time)
        icmp_tracker[ip] = [
            t for t in icmp_tracker[ip]
            if current_time - t < 1
        ]
        
        if len(icmp_tracker[ip]) >= ICMP_FLOOD_THRESHOLD:
            return {
                "threat": "ICMP FLOOD",
                "severity": "HIGH",
                "details": f"IP {ip} — {len(icmp_tracker[ip])} pings in 1 second"
            }
    
    return None

def analyze_packet(packet):
    threats = []
    
    arp_result = detect_arp_spoof(packet)
    if arp_result:
        threats.append(arp_result)
    
    scan_result = detect_port_scan(packet)
    if scan_result:
        threats.append(scan_result)
    
    icmp_result = detect_icmp_flood(packet)
    if icmp_result:
        threats.append(icmp_result)
    
    port_result = detect_suspicious_port(packet)
    if port_result:
        threats.append(port_result)
    
    dns_result = detect_dns_spoof(packet)
    if dns_result:
        threats.append(dns_result)
    
    return threats
    
    

SUSPICIOUS_PORTS = {
    4444: "Metasploit Default",
    1337: "Backdoor",
    31337: "Elite Backdoor",
    9001: "Tor Relay",
    6667: "IRC/Botnet",
    6666: "IRC/Botnet",
    1234: "Suspicious Service",
    5555: "Android Debug Bridge",
    7777: "Suspicious Backdoor",
}

def detect_suspicious_port(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
        ip = packet[IP].src
        
        for port in [dst_port, src_port]:
            if port in SUSPICIOUS_PORTS:
                return {
                    "threat": "SUSPICIOUS PORT",
                    "severity": "MEDIUM",
                    "details": f"IP {ip} — Port {port} ({SUSPICIOUS_PORTS[port]})"
                }
    return None

from scapy.all import ARP, IP, ICMP, TCP, DNS, DNSRR, UDP

def detect_dns_spoof(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSRR):
        dns = packet[DNS]
        
        if dns.qr == 1:  # DNS response hai
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    if rr.type == 1:  # A record (IPv4)
                        ip_addr = rr.rdata
                        domain = rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname
                        
                        # Private IP check
                        if (ip_addr.startswith("192.168.") or 
                            ip_addr.startswith("10.") or 
                            ip_addr.startswith("172.16.")):
                            
                            return {
                                "threat": "DNS SPOOFING",
                                "severity": "HIGH",
                                "details": f"Domain {domain} → Private IP {ip_addr}"
                            }
                except:
                    pass
    return None