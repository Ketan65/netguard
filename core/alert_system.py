import os
import re
import time
from datetime import datetime
from plyer import notification
from geo_lookup import get_ip_location

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "threats.log")

def log_threat(threat):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_entry = f"[{timestamp}] [{threat['severity']}] {threat['threat']} — {threat['details']}\n"
    
    if threat['severity'] == "HIGH":
        print(f"\n🚨 HIGH ALERT: {threat['threat']}")
    elif threat['severity'] == "MEDIUM":
        print(f"\n⚠️  MEDIUM: {threat['threat']}")
    else:
        print(f"\nℹ️  LOW: {threat['threat']}")
    
    print(f"   Details: {threat['details']}")
    print(f"   Time: {timestamp}")
    
    # IP Geolocation
    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', threat['details'])
    if ip_match:
        ip = ip_match.group()
        location = get_ip_location(ip)
        if location:
            print(f"   Location: {location['city']}, {location['country']}")
            print(f"   ISP: {location['isp']}")
            threat['details'] += f" | {location['city']}, {location['country']}"
    
    # Desktop notification
    try:
        notification.notify(
            title=f"🚨 NetGuard — {threat['severity']} ALERT",
            message=f"{threat['threat']}\n{threat['details']}",
            app_name="NetGuard",
            timeout=5
        )
    except:
        pass
    
    # Log file mein save
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)