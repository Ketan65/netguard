import requests

def get_ip_location(ip):
    # Private/Local IPs skip karo
    if (ip.startswith("192.168.") or 
        ip.startswith("10.") or 
        ip.startswith("172.16.") or
        ip.startswith("127.")):
        return None
    
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3
        )
        data = response.json()
        
        if data["status"] == "success":
            return {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
            }
    except:
        pass
    
    return None