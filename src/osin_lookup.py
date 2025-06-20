# DNS resolution (get IP from domain)
import socket
# To save output as jSON
import json
# Calling geolocation APIs
import requests
#For IP WHOIS/RDAP lookups
from ipwhois import IPWhois
# For domain WHOIS lookups
import whois
# For generating a map for IP Location
import folium
import os


# Function to generate a map of the IP Location
def create_map(geo_info):
    if not geo_info:
        print("[!] No geolocation data available.")
        return

    lat = geo_info.get("latitude")
    lon = geo_info.get("longitude")
    ip = geo_info.get("ip")
    org = geo_info.get("org")

    if lat is None or lon is None:
        print("[!] Latitude/Longitude missing - skipping map")
        return
    
    # Create the Map
    m = folium.Map(location=[lat, lon], zoom_start=10)
    popup_text = f"IP: {ip}<br>Org: {org}"
    folium.Marker([lat, lon], popup=popup_text).add_to(m)

    # Save the map as an HTML file
    output_path = "../outputs/ip_location_map.html"
    m.save(output_path)
    print("[+] IP Location map has been saved!")

# Function to resolve a domain name into an IP address
def get_ip(domain):
    try:
        return socket.gethostbyname(domain) # Convert domain to IP
    except Exception as e:
        print(f"[!] Error resolving domain: {e}")
        return None

# Function to get WHOIS information on an IP address
def ip_lookup(ip):
    print(f"[+] Running IP WHOIS lookup on {ip}")
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap() # Use RDAP protocol for structured data
        return {
            "ip": ip,
            "asn": results.get("asn"),
            "country": results.get("asn_country_code"),
            "org": results.get("network", {}).get("name"),
            "raw": results
        }
    except Exception as e:
        print(f"[!] IP WHOIS error: {e}")
        return {}
    
# Function to get WHOIS registration data for a domain name
def domain_lookup(domain):
    print(f"[+] Running domain WHOIS lookup on {domain}")
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "whois_raw": str(w.text)[:300]
        }
    except Exception as e:
        print(f"[!] Domain WHOIS error: {e}")
        return {}

# Function to get approximate geolocation of an IP address using a public API
def ip_geolocation(ip):
    print(f"[+] Getting IP geolocation for {ip}")
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json")
        if res.status_code == 200:
            data = res.json()
            loc = data.get("loc", "0,0").split(",")  # 'loc' = "lat,lon"
            lat, lon = map(float, loc)
            return {
                "ip": ip,
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country_name"),
                "latitude": lat,
                "longitude": lon,
                "org": data.get("org")
            }
        else:
            print(f"[!] IPInfo API error: {res.status_code}")
    except Exception as e:
        print(f"[!] Geolocation error: {e}")
    return {}

# Main logic
if __name__ == "__main__":
    target = input("Enter a domain or IP address: ")

    # Determine if input is an IP or domain
    try:
        socket.inet_aton(target) # If this doesn't raise an error, it's a valid IP
        ip = target
    except socket.error:
        ip = get_ip(target) # Otherwise treat it as a domain

    results = {}

    # If we got a valid IP, run IP-based lookups
    if ip:
        results["ip_info"] = ip_lookup(ip)
        results["geo_info"] = ip_geolocation(ip)

        # Create map based on geolocation data
        create_map(results["geo_info"])
    
    # If input contains dots and isn't a plain IP, assume it's a domain
    if "." in target and not target.replace(".", "").isdigit():
        results["domain_info"] = domain_lookup(target)

    # Save results to a JSON file
    os.makedirs("../outputs", exist_ok=True) # Make sure the file exists
    with open("../outputs/lookup_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\n Lookup complete. Results have been saved!")