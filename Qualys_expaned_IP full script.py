import os
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from panos.panorama import Panorama
from panos.device import SystemSettings
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ===============================
# Palo Alto - Production
# ===============================
pano = Panorama(os.getenv("PALO_IP"), "", "", os.getenv("PALO_API_KEY"))
devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)

palo_ips = set()

for device in devices:
    try:
        system_settings = device.find("", SystemSettings)
        ip = system_settings.ip_address
        if ip:
            palo_ips.add(ip)
    except:
        continue

# ===============================
# Palo Alto - Lab
# ===============================
lab_pano = Panorama(os.getenv("LAB_IP"), "", "", os.getenv("LAB_API_KEY"))
lab_devices = lab_pano.refresh_devices(expand_vsys=False, include_device_groups=False)

print(f"[+] Found {len(lab_devices)} devices in Lab Panorama")

for device in lab_devices:
    try:
        device_info = device.refresh_system_info()
        ip = device_info.ip_address
        print("[DEBUG] Lab device IP:", ip)
        if ip:
            palo_ips.add(ip)   # merged into same set
    except Exception as e:
        print("[DEBUG] Error with lab device:", e)
        continue

# ===============================
# Print All Palo Alto IPs
# ===============================
print(f"\n[+] Palo Alto IPs ({len(palo_ips)}):")
for ip in sorted(palo_ips):
    print(ip)

print(f"\n{datetime.now().strftime('%Y-%m-%d')} Report from Panorama(s)")

# ===============================
# Qualys Section
# ===============================

# Qualys login details (from env)
qualys_user = os.getenv("QUALYS_USER")
qualys_pass = os.getenv("QUALYS_PASS")
qualys_group_id = os.getenv("QUALYS_GROUP_ID")

# Qualys API endpoint
qualys_url = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"

# Parameters to fetch Asset Group details
data = {
    "action": "list",
    "ids": qualys_group_id
}

print(f"\n[+] Fetching IPs from Qualys Asset Group {qualys_group_id}...")

try:
    response = requests.post(
        qualys_url,
        data=data,
        auth=(qualys_user, qualys_pass),
        verify=False,
        headers={"X-Requested-With": "python-requests"}
    )

    print(response.status_code)

    if response.status_code != 200:
        print(f"[X] Failed to fetch Qualys asset group: {response.status_code}")
        qualys_ips = []
    else:
        root = ET.fromstring(response.text)
        qualys_ips = [ip.text for ip in root.findall(".//IP")]
        print(f"[+] Found {len(qualys_ips)} IPs in Qualys Asset Group")
        for ip in qualys_ips:
            print(ip)

except Exception as e:
    print(f"[X] Error fetching Qualys IPs: {e}")
    qualys_ips = []

# ===============================
# Stage 3 - Compare Palo Alto vs Qualys
# ===============================
missing_ips = palo_ips - set(qualys_ips)
print(f"\n[!] Missing IPs in Qualys ({len(missing_ips)}):")
if missing_ips:
    for ip in sorted(missing_ips):
        print(ip)
else:
    print("[*] All Palo Alto IPs are present in Qualys!")

# ===============================
# Stage 4 - Full sync: Replace Qualys group IPs with all Panorama IPs
# ===============================
print(f"\n[+] Syncing Panorama IPs into Qualys Asset Group {qualys_group_id} (full replace)...")

# ensure palo_ips is a set (from earlier in your script)
all_palo_ips = sorted(set(palo_ips))

# Print all IPs that will be set in Qualys (as requested)
print(f"[INFO] Total Panorama IPs to push: {len(all_palo_ips)}")
for ip in all_palo_ips:
    print("   ", ip)

# Prepare the comma-separated string for Qualys 'set_ips' (empty string allowed -> clears group)
set_ips_str = ",".join(all_palo_ips)

# Build request payload - use set_ips to replace group contents (removes any other IPs in the group)
edit_data = {
    "action": "edit",
    "id": qualys_group_id,
    "set_ips": set_ips_str
}

try:
    edit_response = requests.post(
        qualys_url,
        data=edit_data,
        auth=(qualys_user, qualys_pass),
        verify=False,
        headers={"X-Requested-With": "python-requests"},
        timeout=60
    )

    # Basic success check
    if edit_response.status_code == 200:
        print(f"[✓] Successfully replaced IPs in Qualys Asset Group {qualys_group_id}.")
        # Print a helpful snippet of the response (optional)
        print(edit_response.text[:1000])
    else:
        print(f"[X] Failed to replace Qualys group IPs. HTTP {edit_response.status_code}")
        print(edit_response.text)

except Exception as e:
    print(f"[X] Error while updating Qualys group: {e}")

