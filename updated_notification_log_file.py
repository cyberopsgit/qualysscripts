import os
import requests
import xml.etree.ElementTree as ET
import logging
import sys
from datetime import datetime
from panos.panorama import Panorama
from panos.device import SystemSettings
from dotenv import load_dotenv

# ===============================
# Stage Tracking Helpers
# ===============================
def stage_start(stage_name):
    print(f"\n{'='*70}")
    print(f"[Stage] {stage_name} — Started")
    print(f"{'='*70}")

def stage_success(stage_name):
    print(f"✅ [Stage: {stage_name}] Completed Successfully")
    print(f"{'-'*70}")

def stage_fail(stage_name, error):
    print(f"❌ [Stage: {stage_name}] Failed — {error}")
    print(f"{'-'*70}")


# ===== Logging setup (only change) =====
# Create a logfile name like palo_YYYYMMDD.log in the same directory
date_str = datetime.now().strftime("%Y%m%d")
log_filename = f"palo_{date_str}.log"

# Configure logging: both console + file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(log_filename, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

# Redirect all print() and error output to logging automatically
class LoggerWriter:
    def __init__(self, level):
        self.level = level
    def write(self, message):
        if message.strip():
            self.level(message.strip())
    def flush(self):
        pass

sys.stdout = LoggerWriter(logging.info)
sys.stderr = LoggerWriter(logging.error)

print(f"[+] Logging initialized. All output will also be saved to '{log_filename}'")
# ===== End of logging setup =====

# Load environment variables
load_dotenv()

# ===============================
# Palo Alto - Production
# ===============================
stage_start("Production Panorama Fetch")
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
print(f"[+] Found {len(devices)} devices in Prod Panorama")
stage_success("Production Panorama Fetch")

# ===============================
# Palo Alto - Lab (Fixed)
# ===============================
# ✅ Fix 1: Use proper API key authentication
stage_start("Lab Panorama Fetch")
lab_pano = Panorama(os.getenv("LAB_IP"), api_key=os.getenv("LAB_API_KEY"))
lab_devices = lab_pano.refresh_devices(expand_vsys=False, include_device_groups=False)

print(f"[+] Found {len(lab_devices)} devices in Lab Panorama")

# ✅ Fix 2: Fetch IPs using same reliable method as prod
for device in lab_devices:
    try:
        system_settings = device.find("", SystemSettings)
        ip = getattr(system_settings, "ip_address", None)
        if ip:
            print("[DEBUG] Lab device IP:", ip)
            palo_ips.add(ip)
        else:
            print("[DEBUG] Lab device has no IP or SystemSettings missing")
    except Exception as e:
        print("[DEBUG] Error with lab device:", e)
        continue
stage_success("Lab Panorama Fetch")


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
stage_start("Qualys Asset Group Fetch")

qualys_user = os.getenv("QUALYS_USER")
qualys_pass = os.getenv("QUALYS_PASS")
qualys_group_id = os.getenv("QUALYS_GROUP_ID")

qualys_url = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"

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
stage_success("Qualys Asset Group Fetch")

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
stage_start("Qualys Asset Group Sync")
print(f"\n[+] Syncing Panorama IPs into Qualys Asset Group {qualys_group_id} (full replace)...")

all_palo_ips = sorted(set(palo_ips))

print(f"[INFO] Total Panorama IPs to push: {len(all_palo_ips)}")
for ip in all_palo_ips:
    print("   ", ip)

set_ips_str = ",".join(all_palo_ips)

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

    if edit_response.status_code == 200:
        print(f"[✓] Successfully replaced IPs in Qualys Asset Group {qualys_group_id}.")
        print(edit_response.text[:1000])
    else:
        print(f"[X] Failed to replace Qualys group IPs. HTTP {edit_response.status_code}")
        print(edit_response.text)

except Exception as e:
    print(f"[X] Error while updating Qualys group: {e}")
stage_success("Qualys Asset Group Sync")

stage_start("Summary")
print(f"[✓] Total Panorama IPs synced: {len(all_palo_ips)}")
print(f"[✓] Qualys Asset Group ID: {qualys_group_id}")
print(f"[✓] Log file: {log_filename}")
stage_success("Summary")
