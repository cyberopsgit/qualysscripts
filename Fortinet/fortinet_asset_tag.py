import os
import sys
import subprocess

# ---------------------------------------------------------
# Auto Install Required Packages
# ---------------------------------------------------------
required_packages = ["requests", "urllib3", "python-dotenv"]

for package in required_packages:
    try:
        # The import name for python-dotenv is just 'dotenv'
        import_name = "dotenv" if package == "python-dotenv" else package
        __import__(import_name)
    except ImportError:
        print(f"[*] Installing missing package: {package}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )

# ---------------------------------------------------------
# Imports (Safe to run now)
# ---------------------------------------------------------
import requests
import logging
import traceback
import datetime
import urllib3
from dotenv import load_dotenv

# Suppress insecure request warnings for verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load variables from .env file if present
load_dotenv()

# ---------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------
date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"sync_solarwinds_qualys_{date_str}.log"

# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# File Handler (writes everything to the log file)
file_handler = logging.FileHandler(log_filename, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Keep a reference to the original stdout for final messages
ORIGINAL_STDOUT = sys.stdout

def stage_start(name):
    msg = f"\n{'='*70}\n[Stage] {name} ⏳ Started\n{'='*70}"
    print(msg)
    logger.info(f"--- [Stage Started] {name} ---")

def stage_fail(name, err):
    msg = f"❌ [Stage: {name}] Failed 🚨 {err}"
    print(msg)
    print("-" * 70)
    logger.error(msg)
    logger.error(traceback.format_exc())

logger.info(f"Script started. Log file created: {os.path.abspath(log_filename)}")

# ---------------------------------------------------------
# Environment Variables & Configuration
# ---------------------------------------------------------
username = os.getenv("SOLARWINDS_USERNAME")
password = os.getenv("SOLARWINDS_PASSWORD")
solarwinds_url = "https://solarwinds.int.ally.com:17774/SolarWinds/InformationService/v3/Json/Query"

qualys_user = os.getenv("QUALYS_USER")
qualys_pass = os.getenv("QUALYS_PASS")
qualys_group_id = os.getenv("QUALYS_GROUP_ID")
qualys_url = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"

AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")
QUALYS_AUTH_UPDATE_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"
QUALYS_TAG_ID = os.getenv("QUALYS_TAG_ID") 

required = {
    "QUALYS_USER": qualys_user,
    "QUALYS_PASS": qualys_pass,
    "QUALYS_GROUP_ID": qualys_group_id,
    "SOLARWINDS_USERNAME": username,
    "SOLARWINDS_PASSWORD": password
}

missing = [k for k, v in required.items() if not v]

if missing:
    err_msg = f"Missing environment variables: {', '.join(missing)}"
    logger.critical(err_msg)
    print("Script Execution failed, please check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(2)

overall_ok = True
solarwinds_ips = []

# ---------------------------------------------------------
# Stage 1: Fetch IPs from SolarWinds
# ---------------------------------------------------------
stage_name = "Fetch IPs from SolarWinds"
stage_start(stage_name)

payload = {
    "query": "SELECT IPAddress FROM Orion.Nodes WHERE Vendor LIKE '%Fortinet%'"
}

try:
    print("[*] Fetching Fortinet IPs from SolarWinds...")
    response = requests.post(solarwinds_url, json=payload, auth=(username, password), verify=False)
    
    if response.status_code == 200:
        data = response.json()
        raw_ips = [row['IPAddress'] for row in data.get('results', []) if row.get('IPAddress')]
        solarwinds_ips = sorted(list(set(raw_ips))) 
        
        print(f"[✅] Found {len(solarwinds_ips)} Fortinet IPs in SolarWinds.")
        logger.info(f"[Stage: {stage_name}] Completed Successfully with {len(solarwinds_ips)} IPs fetched")
        logger.debug(f"IPs fetched: {solarwinds_ips}")
    else:
        err_msg = f"Failed to fetch SolarWinds data: HTTP {response.status_code}"
        print(f"[X] {err_msg}")
        logger.error(err_msg)
        sys.exit(3)

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)
    sys.exit(3)

# ---------------------------------------------------------
# Stage 2: Clear Qualys Asset Group
# ---------------------------------------------------------
stage_name = "Remove current IP list from Qualys Asset group"
stage_start(stage_name)

try:
    clear_data = {"action": "edit", "id": qualys_group_id, "set_ips": ""}
    clear_resp = requests.post(
        qualys_url,
        data=clear_data,
        auth=(qualys_user, qualys_pass),
        verify=False,
        headers={"X-Requested-With": "python-requests"},
        timeout=60
    )
    
    logger.debug(f"Qualys clear HTTP status: {clear_resp.status_code}")
    if clear_resp.status_code != 200:
        raise RuntimeError(f"Qualys clear failed: HTTP {clear_resp.status_code}")
    
    print("[✅] Successfully cleared existing IPs from Asset Group.")
    logger.info(f"[Stage: {stage_name}] Completed Successfully (cleared existing IPs)")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)
    if not overall_ok:
        sys.exit(5)

# ---------------------------------------------------------
# Stage 3: Add latest IPs to Qualys Asset Group
# ---------------------------------------------------------
stage_name = "Add the latest SolarWinds IPs to Qualys Asset group"
stage_start(stage_name)

try:
    print(f"[*] Syncing {len(solarwinds_ips)} SolarWinds IPs into Qualys Asset Group {qualys_group_id}...")
    set_ips_str = ",".join(solarwinds_ips)
    
    edit_data = {
        "action": "edit",
        "id": qualys_group_id,
        "set_ips": set_ips_str
    }
    
    edit_response = requests.post(
        qualys_url,
        data=edit_data,
        auth=(qualys_user, qualys_pass),
        verify=False,
        headers={"X-Requested-With": "python-requests"},
        timeout=60
    )
    
    if edit_response.status_code == 200:
        print(f"[✅] Successfully Synced/Replaced IPs in Qualys Asset Group {qualys_group_id}.")
        logger.info(f"[Stage: {stage_name}] Completed Successfully")
    else:
        print(f"[X] Failed to replace Qualys group IPs. HTTP {edit_response.status_code}")
        raise RuntimeError(f"Update failed with status {edit_response.status_code}")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# ---------------------------------------------------------
# Stage 4: Replace entire Auth Record IP list
# ---------------------------------------------------------
if AUTH_RECORD_ID and solarwinds_ips:
    stage_name = f"Update Qualys authentication record ID {AUTH_RECORD_ID}"
    stage_start(stage_name)
    
    try:
        update_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": ",".join(solarwinds_ips),
            "echo_request": "1"
        }
        
        update_resp = requests.post(
            QUALYS_AUTH_UPDATE_URL,
            data=update_payload,
            auth=(qualys_user, qualys_pass),
            verify=False,
            headers={"X-Requested-With": "python-requests"},
            timeout=120
        )
        
        logger.debug(f"Auth update response status: {update_resp.status_code}")
        if update_resp.status_code != 200:
            raise RuntimeError(f"Auth record update failed: HTTP {update_resp.status_code}")
            
        print(f"[✅] Successfully updated Auth Record {AUTH_RECORD_ID}.")
        logger.info(f"[Stage: {stage_name}] Completed Successfully (auth record replaced)")

    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)
else:
    msg = "AUTH_RECORD_ID not provided or no IPs found; skipping auth record update."
    print(f"\n[*] {msg}")
    logger.info(msg)

# ---------------------------------------------------------
# Stage 5: Sync IPs to Qualys Asset Tag
# ---------------------------------------------------------
if QUALYS_TAG_ID and solarwinds_ips:
    stage_name = f"Update Qualys Asset Tag ID {QUALYS_TAG_ID}"
    stage_start(stage_name)
    
    try:
        qps_tag_url = f"https://qualysapi.qualys.com/qps/rest/2.0/update/am/tag/{QUALYS_TAG_ID}"
        ips_str = ",".join(solarwinds_ips)
        
        # QPS API requires XML payload to update a static IP tag rule
        xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
        <ServiceRequest>
            <data>
                <Tag>
                    <ruleType>STATIC</ruleType>
                    <ruleText>{ips_str}</ruleText>
                </Tag>
            </data>
        </ServiceRequest>
        """
        
        tag_resp = requests.post(
            qps_tag_url,
            data=xml_payload.encode('utf-8'),
            auth=(qualys_user, qualys_pass),
            verify=False,
            headers={"Content-Type": "text/xml", "Accept": "text/xml", "X-Requested-With": "python-requests"},
            timeout=120
        )
        
        logger.debug(f"Asset Tag update response status: {tag_resp.status_code}")
        
        if tag_resp.status_code == 200:
            print(f"[✅] Successfully replaced IPs in Asset Tag {QUALYS_TAG_ID}.")
            logger.info(f"[Stage: {stage_name}] Completed Successfully (Asset Tag updated)")
        else:
            raise RuntimeError(f"Asset Tag update failed: HTTP {tag_resp.status_code} - {tag_resp.text[:200]}")

    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)
else:
    msg = "QUALYS_TAG_ID not provided or no IPs found; skipping Asset Tag update."
    print(f"\n[*] {msg}")
    logger.info(msg)

# ---------------------------------------------------------
# Final Summary
# ---------------------------------------------------------
print("\n" + "="*70)
logger.info(f"Summary: {len(solarwinds_ips)} total IPs processed.")

if overall_ok:
    logger.info("Script completed successfully.")
    print("Script Execution Successfully, please check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print("Script Execution failed, please check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(7)
