import os
import requests
import logging
import traceback
import sys

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mocking ORIGINAL_STDOUT if not defined in your environment
ORIGINAL_STDOUT = sys.stdout

def stage_start(name):
    print("\n" + "="*70)
    print(f"[Stage] {name} ⏳ Started")
    print("="*70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed 🚨 {err}")
    logger.error(traceback.format_exc())
    print("-" * 70)

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

required = {
    "QUALYS_USER": qualys_user,
    "QUALYS_PASS": qualys_pass,
    "QUALYS_GROUP_ID": qualys_group_id,
    "SOLARWINDS_USERNAME": username,
    "SOLARWINDS_PASSWORD": password
}

missing = [k for k, v in required.items() if not v]

if missing:
    logger.critical(f"Missing environment variables: {', '.join(missing)}")
    print("Script Execution failed, please check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(2)

overall_ok = True

# ---------------------------------------------------------
# Stage 1: Fetch IPs from SolarWinds
# ---------------------------------------------------------
stage_name = "Fetch IPs from SolarWinds"
stage_start(stage_name)

payload = {
    "query": "SELECT IPAddress FROM Orion.Nodes WHERE Vendor LIKE '%Fortinet%'"
}

try:
    print(f"[*] Fetching Fortinet IPs from SolarWinds...")
    response = requests.post(solarwinds_url, json=payload, auth=(username, password), verify=False)
    
    if response.status_code == 200:
        data = response.json()
        solarwinds_ips = [row['IPAddress'] for row in data.get('results', []) if row.get('IPAddress')]
        solarwinds_ips = sorted(list(set(solarwinds_ips))) # Remove duplicates and sort
        
        print(f"[✅] Found {len(solarwinds_ips)} Fortinet IPs in SolarWinds.")
        logger.info(f"[Stage: {stage_name}] Completed Successfully with {len(solarwinds_ips)} IPs fetched")
    else:
        print(f"[X] Failed to fetch SolarWinds data: {response.status_code}")
        sys.exit(3)

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)
    if not overall_ok:
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
    
    print(f"[DEBUG] Qualys clear HTTP status: {clear_resp.status_code}")
    if clear_resp.status_code != 200:
        raise RuntimeError(f"Qualys clear failed: HTTP {clear_resp.status_code}")
    
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
    print(f"Syncing SolarWinds IPs into Qualys Asset Group {qualys_group_id}")
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
        headers={"X-Requested-With": "python-requests"}
    )
    
    if edit_response.status_code == 200:
        print(f"[✅] Successfully Sync/Replaced IPs in Qualys Asset Group {qualys_group_id}.")
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
            
        logger.info(f"[Stage: {stage_name}] Completed Successfully (auth record replaced)")
        logger.info(f"Summary: {len(solarwinds_ips)} total IPs processed")

    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)
else:
    logger.info("AUTH_RECORD_ID not provided or no combined IPs; skipping auth record update.")

# ---------------------------------------------------------
# Final Summary
# ---------------------------------------------------------
if overall_ok:
    logger.info("Script completed successfully.")
    print("Script Execution Successfully, please check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print("Script Execution failed, please check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(7)
