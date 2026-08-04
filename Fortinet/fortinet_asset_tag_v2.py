import os
import sys
import subprocess
import csv

# ---------------------------------------------------------
# Auto Install Required Packages
# ---------------------------------------------------------
required_packages = ["requests", "urllib3", "python-dotenv", "openpyxl"]

for package in required_packages:
    try:
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
import openpyxl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# ---------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------
date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"sync_fortinet_qualys_{date_str}.log"

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(log_filename, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

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

# ---------------------------------------------------------
# Files Configuration
# ---------------------------------------------------------
CMDB_EXCEL_FILE = os.getenv("CMDB_EXCEL_FILE", "fortinet_cmdb_ips.xlsx")
TAG_MAPPING_CSV = os.getenv("TAG_MAPPING_CSV", "tag_assignment_inventory.csv")

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
cmdb_ips = []
merged_ips = []
ip_to_tag_mapping = {}  # {IP: TAG_ID}
tag_to_ips_mapping = {}  # {TAG_ID: [IPs]}

# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------

def is_valid_ip(ip):
    """Basic IP validation"""
    parts = str(ip).split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def read_excel_cmdb():
    """Read CMDB IPs from Excel file"""
    try:
        if not os.path.exists(CMDB_EXCEL_FILE):
            print(f"[⚠️] Excel file not found: {CMDB_EXCEL_FILE}")
            logger.warning(f"Excel file not found: {CMDB_EXCEL_FILE}")
            return []
        
        wb = openpyxl.load_workbook(CMDB_EXCEL_FILE)
        ws = wb.active
        
        ips = []
        for idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
            try:
                ip = row[0] if row and row[0] else None
                
                if ip and is_valid_ip(str(ip)):
                    ips.append(str(ip).strip())
            except Exception as e:
                logger.warning(f"Skipped row {idx} in Excel: {e}")
                continue
        
        return ips
    
    except Exception as e:
        print(f"[X] Error reading Excel file: {e}")
        logger.error(f"Error reading Excel: {e}")
        return []

def read_tag_mapping_csv():
    """Read IP to Tag mapping from CSV"""
    try:
        if not os.path.exists(TAG_MAPPING_CSV):
            print(f"[⚠️] Tag mapping CSV not found: {TAG_MAPPING_CSV}")
            logger.warning(f"CSV file not found: {TAG_MAPPING_CSV}")
            return {}
        
        mapping = {}
        with open(TAG_MAPPING_CSV, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get('IP Address', '').strip()
                tag_id = row.get('Qualys Tag ID', '').strip()
                
                if ip and tag_id and is_valid_ip(ip):
                    mapping[ip] = tag_id
                else:
                    if ip:
                        logger.warning(f"Skipped invalid mapping: {ip} → {tag_id}")
        
        return mapping
    
    except Exception as e:
        print(f"[X] Error reading CSV file: {e}")
        logger.error(f"Error reading CSV: {e}")
        return {}

def update_tag_with_ips(tag_id, ips_list):
    """Update a single Qualys tag with IP list"""
    try:
        if not ips_list:
            print(f"[⚠️] No IPs to update for tag {tag_id}")
            return False
        
        ips_str = ",".join(ips_list)
        qps_tag_url = f"https://qualysapi.qualys.com/qps/rest/2.0/update/am/tag/{tag_id}"
        
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
        
        if tag_resp.status_code == 200:
            print(f"[✅] Updated Tag {tag_id} with {len(ips_list)} IPs")
            logger.info(f"Updated tag {tag_id} with {len(ips_list)} IPs: {ips_list}")
            return True
        else:
            print(f"[X] Tag {tag_id} update failed: HTTP {tag_resp.status_code}")
            logger.error(f"Tag {tag_id} update failed: HTTP {tag_resp.status_code} - {tag_resp.text[:200]}")
            return False
    
    except Exception as e:
        print(f"[X] Error updating tag {tag_id}: {e}")
        logger.error(f"Error updating tag {tag_id}: {e}")
        return False

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
        logger.debug(f"SolarWinds IPs: {solarwinds_ips}")
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
# Stage 2: Read CMDB IPs from Excel
# ---------------------------------------------------------
stage_name = "Read CMDB IPs from Excel"
stage_start(stage_name)

try:
    print(f"[*] Reading IPs from Excel: {CMDB_EXCEL_FILE}...")
    cmdb_ips = read_excel_cmdb()
    
    if cmdb_ips:
        print(f"[✅] Found {len(cmdb_ips)} IPs in CMDB Excel.")
        logger.info(f"[Stage: {stage_name}] Read {len(cmdb_ips)} IPs from Excel")
        logger.debug(f"CMDB IPs: {cmdb_ips}")
    else:
        print(f"[⚠️] No IPs found in Excel file")
        logger.warning("No CMDB data loaded")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# ---------------------------------------------------------
# Stage 3: Merge & Deduplicate IPs
# ---------------------------------------------------------
stage_name = "Merge SolarWinds and CMDB IPs"
stage_start(stage_name)

try:
    solarwinds_set = set(solarwinds_ips)
    cmdb_set = set(cmdb_ips)
    
    # Find statistics
    new_ips_from_cmdb = cmdb_set - solarwinds_set
    common_ips = solarwinds_set & cmdb_set
    only_solarwinds = solarwinds_set - cmdb_set
    
    merged_ips = sorted(list(solarwinds_set | cmdb_set))
    
    print(f"[*] SolarWinds IPs: {len(solarwinds_ips)}")
    print(f"[*] CMDB IPs: {len(cmdb_ips)}")
    print(f"[*] Common IPs: {len(common_ips)}")
    print(f"[*] New from CMDB: {len(new_ips_from_cmdb)}")
    print(f"[*] New from SolarWinds: {len(only_solarwinds)}")
    print(f"[✅] Total merged IPs: {len(merged_ips)}")
    
    logger.info(f"[Stage: {stage_name}] Merged: SW={len(solarwinds_ips)}, CMDB={len(cmdb_ips)}, Total={len(merged_ips)}")
    logger.debug(f"Merged IPs: {merged_ips}")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)
    merged_ips = solarwinds_ips

# ---------------------------------------------------------
# Stage 4: Load IP to Tag Mapping from CSV
# ---------------------------------------------------------
stage_name = "Load IP to Tag mapping from CSV"
stage_start(stage_name)

try:
    print(f"[*] Reading tag mapping from: {TAG_MAPPING_CSV}...")
    ip_to_tag_mapping = read_tag_mapping_csv()
    
    if ip_to_tag_mapping:
        print(f"[✅] Loaded {len(ip_to_tag_mapping)} IP-to-Tag mappings")
        logger.info(f"[Stage: {stage_name}] Loaded {len(ip_to_tag_mapping)} mappings")
        logger.debug(f"Mapping: {ip_to_tag_mapping}")
    else:
        print(f"[⚠️] No tag mappings found in CSV")
        logger.warning("No tag mappings loaded from CSV")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# ---------------------------------------------------------
# Stage 5: Build Tag to IPs Mapping
# ---------------------------------------------------------
stage_name = "Build tag to IPs mapping"
stage_start(stage_name)

try:
    tag_to_ips_mapping = {}
    unmapped_ips = []
    
    for ip in merged_ips:
        if ip in ip_to_tag_mapping:
            tag_id = ip_to_tag_mapping[ip]
            if tag_id not in tag_to_ips_mapping:
                tag_to_ips_mapping[tag_id] = []
            tag_to_ips_mapping[tag_id].append(ip)
        else:
            unmapped_ips.append(ip)
    
    print(f"[✅] Created mapping for {len(tag_to_ips_mapping)} tags")
    print(f"[*] Total mapped IPs: {len(merged_ips) - len(unmapped_ips)}")
    print(f"[⚠️] Unmapped IPs: {len(unmapped_ips)}")
    
    if unmapped_ips:
        print(f"    Unmapped IPs: {unmapped_ips}")
        logger.warning(f"Unmapped IPs (not in CSV): {unmapped_ips}")
    
    logger.info(f"[Stage: {stage_name}] Created mapping for {len(tag_to_ips_mapping)} tags")
    logger.debug(f"Tag to IPs mapping: {tag_to_ips_mapping}")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# ---------------------------------------------------------
# Stage 6: Update Qualys Asset Group (All Merged IPs)
# ---------------------------------------------------------
stage_name = "Update Qualys Asset Group with all merged IPs"
stage_start(stage_name)

try:
    # Clear existing
    clear_data = {"action": "edit", "id": qualys_group_id, "set_ips": ""}
    clear_resp = requests.post(
        qualys_url,
        data=clear_data,
        auth=(qualys_user, qualys_pass),
        verify=False,
        headers={"X-Requested-With": "python-requests"},
        timeout=60
    )
    
    if clear_resp.status_code != 200:
        raise RuntimeError(f"Qualys clear failed: HTTP {clear_resp.status_code}")
    
    print("[✅] Cleared existing IPs from Asset Group.")
    
    # Add all merged IPs
    set_ips_str = ",".join(merged_ips)
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
        print(f"[✅] Successfully synced {len(merged_ips)} IPs to Asset Group {qualys_group_id}.")
        logger.info(f"[Stage: {stage_name}] Successfully updated asset group with {len(merged_ips)} IPs")
    else:
        raise RuntimeError(f"Update failed with status {edit_response.status_code}")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# ---------------------------------------------------------
# Stage 7: Update Auth Record (if configured)
# ---------------------------------------------------------
if AUTH_RECORD_ID and merged_ips:
    stage_name = f"Update Qualys authentication record ID {AUTH_RECORD_ID}"
    stage_start(stage_name)
    
    try:
        update_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": ",".join(merged_ips),
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
        
        if update_resp.status_code != 200:
            raise RuntimeError(f"Auth record update failed: HTTP {update_resp.status_code}")
        
        print(f"[✅] Successfully updated Auth Record {AUTH_RECORD_ID}.")
        logger.info(f"[Stage: {stage_name}] Successfully updated auth record")

    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)

# ---------------------------------------------------------
# Stage 8: Update Qualys Tags with Segregated IPs
# ---------------------------------------------------------
if tag_to_ips_mapping:
    stage_name = "Update Qualys Asset Tags with segregated IPs"
    stage_start(stage_name)
    
    try:
        print(f"[*] Updating {len(tag_to_ips_mapping)} asset tags...")
        
        tags_updated = 0
        tags_failed = 0
        
        for tag_id, ips in tag_to_ips_mapping.items():
            print(f"\n[*] Tag {tag_id}: {len(ips)} IPs")
            if update_tag_with_ips(tag_id, ips):
                tags_updated += 1
            else:
                tags_failed += 1
        
        print(f"\n[✅] Successfully updated {tags_updated} tags")
        if tags_failed > 0:
            print(f"[⚠️] Failed to update {tags_failed} tags")
            overall_ok = False
        
        logger.info(f"[Stage: {stage_name}] Updated {tags_updated} tags, {tags_failed} failed")

    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)
else:
    print("\n[*] No tag mappings available; skipping tag updates")
    logger.info("No tag mappings found; tag update stage skipped")

# ---------------------------------------------------------
# Final Summary
# ---------------------------------------------------------
print("\n" + "="*70)
print("[📊] FINAL SUMMARY:")
print(f"    SolarWinds IPs fetched: {len(solarwinds_ips)}")
print(f"    CMDB IPs read: {len(cmdb_ips)}")
print(f"    Total merged IPs: {len(merged_ips)}")
print(f"    Asset Group {qualys_group_id}: Updated with {len(merged_ips)} IPs")
print(f"    Asset Tags updated: {len(tag_to_ips_mapping)}")
if unmapped_ips:
    print(f"    Unmapped IPs: {len(unmapped_ips)}")
print("="*70)

logger.info(f"Summary: SW={len(solarwinds_ips)}, CMDB={len(cmdb_ips)}, Total={len(merged_ips)}, Tags={len(tag_to_ips_mapping)}, Unmapped={len(unmapped_ips) if unmapped_ips else 0}")

if overall_ok:
    logger.info("Script completed successfully.")
    print("\n✅ Script Execution Successfully! Please check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print("\n❌ Script Execution completed with failures. Please check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(7)
