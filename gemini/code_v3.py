import os
import sys
import requests
import json
import logging
import traceback
import re
import boto3
from datetime import datetime
from botocore.exceptions import ClientError
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# CONFIGURATION
# =========================================================
AWS_REGION = os.getenv("region_name", "us-east-1")
SECRET_NAME = os.getenv("AWS_SECRET_NAME", "qualys-secret-qs-dev-qualys-script")

QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"
QUALYS_AUTH_UPDATE_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"

# =========================================================
# LOGGING SETUP
# =========================================================
os.makedirs("logs", exist_ok=True)
date_str = datetime.now().strftime("%Y%m%d")
log_filename = f"logs/log_{date_str}.log"

logger = logging.getLogger("GitLab_Qualys_Script")
logger.setLevel(logging.DEBUG)

if logger.hasHandlers():
    logger.handlers.clear()

# File Handler
file_handler = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(file_handler)

# Console Handler (Visible in GitLab)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(console_handler)

logger.info(f"Logging initialized. Log file: {os.path.abspath(log_filename)}")

# =========================================================
# AWS SECRETS
# =========================================================
def get_secret(secret_name, region_name):
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)
    try:
        resp = client.get_secret_value(SecretId=secret_name)
        if "SecretString" in resp:
            return json.loads(resp["SecretString"])
        raise Exception("Binary secret not supported.")
    except ClientError as e:
        logger.error(f"Failed to retrieve secret: {e}")
        raise e

try:
    SECRETS = get_secret(SECRET_NAME, AWS_REGION)
except Exception:
    logger.critical("CRITICAL: Could not load secrets.")
    sys.exit(1)

PALO_IP = SECRETS.get("PALO_IP")
PALO_API_KEY = SECRETS.get("PALO_API_KEY")
LAB_IP = SECRETS.get("LAB_IP")
LAB_API_KEY = SECRETS.get("LAB_API_KEY")
QUALYS_USER = SECRETS.get("QUALYS_USER")
QUALYS_PASS = SECRETS.get("QUALYS_PASS")
QUALYS_GROUP_ID = SECRETS.get("QUALYS_GROUP_ID")
AUTH_RECORD_ID = SECRETS.get("AUTH_RECORD_ID")

if not all([PALO_IP, PALO_API_KEY, LAB_IP, LAB_API_KEY, QUALYS_USER, QUALYS_PASS, QUALYS_GROUP_ID]):
    logger.critical("Missing required secrets.")
    sys.exit(2)

try:
    from panos.panorama import Panorama
    from panos.device import SystemSettings
except ImportError:
    logger.critical("Missing 'pan-os-python' library.")
    sys.exit(1)

# =========================================================
# HELPER FUNCTIONS (Smart IP Logic)
# =========================================================
def is_valid_ip(ip):
    if not ip: return False
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip) is not None

def extract_device_ip(device, device_type="Unknown"):
    """Tries Management IP -> Hostname -> SystemSettings"""
    # 1. Try ip_address attribute
    ip = getattr(device, "ip_address", None)
    if is_valid_ip(ip): return ip
    
    # 2. Try hostname attribute (sometimes it contains the IP)
    hostname = getattr(device, "hostname", None)
    if is_valid_ip(hostname): return hostname
    
    # 3. Try SystemSettings (Deep lookup)
    try:
        ss = device.find("", SystemSettings)
        if ss:
            sys_ip = getattr(ss, "ip_address", None)
            if is_valid_ip(sys_ip): return sys_ip
    except Exception:
        pass
    
    # If all fail
    return None

def stage_start(name):
    logger.info("="*60)
    logger.info(f"[Stage] {name}")
    logger.info("="*60)

def stage_fail(name, err):
    logger.error(f"❌ [Stage: {name}] Failed — {err}")
    logger.debug(traceback.format_exc())

overall_ok = True

# =========================================================
# STAGE 1: Fetch PROD IPs
# =========================================================
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)
prod_ips = set()
try:
    pano = Panorama(PALO_IP, api_key=PALO_API_KEY)
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    logger.info(f"Production Panorama devices found: {len(devices)}")
    
    for dev in devices:
        # Using Smart Extract
        ip = extract_device_ip(dev, "Prod")
        if ip:
            prod_ips.add(ip)
    
    # >>> EXPLICIT PRINTING FOR LOGS <<<
    logger.info(f"✅ Successfully fetched {len(prod_ips)} IPs from Prod:")
    for ip in sorted(prod_ips):
        logger.info(f"   {ip}")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# STAGE 2: Fetch LAB IPs
# =========================================================
stage_name = "Fetch IPs from Lab Palo Alto"
stage_start(stage_name)
lab_ips = set()
try:
    lab_pano = Panorama(LAB_IP, api_key=LAB_API_KEY)
    lab_devices = lab_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    logger.info(f"Lab Panorama devices found: {len(lab_devices)}")
    
    for dev in lab_devices:
        ip = extract_device_ip(dev, "Lab")
        if ip:
            lab_ips.add(ip)

    # >>> EXPLICIT PRINTING FOR LOGS <<<
    logger.info(f"✅ Successfully fetched {len(lab_ips)} IPs from Lab:")
    for ip in sorted(lab_ips):
        logger.info(f"   {ip}")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    logger.error("Stopping execution due to failures in fetching IPs.")
    sys.exit(3)

# =========================================================
# STAGE 3: Combine IPs
# =========================================================
stage_name = "Combine IP Lists"
stage_start(stage_name)
combined_ips = sorted(set(prod_ips) | set(lab_ips))
logger.info(f"Total Unique IPs to Process: {len(combined_ips)}")

if not combined_ips:
    logger.error("No IPs found. Aborting.")
    sys.exit(4)

# =========================================================
# STAGE 4: Update Qualys (With Header Fix)
# =========================================================
qualys_headers = {"X-Requested-With": "python-requests"}

# 4A. Clear
stage_name = "Clear Qualys Asset Group"
stage_start(stage_name)
try:
    clear_data = {"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": ""}
    
    resp = requests.post(
        QUALYS_URL, 
        data=clear_data, 
        auth=(QUALYS_USER, QUALYS_PASS), 
        verify=False, 
        headers=qualys_headers,
        timeout=60
    )
    
    if resp.status_code != 200:
        raise RuntimeError(f"Qualys returned {resp.status_code}: {resp.text}")
    logger.info("✅ Asset group cleared successfully.")
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok: sys.exit(5)

# 4B. Add
stage_name = "Add IPs to Qualys Asset Group"
stage_start(stage_name)
try:
    set_ips_str = ",".join(combined_ips)
    add_data = {"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": set_ips_str}
    
    resp = requests.post(
        QUALYS_URL, 
        data=add_data, 
        auth=(QUALYS_USER, QUALYS_PASS), 
        verify=False, 
        headers=qualys_headers,
        timeout=120
    )

    if resp.status_code != 200:
        raise RuntimeError(f"Qualys returned {resp.status_code}: {resp.text}")
    logger.info(f"✅ Successfully added {len(combined_ips)} IPs to Group {QUALYS_GROUP_ID}.")
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok: sys.exit(5)

# =========================================================
# STAGE 5: Update Auth Record
# =========================================================
if AUTH_RECORD_ID:
    stage_name = f"Update Qualys Auth Record {AUTH_RECORD_ID}"
    stage_start(stage_name)
    try:
        update_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": set_ips_str,
            "echo_request": "1"
        }
        
        resp = requests.post(
            QUALYS_AUTH_UPDATE_URL, 
            data=update_payload, 
            auth=(QUALYS_USER, QUALYS_PASS), 
            verify=False, 
            headers=qualys_headers,
            timeout=120
        )

        if resp.status_code != 200:
            raise RuntimeError(f"Qualys returned {resp.status_code}: {resp.text}")
        
        logger.info(f"✅ Auth record {AUTH_RECORD_ID} updated successfully.")
    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)
else:
    logger.info("Skipping Auth Record update (AUTH_RECORD_ID not set).")

# =========================================================
# FINAL SUMMARY
# =========================================================
logger.info("-" * 60)
if overall_ok:
    logger.info("SCRIPT COMPLETED SUCCESSFULLY")
    print("Script Execution Successfully, please check the log file for details")
    sys.exit(0)
else:
    logger.error("SCRIPT COMPLETED WITH FAILURES")
    print("Script Execution failed, please check the log file for details")
    sys.exit(6)
