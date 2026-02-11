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

# Qualys Endpoints
QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"
QUALYS_AUTH_UPDATE_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"

# =========================================================
# LOGGING SETUP (GitLab Friendly)
# =========================================================
# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)
date_str = datetime.now().strftime("%Y%m%d")
log_filename = f"logs/log_{date_str}.log"

# Create Logger
logger = logging.getLogger("GitLab_Qualys_Script")
logger.setLevel(logging.DEBUG)

# Reset handlers to avoid duplicates
if logger.hasHandlers():
    logger.handlers.clear()

# 1. File Handler (Detailed logs for artifacts)
file_handler = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(file_handler)

# 2. Console Handler (Visible in GitLab Job Output)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO) # Keep console clean, INFO only
console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(console_handler)

logger.info(f"Logging initialized. Log file: {os.path.abspath(log_filename)}")

# =========================================================
# AWS SECRETS MANAGER
# =========================================================
def get_secret(secret_name, region_name):
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    try:
        logger.info(f"Attempting to fetch secret: {secret_name}")
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        logger.error(f"Failed to retrieve secret '{secret_name}': {e}")
        raise e
    else:
        # Decrypts secret using the associated KMS key.
        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
            return json.loads(secret)
        else:
            logger.error("Secret is binary, expected string.")
            raise Exception("Binary secret not supported in this script.")

# Fetch Secrets
try:
    SECRETS = get_secret(SECRET_NAME, AWS_REGION)
except Exception as e:
    logger.critical("CRITICAL: Could not load secrets. Exiting.")
    sys.exit(1)

# Extract Variables
PALO_IP = SECRETS.get("PALO_IP")
PALO_API_KEY = SECRETS.get("PALO_API_KEY")
LAB_IP = SECRETS.get("LAB_IP")
LAB_API_KEY = SECRETS.get("LAB_API_KEY")
QUALYS_USER = SECRETS.get("QUALYS_USER")
QUALYS_PASS = SECRETS.get("QUALYS_PASS")
QUALYS_GROUP_ID = SECRETS.get("QUALYS_GROUP_ID")
AUTH_RECORD_ID = SECRETS.get("AUTH_RECORD_ID")

# Validate Required Variables
required_vars = {
    "PALO_IP": PALO_IP, "PALO_API_KEY": PALO_API_KEY,
    "LAB_IP": LAB_IP, "LAB_API_KEY": LAB_API_KEY,
    "QUALYS_USER": QUALYS_USER, "QUALYS_PASS": QUALYS_PASS,
    "QUALYS_GROUP_ID": QUALYS_GROUP_ID
}
missing = [k for k, v in required_vars.items() if not v]
if missing:
    logger.critical(f"Missing required secrets: {', '.join(missing)}")
    sys.exit(2)

# =========================================================
# PAN-OS IMPORTS (Delayed to avoid import errors if lib missing)
# =========================================================
try:
    from panos.panorama import Panorama
    from panos.device import SystemSettings
except ImportError:
    logger.critical("Missing library 'pan-os-python'. Please ensure it is in requirements.txt")
    sys.exit(1)

# =========================================================
# HELPER FUNCTIONS
# =========================================================
def is_valid_ip(ip):
    """Simple check to see if string looks like an IPv4 address."""
    if not ip: return False
    # Basic Regex for IPv4
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip) is not None

def extract_device_ip(device, device_type="Unknown"):
    """
    Robust logic to get IP.
    Priority:
    1. device.ip_address (Management IP attribute)
    2. device.hostname (If it looks like an IP)
    3. SystemSettings lookup (Deep API call)
    """
    # 1. Try Attribute: ip_address
    ip = getattr(device, "ip_address", None)
    if is_valid_ip(ip):
        return ip

    # 2. Try Attribute: hostname (Check if it's actually an IP)
    hostname = getattr(device, "hostname", None)
    if is_valid_ip(hostname):
        return hostname
    
    # 3. Try SystemSettings (The "Old Script" Logic)
    try:
        # Note: This requires a live connection to the device context
        ss = device.find("", SystemSettings)
        if ss:
            sys_ip = getattr(ss, "ip_address", None)
            if is_valid_ip(sys_ip):
                return sys_ip
    except Exception:
        # Fail silently here, we log below
        pass
    
    logger.warning(f"Could not resolve IP for device '{hostname}' ({device_type}). Skipped.")
    return None

def stage_start(name):
    logger.info("="*60)
    logger.info(f"[Stage] {name}")
    logger.info("="*60)

def stage_fail(name, err):
    logger.error(f"❌ [Stage: {name}] Failed — {err}")
    logger.debug(traceback.format_exc())

# Global Status Tracker
overall_ok = True

# =========================================================
# STAGE 1: Fetch PROD IPs
# =========================================================
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)
prod_ips = set()

try:
    pano = Panorama(PALO_IP, api_key=PALO_API_KEY)
    # expand_vsys=False ensures we get physical devices/contexts
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    logger.info(f"Production Panorama devices found: {len(devices)}")
    
    for dev in devices:
        ip = extract_device_ip(dev, "Prod")
        if ip:
            prod_ips.add(ip)

    logger.info(f"✅ Successfully fetched {len(prod_ips)} IPs from Prod.")
    logger.debug(f"Prod IPs: {sorted(prod_ips)}")

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

    logger.info(f"✅ Successfully fetched {len(lab_ips)} IPs from Lab.")
    logger.debug(f"Lab IPs: {sorted(lab_ips)}")

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
    logger.error("No IPs found in either Lab or Prod. Aborting to prevent clearing Qualys Group accidentally.")
    sys.exit(4)

# =========================================================
# STAGE 4: Update Qualys Asset Group
# =========================================================
# Note: Qualys API supports replacing IPs directly, no need to clear first usually, 
# but maintaining your "Clear then Add" logic for safety/legacy reasons.

# 4A. Clear
stage_name = "Clear Qualys Asset Group"
stage_start(stage_name)
try:
    clear_data = {"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": ""}
    resp = requests.post(QUALYS_URL, data=clear_data, auth=(QUALYS_USER, QUALYS_PASS), verify=False, timeout=60)
    
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
    resp = requests.post(QUALYS_URL, data=add_data, auth=(QUALYS_USER, QUALYS_PASS), verify=False, timeout=120)

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
        # 'echo_request': '1' is often needed to suppress output, '0' enables it. 
        # Using your parameters.
        update_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": set_ips_str
        }
        resp = requests.post(QUALYS_AUTH_UPDATE_URL, data=update_payload, auth=(QUALYS_USER, QUALYS_PASS), verify=False, timeout=120)

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
    print("Script Execution Successfully, please check the log file for details") # Standard Print for GitLab parser
    sys.exit(0)
else:
    logger.error("SCRIPT COMPLETED WITH FAILURES")
    print("Script Execution failed, please check the log file for details")
    sys.exit(6)
