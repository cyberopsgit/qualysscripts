import os
import sys
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from panos.panorama import Panorama
from panos.device import SystemSettings
# >>> OLD (COMMENTED): dotenv
# from dotenv import load_dotenv
import logging
import urllib3
import traceback
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# >>> OLD (COMMENTED): load .env file
# =========================================================
# load_dotenv()

# =========================================================
# >>> NEW (AWS SECRETS MANAGER – AWS OFFICIAL SAMPLE)
# =========================================================
import boto3
from botocore.exceptions import ClientError

def get_secret():
    secret_name = "qualys-gs-dev-f-paloalt-92806b-qualys-secret"
    region_name = "us-east-1"
    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise e

    return json.loads(response["SecretString"])

SECRETS = get_secret()

# =========================================================
# >>> CHANGE: logging setup (GitLab workspace only)
# =========================================================
date_str = datetime.now().strftime("%Y%m%d")
os.makedirs("logs", exist_ok=True)
log_filename = f"logs/log_{date_str}.log"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
for h in list(logger.handlers):
    logger.removeHandler(h)

fh = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(fh)

ch = logging.StreamHandler(sys.__stdout__)
ch.setLevel(logging.CRITICAL)
logger.addHandler(ch)

ORIGINAL_STDOUT = sys.__stdout__

class LoggerWriter:
    def __init__(self, level_func):
        self.level_func = level_func
    def write(self, message):
        message = message.rstrip()
        if message:
            self.level_func(message)
    def flush(self):
        pass

sys.stdout = LoggerWriter(logger.debug)
sys.stderr = LoggerWriter(logger.error)

logger.info(f"Logging initialized. Log file: {os.path.abspath(log_filename)}")

# =========================================================
# helper functions (UNCHANGED)
# =========================================================
def stage_start(name):
    print("\n" + "="*70)
    print(f"[Stage] {name} — Started")
    print("="*70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(traceback.format_exc())
    print("-"*70)

# =========================================================
# >>> OLD (COMMENTED): environment variables
# =========================================================
# PALO_IP = os.getenv("PALO_IP")
# PALO_API_KEY = os.getenv("PALO_API_KEY")
# LAB_IP = os.getenv("LAB_IP")
# LAB_API_KEY = os.getenv("LAB_API_KEY")
# QUALYS_USER = os.getenv("QUALYS_USER")
# QUALYS_PASS = os.getenv("QUALYS_PASS")
# QUALYS_GROUP_ID = os.getenv("QUALYS_GROUP_ID")
# AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")

# =========================================================
# >>> NEW: values from AWS Secrets Manager
# =========================================================
PALO_IP = SECRETS.get("PALO_IP")
PALO_API_KEY = SECRETS.get("PALO_API_KEY")
LAB_IP = SECRETS.get("LAB_IP")
LAB_API_KEY = SECRETS.get("LAB_API_KEY")
QUALYS_USER = SECRETS.get("QUALYS_USER")
QUALYS_PASS = SECRETS.get("QUALYS_PASS")
QUALYS_GROUP_ID = SECRETS.get("QUALYS_GROUP_ID")
AUTH_RECORD_ID = SECRETS.get("AUTH_RECORD_ID")

QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"
QUALYS_AUTH_UPDATE_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"

# =========================================================
# validation (UNCHANGED)
# =========================================================
required = {
    "PALO_IP": PALO_IP,
    "PALO_API_KEY": PALO_API_KEY,
    "LAB_IP": LAB_IP,
    "LAB_API_KEY": LAB_API_KEY,
    "QUALYS_USER": QUALYS_USER,
    "QUALYS_PASS": QUALYS_PASS,
    "QUALYS_GROUP_ID": QUALYS_GROUP_ID
}
missing = [k for k, v in required.items() if not v]
if missing:
    logger.critical(f"Missing environment variables: {', '.join(missing)}")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(2)

overall_ok = True

# =========================================================
# Stage 1 - fetch from prod (UNCHANGED)
# =========================================================
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)
prod_ips = set()
try:
    pano = Panorama(PALO_IP, api_key=PALO_API_KEY)
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] Production Panorama devices count: {len(devices)}")
    for dev in devices:
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None)
            if ip:
                prod_ips.add(ip)
        except Exception as e:
            print(f"[WARN] Could not read system settings for a prod device: {e}")
    print(f"[INFO] IPs fetched from Prod ({len(prod_ips)}):")
    for ip in sorted(prod_ips):
        print("   ", ip)
    logger.info("✅ [Stage: %s] Completed Successfully with %d IPs fetched", stage_name, len(prod_ips))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# Stage 2 - fetch from lab (UNCHANGED)
# =========================================================
stage_name = "Fetch IPs from Lab Palo Alto"
stage_start(stage_name)
lab_ips = set()
try:
    lab_pano = Panorama(LAB_IP, api_key=LAB_API_KEY)
    lab_devices = lab_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] Lab Panorama devices count: {len(lab_devices)}")
    for dev in lab_devices:
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None)
            if ip:
                lab_ips.add(ip)
        except Exception as e:
            print(f"[WARN] Could not read system settings for a lab device: {e}")
    print(f"[INFO] IPs fetched from Lab ({len(lab_ips)}):")
    for ip in sorted(lab_ips):
        print("   ", ip)
    logger.info("✅ [Stage: %s] Completed Successfully with %d IPs fetched", stage_name, len(lab_ips))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(3)

# =========================================================
# Stage 3 - combine (UNCHANGED)
# =========================================================
stage_name = "Combine both Prod and Lab IP Addresses"
stage_start(stage_name)
try:
    combined_ips = sorted(set(prod_ips) | set(lab_ips))
    print(f"[INFO] Combined unique IP count: {len(combined_ips)}")
    for ip in combined_ips:
        print("   ", ip)
    logger.info("✅ [Stage: %s] Completed Successfully with combined list of %d IPs", stage_name, len(combined_ips))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(4)

# =========================================================
# Stage 4 - clear asset group (UNCHANGED)
# =========================================================
stage_name = "Remove current IP list from Qualys Asset group"
stage_start(stage_name)
try:
    clear_data = {"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": ""}
    clear_resp = requests.post(
        QUALYS_URL,
        data=clear_data,
        auth=(QUALYS_USER, QUALYS_PASS),
        verify=False,
        headers={"X-Requested-With": "python-requests"},
        timeout=60
    )
    print(f"[DEBUG] Qualys clear HTTP status: {clear_resp.status_code}")
    print(clear_resp.text[:1000])
    if clear_resp.status_code != 200:
        raise RuntimeError(f"Qualys clear failed: HTTP {clear_resp.status_code}")
    logger.info("✅ [Stage: %s] Completed Successfully (cleared existing IPs)", stage_name)
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(5)

# =========================================================
# Stage 5 - add to Qualys Asset Group (UNCHANGED)
# =========================================================
stage_name = "Add the latest Palo Alto IPs to Qualys Asset group"
stage_start(stage_name)
try:
    set_ips_str = ",".join(combined_ips)
    add_data = {"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": set_ips_str}
    add_resp = requests.post(
        QUALYS_URL,
        data=add_data,
        auth=(QUALYS_USER, QUALYS_PASS),
        verify=False,
        headers={"X-Requested-With": "python-requests"},
        timeout=120
    )
    print(f"[DEBUG] Qualys add HTTP status: {add_resp.status_code}")
    print(add_resp.text[:1000])
    if add_resp.status_code != 200:
        raise RuntimeError(f"Qualys add failed: HTTP {add_resp.status_code}")
    logger.info(
        "✅ [Stage: %s — Combined list of %d IPs] Completed Successfully",
        stage_name,
        len(combined_ips)
    )
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(5)

# =========================================================
# Stage 6 - update auth record (UNCHANGED)
# =========================================================
if AUTH_RECORD_ID and combined_ips:
    stage_name = f"Update Qualys authentication record ID {AUTH_RECORD_ID}"
    stage_start(stage_name)
    try:
        update_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": set_ips_str,
            "echo_request": "1"
        }
        update_resp = requests.post(
            QUALYS_AUTH_UPDATE_URL,
            data=update_payload,
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            headers={"X-Requested-With": "python-requests"},
            timeout=120
        )
        logger.debug("Auth update response status: %s", update_resp.status_code)
        logger.debug("Auth update response body (truncated): %s", update_resp.text[:2000])
        if update_resp.status_code != 200:
            raise RuntimeError(f"Auth record update failed: HTTP {update_resp.status_code}")

        logger.info(
            "✅ [Stage: %s — Combined list of %d IPs] Completed Successfully (auth record replaced)",
            stage_name,
            len(combined_ips)
        )

        logger.info(
            "Summary: %d total IPs processed (auth record replaced with %d IPs)",
            len(combined_ips),
            len(combined_ips)
        )

    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)
else:
    logger.info("AUTH_RECORD_ID not provided or no combined IPs; skipping auth record update.")

# =========================================================
# final summary (EXACT – DO NOT CHANGE)
# =========================================================
if overall_ok:
    logger.info("Script completed successfully.")
    print("Script Execution Successfully, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(6)
