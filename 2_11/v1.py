import os
import sys
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from panos.panorama import Panorama
from panos.device import SystemSettings
import logging
import urllib3
import traceback
import json
import boto3
from botocore.exceptions import ClientError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# AWS Secrets
# =========================================================
AWS_REGION = os.getenv("region_name", "us-east-1")
SECRET_NAME = os.getenv("AWS_SECRET_NAME", "qualys-secret-qs-dev-qualys-script")

session = boto3.session.Session()
client = session.client(service_name="secretsmanager", region_name=AWS_REGION)

def get_secret():
    response = client.get_secret_value(SecretId=SECRET_NAME)
    return json.loads(response["SecretString"])

SECRETS = get_secret()

# =========================================================
# Logging Setup
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

sys.stdout = LoggerWriter(logger.info)
sys.stderr = LoggerWriter(logger.error)

logger.info(f"Logging initialized. Log file: {os.path.abspath(log_filename)}")

# =========================================================
# Stage Helpers
# =========================================================
def stage_start(name):
    logger.info("="*70)
    logger.info("[Stage] %s — Started", name)
    logger.info("="*70)

def stage_fail(name, err):
    logger.error("❌ [Stage: %s] Failed — %s", name, err)
    logger.error(traceback.format_exc())

# =========================================================
# Secrets Values
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
    logger.critical(f"Missing secrets: {', '.join(missing)}")
    sys.exit(2)

overall_ok = True

# =========================================================
# Stage 1 - Fetch from Prod (FIXED HERE)
# =========================================================
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)

prod_ips = set()

try:
    pano = Panorama(PALO_IP, api_key=PALO_API_KEY)
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    logger.info("Production Panorama devices count: %d", len(devices))

    # ✅ FIXED LOGIC — use device.hostname directly
    for dev in devices:
        try:
            ip = getattr(dev, "hostname", None)
            if ip:
                prod_ips.add(ip)
        except Exception as e:
            logger.warning("Could not read prod device hostname: %s", e)

    logger.info("IPs fetched from Prod (%d): %s", len(prod_ips), sorted(prod_ips))

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# Stage 2 - Fetch from Lab (FIXED HERE)
# =========================================================
stage_name = "Fetch IPs from Lab Palo Alto"
stage_start(stage_name)

lab_ips = set()

try:
    lab_pano = Panorama(LAB_IP, api_key=LAB_API_KEY)
    lab_devices = lab_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    logger.info("Lab Panorama devices count: %d", len(lab_devices))

    # ✅ FIXED LOGIC — use device.hostname directly
    for dev in lab_devices:
        try:
            ip = getattr(dev, "hostname", None)
            if ip:
                lab_ips.add(ip)
        except Exception as e:
            logger.warning("Could not read lab device hostname: %s", e)

    logger.info("IPs fetched from Lab (%d): %s", len(lab_ips), sorted(lab_ips))

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    sys.exit(3)

# =========================================================
# Stage 3 - Combine
# =========================================================
stage_name = "Combine both Prod and Lab IP Addresses"
stage_start(stage_name)

combined_ips = sorted(set(prod_ips) | set(lab_ips))
logger.info("Combined unique IP count: %d", len(combined_ips))
logger.info("Combined IPs: %s", combined_ips)

# =========================================================
# Stage 4 - Clear Asset Group
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
        timeout=60
    )

    if clear_resp.status_code != 200:
        raise RuntimeError(f"Qualys clear failed: {clear_resp.status_code}")

    logger.info("Asset group cleared successfully.")

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# Stage 5 - Add IPs
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
        timeout=120
    )

    if add_resp.status_code != 200:
        raise RuntimeError(f"Qualys add failed: {add_resp.status_code}")

    logger.info("Asset group updated successfully with %d IPs.", len(combined_ips))

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# Stage 6 - Auth Update
# =========================================================
if AUTH_RECORD_ID and combined_ips:
    stage_name = f"Update Qualys authentication record ID {AUTH_RECORD_ID}"
    stage_start(stage_name)

    try:
        update_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": set_ips_str
        }

        update_resp = requests.post(
            QUALYS_AUTH_UPDATE_URL,
            data=update_payload,
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            timeout=120
        )

        if update_resp.status_code != 200:
            raise RuntimeError(f"Auth update failed: {update_resp.status_code}")

        logger.info("Auth record updated successfully.")

    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)

# =========================================================
# Final Summary (UNCHANGED AS YOU REQUESTED)
# =========================================================
if overall_ok:
    logger.info("Script completed successfully.")
    print("Script Execution Successfully, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(6)
