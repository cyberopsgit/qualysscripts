import os
import sys
import json
import logging
import traceback
from datetime import datetime

import boto3
import requests
import urllib3
from panos.panorama import Panorama
from panos.device import SystemSettings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# LOGGING SETUP (UNCHANGED SOUL)
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
fh.setFormatter(
    logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
)
logger.addHandler(fh)

ch = logging.StreamHandler(sys.__stdout__)
ch.setLevel(logging.INFO)
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

sys.stdout = LoggerWriter(logger.info)
sys.stderr = LoggerWriter(logger.error)

logger.info(f"Logging initialized. Log file: {os.path.abspath(log_filename)}")

# =========================================================
# STAGE HELPERS (UNCHANGED)
# =========================================================
def stage_start(name):
    print("\n" + "=" * 70)
    print(f"[Stage] {name} — Started")
    print("=" * 70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(traceback.format_exc())
    print("-" * 70)

# =========================================================
# AWS SECRETS
# =========================================================
AWS_REGION = "us-east-1"
SECRET_NAME = "qualys-secret-qs-dev-qualys-script"

def get_secret():
    client = boto3.client("secretsmanager", region_name=AWS_REGION)
    response = client.get_secret_value(SecretId=SECRET_NAME)
    return json.loads(response["SecretString"])

SECRETS = get_secret()

# =========================================================
# VARIABLES
# =========================================================
PALO_IP = SECRETS.get("PALO_IP")
PALO_API_KEY = SECRETS.get("PALO_API_KEY")
LAB_IP = SECRETS.get("LAB_IP")
LAB_API_KEY = SECRETS.get("LAB_API_KEY")

QUALYS_USER = SECRETS.get("QUALYS_USER")
QUALYS_PASS = SECRETS.get("QUALYS_PASS")
QUALYS_GROUP_ID = SECRETS.get("QUALYS_GROUP_ID")
AUTH_RECORD_ID = SECRETS.get("AUTH_RECORD_ID")

QUALYS_GROUP_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"
QUALYS_AUTH_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"

required = {
    "PALO_IP": PALO_IP,
    "PALO_API_KEY": PALO_API_KEY,
    "LAB_IP": LAB_IP,
    "LAB_API_KEY": LAB_API_KEY,
    "QUALYS_USER": QUALYS_USER,
    "QUALYS_PASS": QUALYS_PASS,
    "QUALYS_GROUP_ID": QUALYS_GROUP_ID,
}

missing = [k for k, v in required.items() if not v]
if missing:
    logger.critical(f"Missing required secrets: {', '.join(missing)}")
    sys.exit(2)

overall_ok = True

# =========================================================
# STAGE 1 – FETCH PROD IPS
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
            hostname = getattr(dev, "hostname", None)
            if not hostname:
                continue
            ss = dev.add(SystemSettings(hostname=hostname))
            ss.refresh()
            ip = getattr(ss, "ip_address", None)
            if ip:
                prod_ips.add(ip)
        except Exception as e:
            print(f"[WARN] Could not read system settings: {e}")

    print(f"[INFO] IPs fetched from Prod ({len(prod_ips)}):")
    for ip in sorted(prod_ips):
        print("   ", ip)

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# STAGE 2 – FETCH LAB IPS
# =========================================================
stage_name = "Fetch IPs from Lab Palo Alto"
stage_start(stage_name)

lab_ips = set()
try:
    pano = Panorama(LAB_IP, api_key=LAB_API_KEY)
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] Lab Panorama devices count: {len(devices)}")

    for dev in devices:
        try:
            hostname = getattr(dev, "hostname", None)
            if not hostname:
                continue
            ss = dev.add(SystemSettings(hostname=hostname))
            ss.refresh()
            ip = getattr(ss, "ip_address", None)
            if ip:
                lab_ips.add(ip)
        except Exception as e:
            print(f"[WARN] Could not read system settings: {e}")

    print(f"[INFO] IPs fetched from Lab ({len(lab_ips)}):")
    for ip in sorted(lab_ips):
        print("   ", ip)

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# STAGE 3 – COMBINE IPS
# =========================================================
stage_name = "Combine Prod and Lab IPs"
stage_start(stage_name)

combined_ips = sorted(set(prod_ips) | set(lab_ips))
print(f"[INFO] Combined unique IP count: {len(combined_ips)}")
for ip in combined_ips:
    print("   ", ip)

if not combined_ips:
    overall_ok = False
    print("[ERROR] Combined IP list is empty, skipping Qualys stages")

# =========================================================
# STAGE 4 – CLEAR QUALYS ASSET GROUP
# =========================================================
if overall_ok:
    stage_name = "Remove current IP list from Qualys Asset group"
    stage_start(stage_name)
    try:
        requests.post(
            QUALYS_GROUP_URL,
            auth=(QUALYS_USER, QUALYS_PASS),
            data={
                "action": "edit",
                "id": QUALYS_GROUP_ID,
                "remove_ips": "ALL",
            },
            timeout=60,
            verify=False,
        )
        print("[INFO] Qualys asset group cleared")
    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)

# =========================================================
# STAGE 5 – ADD IPS TO QUALYS ASSET GROUP
# =========================================================
if overall_ok:
    stage_name = "Add latest IPs to Qualys Asset group"
    stage_start(stage_name)
    try:
        requests.post(
            QUALYS_GROUP_URL,
            auth=(QUALYS_USER, QUALYS_PASS),
            data={
                "action": "edit",
                "id": QUALYS_GROUP_ID,
                "add_ips": ",".join(combined_ips),
            },
            timeout=60,
            verify=False,
        )
        print("[INFO] Qualys asset group updated")
    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)

# =========================================================
# STAGE 6 – UPDATE AUTH RECORD
# =========================================================
if overall_ok and AUTH_RECORD_ID:
    stage_name = "Update Qualys Authentication Record"
    stage_start(stage_name)
    try:
        requests.post(
            QUALYS_AUTH_URL,
            auth=(QUALYS_USER, QUALYS_PASS),
            data={
                "action": "update",
                "ids": AUTH_RECORD_ID,
                "ips": ",".join(combined_ips),
            },
            timeout=60,
            verify=False,
        )
        print("[INFO] Qualys authentication record updated")
    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)

# =========================================================
# FINAL STATUS (EXACT BLOCK YOU REQUESTED)
# =========================================================
if overall_ok:
    logger.info("Script completed successfully.")
    print(
        "Script Execution Successfully, please check the log file for details",
        file=ORIGINAL_STDOUT,
    )
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print(
        "Script Execution failed, please check the log file for details",
        file=ORIGINAL_STDOUT,
    )
    sys.exit(6)