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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# AWS SECRETS MANAGER
# =========================================================
import boto3
from botocore.exceptions import ClientError

AWS_REGION = os.getenv("region_name", "us-east-1")
SECRET_NAME = os.getenv("AWS_SECRET_NAME", "qualys-secret-qs-dev-qualys-script")

session = boto3.session.Session()
client = session.client(service_name="secretsmanager", region_name=AWS_REGION)

def get_secret():
    response = client.get_secret_value(
        SecretId=SECRET_NAME,
        VersionStage="AWSCURRENT"
    )
    return json.loads(response["SecretString"])

SECRETS = get_secret()

# =========================================================
# LOGGING SETUP (UNCHANGED)
# =========================================================
date_str = datetime.now().strftime("%Y%m%d")
os.makedirs("logs", exist_ok=True)
log_filename = f"logs/log_{date_str}.log"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

for h in list(logger.handlers):
    logger.removeHandler(h)

fh = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
fh.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
)
logger.addHandler(fh)

ORIGINAL_STDOUT = sys.__stdout__

class LoggerWriter:
    def __init__(self, level_func):
        self.level_func = level_func
    def write(self, message):
        if message.strip():
            self.level_func(message.rstrip())
    def flush(self):
        pass

sys.stdout = LoggerWriter(logger.info)
sys.stderr = LoggerWriter(logger.error)

logger.info(f"Logging initialized. Log file: {os.path.abspath(log_filename)}")

# =========================================================
# HELPERS (UNCHANGED)
# =========================================================
def stage_start(name):
    print("\n" + "=" * 70)
    print(f"[Stage] {name} — Started")
    print("=" * 70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(traceback.format_exc())

# =========================================================
# VARIABLES FROM SECRETS
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

overall_ok = True

# =========================================================
# Stage 1 - fetch from prod (FIX APPLIED)
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
            ip = getattr(dev, "ip_address", None)
            if ip:
                prod_ips.add(ip)
        except Exception as e:
            print(f"[WARN] Could not read IP for a prod device: {e}")

    print(f"[INFO] IPs fetched from Prod ({len(prod_ips)}):")
    for ip in sorted(prod_ips):
        print("   ", ip)

    logger.info(
        "✅ [Stage: %s] Completed Successfully with %d IPs fetched",
        stage_name,
        len(prod_ips)
    )

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# Stage 2 - fetch from lab (SAME FIX)
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
            ip = getattr(dev, "ip_address", None)
            if ip:
                lab_ips.add(ip)
        except Exception as e:
            print(f"[WARN] Could not read IP for a lab device: {e}")

    print(f"[INFO] IPs fetched from Lab ({len(lab_ips)}):")
    for ip in sorted(lab_ips):
        print("   ", ip)

    logger.info(
        "✅ [Stage: %s] Completed Successfully with %d IPs fetched",
        stage_name,
        len(lab_ips)
    )

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# Stage 3 - combine (UNCHANGED)
# =========================================================
stage_name = "Combine both Prod and Lab IP Addresses"
stage_start(stage_name)

combined_ips = sorted(set(prod_ips) | set(lab_ips))
print(f"[INFO] Combined unique IP count: {len(combined_ips)}")
for ip in combined_ips:
    print("   ", ip)

logger.info(
    "✅ [Stage: %s] Completed Successfully with combined list of %d IPs",
    stage_name,
    len(combined_ips)
)

# =========================================================
# Stage 4 - clear asset group (UNCHANGED)
# =========================================================
stage_name = "Remove current IP list from Qualys Asset group"
stage_start(stage_name)

try:
    clear_resp = requests.post(
        QUALYS_URL,
        data={"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": ""},
        auth=(QUALYS_USER, QUALYS_PASS),
        verify=False,
        timeout=60,
    )
    if clear_resp.status_code != 200:
        raise RuntimeError(f"Qualys clear failed: {clear_resp.status_code}")
    logger.info("✅ [Stage: %s] Completed Successfully", stage_name)
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# Stage 5 - add to Qualys Asset Group (UNCHANGED)
# =========================================================
stage_name = "Add the latest Palo Alto IPs to Qualys Asset group"
stage_start(stage_name)

try:
    add_resp = requests.post(
        QUALYS_URL,
        data={
            "action": "edit",
            "id": QUALYS_GROUP_ID,
            "set_ips": ",".join(combined_ips),
        },
        auth=(QUALYS_USER, QUALYS_PASS),
        verify=False,
        timeout=120,
    )
    if add_resp.status_code != 200:
        raise RuntimeError(f"Qualys add failed: {add_resp.status_code}")
    logger.info("✅ [Stage: %s] Completed Successfully", stage_name)
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# FINAL SUMMARY (EXACT – UNCHANGED)
# =========================================================
if overall_ok:
    logger.info("Script completed successfully.")
    print(
        "Script Execution Successfully, please check the log file for details",
        file=ORIGINAL_STDOUT
    )
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print(
        "Script Execution failed, please check the log file for details",
        file=ORIGINAL_STDOUT
    )
    sys.exit(6)