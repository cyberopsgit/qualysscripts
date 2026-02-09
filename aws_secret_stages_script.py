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
import socket
import boto3
from botocore.exceptions import ClientError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# AWS Secrets Manager
# =========================================================
AWS_REGION = os.getenv("region_name", "us-east-1")
SECRET_NAME = os.getenv("AWS_SECRET_NAME", "qualys-secret-qs-dev-qualys-script")

session = boto3.session.Session()
client = session.client("secretsmanager", region_name=AWS_REGION)

def get_secret():
    response = client.get_secret_value(
        SecretId=SECRET_NAME,
        VersionStage="AWSCURRENT"
    )
    return json.loads(response["SecretString"])

SECRETS = get_secret()

# =========================================================
# Logging setup
# =========================================================
date_str = datetime.now().strftime("%Y%m%d")
os.makedirs("logs", exist_ok=True)
log_filename = f"logs/log_{date_str}.log"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.handlers.clear()

fh = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
fh.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
)
logger.addHandler(fh)

ch = logging.StreamHandler(sys.__stdout__)
ch.setLevel(logging.INFO)
logger.addHandler(ch)

ORIGINAL_STDOUT = sys.__stdout__

# =========================================================
# Helper functions
# =========================================================
def stage_start(name):
    print("\n" + "=" * 70)
    print(f"[Stage] {name} — Started")
    print("=" * 70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(traceback.format_exc())

# =========================================================
# Load secrets
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
# Validation
# =========================================================
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
    print(f"Missing required values: {missing}", file=ORIGINAL_STDOUT)
    sys.exit(2)

overall_ok = True

# =========================================================
# Stage 1 – Fetch PROD IPs (FIXED)
# =========================================================
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)
prod_ips = set()

try:
    pano = Panorama(PALO_IP, api_key=PALO_API_KEY)
    devices = pano.refresh_devices(
        expand_vsys=False,
        include_device_groups=False
    )

    print(f"[+] Production Panorama devices count: {len(devices)}")

    for dev in devices:
        try:
            ss = dev.find("", SystemSettings)

            # Try system IP first
            ip = getattr(ss, "ip_address", None)

            # PROD fallback: resolve hostname → IP
            if not ip and dev.hostname:
                try:
                    ip = socket.gethostbyname(dev.hostname)
                except Exception:
                    ip = None

            if ip:
                prod_ips.add(ip)

        except Exception as e:
            logger.warning(
                f"Could not read system settings for prod device "
                f"{dev.name}: {e}"
            )

    print(f"[INFO] IPs fetched from Prod ({len(prod_ips)}):")
    for ip in sorted(prod_ips):
        print("   ", ip)

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# =========================================================
# Stage 2 – Fetch LAB IPs (UNCHANGED)
# =========================================================
stage_name = "Fetch IPs from Lab Palo Alto"
stage_start(stage_name)
lab_ips = set()

try:
    lab_pano = Panorama(LAB_IP, api_key=LAB_API_KEY)
    lab_devices = lab_pano.refresh_devices(
        expand_vsys=False,
        include_device_groups=False
    )

    print(f"[+] Lab Panorama devices count: {len(lab_devices)}")

    for dev in lab_devices:
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None)
            if ip:
                lab_ips.add(ip)
        except Exception as e:
            logger.warning(
                f"Could not read system settings for lab device "
                f"{dev.name}: {e}"
            )

    print(f"[INFO] IPs fetched from Lab ({len(lab_ips)}):")
    for ip in sorted(lab_ips):
        print("   ", ip)

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    print(
        "Script Execution failed, please check the log file for details",
        file=ORIGINAL_STDOUT
    )
    sys.exit(3)

# =========================================================
# Stage 3 – Combine IPs
# =========================================================
stage_name = "Combine both Prod and Lab IP Addresses"
stage_start(stage_name)

combined_ips = sorted(prod_ips | lab_ips)
print(f"[INFO] Combined unique IP count: {len(combined_ips)}")

for ip in combined_ips:
    print("   ", ip)

# =========================================================
# Stage 4 – Clear Qualys Asset Group
# =========================================================
stage_name = "Remove current IP list from Qualys Asset group"
stage_start(stage_name)

try:
    clear_resp = requests.post(
        QUALYS_URL,
        data={"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": ""},
        auth=(QUALYS_USER, QUALYS_PASS),
        verify=False,
        timeout=60
    )

    if clear_resp.status_code != 200:
        raise RuntimeError("Qualys clear failed")

except Exception as e:
    stage_fail(stage_name, e)
    sys.exit(5)

# =========================================================
# Stage 5 – Add IPs to Qualys Asset Group
# =========================================================
stage_name = "Add the latest Palo Alto IPs to Qualys Asset group"
stage_start(stage_name)

set_ips_str = ",".join(combined_ips)

try:
    add_resp = requests.post(
        QUALYS_URL,
        data={"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": set_ips_str},
        auth=(QUALYS_USER, QUALYS_PASS),
        verify=False,
        timeout=120
    )

    if add_resp.status_code != 200:
        raise RuntimeError("Qualys add failed")

except Exception as e:
    stage_fail(stage_name, e)
    sys.exit(6)

# =========================================================
# Stage 6 – Update Auth Record (UNCHANGED)
# =========================================================
if AUTH_RECORD_ID and combined_ips:
    stage_name = f"Update Qualys authentication record ID {AUTH_RECORD_ID}"
    stage_start(stage_name)

    try:
        update_resp = requests.post(
            QUALYS_AUTH_UPDATE_URL,
            data={
                "action": "update",
                "ids": AUTH_RECORD_ID,
                "ips": set_ips_str,
                "echo_request": "1",
            },
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            timeout=120
        )

        if update_resp.status_code != 200:
            raise RuntimeError("Auth record update failed")

    except Exception as e:
        stage_fail(stage_name, e)
        sys.exit(7)

# =========================================================
# Final Summary
# =========================================================
logger.info("Script completed successfully.")
print(
    "Script Execution Successfully, please check the log file for details",
    file=ORIGINAL_STDOUT
)
sys.exit(0)
