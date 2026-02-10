import os
import sys
import json
import logging
import traceback
from datetime import datetime

import boto3
import urllib3
from panos.panorama import Panorama
from panos.device import SystemSettings
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================
# Preserve original stdout
# =========================
ORIGINAL_STDOUT = sys.stdout

# =========================
# Logging setup
# =========================
LOG_DIR = os.path.join(os.getcwd(), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(
    LOG_DIR, f"log_{datetime.now().strftime('%Y%m%d')}.log"
)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)
logger.info("Logging initialized. Log file: %s", LOG_FILE)

overall_ok = True

# =========================
# AWS Secrets Manager
# =========================
def get_secret(secret_name, region="us-east-1"):
    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


# =========================
# Fetch IPs from Panorama
# =========================
def fetch_ips_from_panorama(pano_ip, api_key, label):
    ips = set()

    logger.info("[Stage] Fetch IPs from %s Palo Alto – Started", label)

    pano = Panorama(
        hostname=pano_ip,
        api_key=api_key,
    )

    devices = pano.refresh_devices(
        expand_vsys=False, include_device_groups=False
    )

    logger.info("[+] %s Panorama devices count: %d", label, len(devices))

    for dev in devices:
        try:
            # 🔧 REQUIRED FIX — hostname is mandatory under Panorama
            ss = dev.add(SystemSettings(hostname=dev.hostname))
            ss.refresh()

            ip = getattr(ss, "ip_address", None)
            if ip:
                ips.add(ip)

        except Exception as e:
            logger.warning(
                "Could not read system settings for device %s: %s",
                getattr(dev, "hostname", "UNKNOWN"),
                e,
            )

    logger.info("IPs fetched from %s (%d):", label, len(ips))
    for ip in sorted(ips):
        logger.info("  %s", ip)

    return ips


# =========================
# Qualys helpers
# =========================
def qualys_clear_asset_group(session, group_id):
    logger.info("[Stage] Clear Qualys Asset Group – Started")
    r = session.post(
        "https://qualysapi.qualys.com/api/2.0/fo/asset/group/",
        data={"action": "edit", "id": group_id, "remove_ips": "ALL"},
    )
    if r.status_code != 200:
        raise RuntimeError("Qualys clear failed")


def qualys_add_asset_group(session, group_id, ips):
    logger.info("[Stage] Add IPs to Qualys Asset Group – Started")
    r = session.post(
        "https://qualysapi.qualys.com/api/2.0/fo/asset/group/",
        data={"action": "edit", "id": group_id, "add_ips": ",".join(ips)},
    )
    if r.status_code != 200:
        raise RuntimeError("Qualys add failed")


# =========================
# Main
# =========================
try:
    secrets = get_secret("qualys-secret-qs-dev-qualys-script")

    PROD_IPS = fetch_ips_from_panorama(
        secrets["PALO_IP"],
        secrets["PALO_API_KEY"],
        "Prod",
    )

    LAB_IPS = fetch_ips_from_panorama(
        secrets["LAB_PALO_IP"],
        secrets["LAB_PALO_API_KEY"],
        "Lab",
    )

    logger.info("[Stage] Combine Prod and Lab IPs – Started")
    combined_ips = sorted(PROD_IPS | LAB_IPS)
    logger.info("Combined unique IP count: %d", len(combined_ips))

    if not combined_ips:
        logger.error("Combined IP list is empty, skipping Qualys stages")
        overall_ok = False
    else:
        session = requests.Session()
        session.auth = (
            secrets["QUALYS_USERNAME"],
            secrets["QUALYS_PASSWORD"],
        )

        qualys_clear_asset_group(session, secrets["QUALYS_ASSET_GROUP_ID"])
        qualys_add_asset_group(
            session, secrets["QUALYS_ASSET_GROUP_ID"], combined_ips
        )

except Exception:
    overall_ok = False
    logger.error("Unhandled exception occurred")
    logger.error(traceback.format_exc())


# =========================
# Final status (YOUR BLOCK)
# =========================
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