import os
import sys
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from panos.panorama import Panorama
from panos.device import SystemSettings
from dotenv import load_dotenv
import logging
import urllib3
import traceback

# load .env file
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# logging setup
date_str = datetime.now().strftime("%Y%m%d")
log_filename = f"log_{date_str}.log"

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

# helper functions
def stage_start(name):
    print("\n" + "="*70)
    print(f"[Stage] {name} — Started")
    print("="*70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(traceback.format_exc())
    print("-"*70)

# environment variables
PALO_IP = os.getenv("PALO_IP")
PALO_API_KEY = os.getenv("PALO_API_KEY")
LAB_IP = os.getenv("LAB_IP")
LAB_API_KEY = os.getenv("LAB_API_KEY")
QUALYS_USER = os.getenv("QUALYS_USER")
QUALYS_PASS = os.getenv("QUALYS_PASS")
QUALYS_GROUP_ID = os.getenv("QUALYS_GROUP_ID")
AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")

QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"
QUALYS_AUTH_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"

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

# Stage 1 - fetch from prod
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

# Stage 2 - fetch from lab
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

# Stage 3 - combine
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

# Stage 4 - clear asset group
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

# Stage 5 - add to Qualys Asset Group
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

# Stage 6 - update Qualys Authentication Record
if AUTH_RECORD_ID and combined_ips:
    stage_name = f"Update Qualys authentication record ID {AUTH_RECORD_ID}"
    stage_start(stage_name)
    try:
        auth_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "add_ips": ",".join(combined_ips),
            "echo_request": "1"
        }
        auth_resp = requests.post(
            QUALYS_AUTH_URL,
            data=auth_payload,
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            headers={"X-Requested-With": "python-requests"},
            timeout=120
        )
        logger.debug("Auth update response status: %s", auth_resp.status_code)
        logger.debug("Auth update response body (truncated): %s", auth_resp.text[:2000])
        if auth_resp.status_code != 200:
            raise RuntimeError(f"Auth record update failed: HTTP {auth_resp.status_code}")
        try:
            root = ET.fromstring(auth_resp.text)
            txt = root.find(".//TEXT")
            if txt is not None:
                logger.info("Auth record response: %s", txt.text)
        except Exception:
            logger.debug("Unable to parse auth API XML; raw response above.")
        logger.info(
            "✅ [Stage: %s — Combined list of %d IPs] Completed Successfully",
            stage_name,
            len(combined_ips)
        )
    except Exception as e:
        overall_ok = False
        stage_fail(stage_name, e)
else:
    logger.info("AUTH_RECORD_ID not provided or no combined IPs; skipping auth record update.")

# final summary
if overall_ok:
    logger.info("Script completed successfully.")
    print("Script Execution Successfully, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(6)