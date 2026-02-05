import os
import sys
import requests
import traceback
from datetime import datetime
from panos.panorama import Panorama
from panos.device import SystemSettings
from dotenv import load_dotenv
import logging
import urllib3
import time  # ✅ REQUIRED CHANGE

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

def fetch_ips_from_host(host, api_key, label):
    ips = set()
    if not host or not api_key:
        logger.info("Skipping %s because host or api_key not provided (host=%s, key_provided=%s)", label, host, bool(api_key))
        return ips
    try:
        print(f"[+] Connecting to Panorama {host} ({label})")
        pano = Panorama(host, api_key=api_key)
        devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
        print(f"[+] {label}: Panorama {host} devices count: {len(devices)}")
        fetched = 0
        for dev in devices:
            try:
                ss = dev.find("", SystemSettings)
                ip = getattr(ss, "ip_address", None)
                if ip:
                    ips.add(ip)
                    fetched += 1
            except Exception as e:
                print(f"[WARN] Could not read system settings for a device on {host}: {e}")
                logger.warning("Device read failed on %s: %s", host, str(e))
        logger.info("Host %s (%s) fetched %d IPs", host, label, fetched)
    except Exception as e:
        print(f"[ERROR] Failed to connect or fetch devices from {host} ({label}): {e}")
        logger.error("Panorama host %s (%s) failed: %s\n%s", host, label, str(e), traceback.format_exc())
    return ips

# ---------------------------
# Environment variables
# ---------------------------
PALO_PROD_HOST = os.getenv("PALO_PROD_HOST")
PALO_PROD_API_KEY = os.getenv("PALO_PROD_API_KEY")

LAB_HOST = os.getenv("LAB_HOST")
LAB_API_KEY = os.getenv("LAB_API_KEY")

PCI1_HOST = os.getenv("PCI1_HOST")
PCI1_API_KEY = os.getenv("PCI1_API_KEY")

PCI2_HOST = os.getenv("PCI2_HOST")
PCI2_API_KEY = os.getenv("PCI2_API_KEY")

QUALYS_USER = os.getenv("QUALYS_USER")
QUALYS_PASS = os.getenv("QUALYS_PASS")
QUALYS_GROUP_ID = os.getenv("QUALYS_GROUP_ID")
AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")

QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"
QUALYS_AUTH_UPDATE_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"

required = {
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

# Fetch IPs
stage_name = "Fetch IPs from configured Palo Alto Panorama hosts"
stage_start(stage_name)
all_ips = set()
try:
    hosts = [
        (PALO_PROD_HOST, PALO_PROD_API_KEY, "PROD"),
        (LAB_HOST, LAB_API_KEY, "LAB"),
        (PCI1_HOST, PCI1_API_KEY, "PCI1"),
        (PCI2_HOST, PCI2_API_KEY, "PCI2"),
    ]

    used_hosts = [h for h in hosts if h[0] and h[1]]
    if not used_hosts:
        raise RuntimeError("No Panorama hosts configured")

    for host, key, label in hosts:
        ips = fetch_ips_from_host(host, key, label)
        if ips:
            all_ips |= ips

    logger.info("Fetched %d unique IPs", len(all_ips))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    sys.exit(3)

combined_ips = sorted(all_ips)
set_ips_str = ",".join(combined_ips)

# Clear asset group
requests.post(
    QUALYS_URL,
    data={"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": ""},
    auth=(QUALYS_USER, QUALYS_PASS),
    verify=False,
    timeout=60
)

# Add asset group
requests.post(
    QUALYS_URL,
    data={"action": "edit", "id": QUALYS_GROUP_ID, "set_ips": set_ips_str},
    auth=(QUALYS_USER, QUALYS_PASS),
    verify=False,
    timeout=120
)

# ==========================================================
# ✅ FIXED AUTH RECORD UPDATE (ONLY REQUIRED CHANGE)
# ==========================================================
if AUTH_RECORD_ID and combined_ips:
    stage_name = f"Update Qualys authentication record ID {AUTH_RECORD_ID}"
    stage_start(stage_name)
    try:
        # STEP 1: CLEAR IPs
        clear_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": ""
        }
        clear_resp = requests.post(
            QUALYS_AUTH_UPDATE_URL,
            data=clear_payload,
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            headers={"X-Requested-With": "python-requests"},
            timeout=60
        )
        if clear_resp.status_code != 200:
            raise RuntimeError("Auth record IP clear failed")

        logger.info("Auth record IPs cleared successfully")

        # Qualys backend propagation delay
        time.sleep(3)

        # STEP 2: ADD IPs
        add_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": set_ips_str
        }
        add_resp = requests.post(
            QUALYS_AUTH_UPDATE_URL,
            data=add_payload,
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            headers={"X-Requested-With": "python-requests"},
            timeout=120
        )
        if add_resp.status_code != 200:
            raise RuntimeError("Auth record IP add failed")

        # STEP 3: VERIFY
        verify_payload = {
            "action": "list",
            "ids": AUTH_RECORD_ID,
            "show_ips": "1"
        }
        verify_resp = requests.post(
            QUALYS_AUTH_UPDATE_URL,
            data=verify_payload,
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            headers={"X-Requested-With": "python-requests"},
            timeout=60
        )

        logger.debug("Auth verify response:\n%s", verify_resp.text[:2000])
        logger.info("Auth record IPs replaced successfully")

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
    sys.exit(7)
