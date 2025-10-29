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

# Load env
load_dotenv()

# Disable insecure warnings if needed (your earlier scripts used verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===============================
# Logging setup (minimal change)
# ===============================
date_str = datetime.now().strftime("%Y%m%d")
log_filename = f"log_{date_str}.log"

# --- START: Explicit logger configuration (replace basicConfig to keep console quiet) ---
logger = logging.getLogger()  # root logger
logger.setLevel(logging.DEBUG)

# Remove any pre-existing handlers to avoid duplicates if module is reloaded
for h in list(logger.handlers):
    logger.removeHandler(h)

# File handler: all detailed logs go to this file
file_handler = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Console handler: set to CRITICAL so nothing except critical logs go to console.
# We will print the final short message directly to the original stdout.
console_handler = logging.StreamHandler(sys.__stdout__)
console_handler.setLevel(logging.CRITICAL)
console_formatter = logging.Formatter("%(levelname)s: %(message)s")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)
# --- END: Explicit logger configuration ---

# Save original stdout so we can print the final short message to the console only
ORIGINAL_STDOUT = sys.__stdout__

# Redirect stdout/stderr to logging so existing prints go into the log file
class LoggerWriter:
    def __init__(self, level_func):
        self.level_func = level_func

    def write(self, message):
        message = message.rstrip()
        if message:
            # Use debug to ensure it goes to file handler but not displayed on console
            self.level_func(message)

    def flush(self):
        pass

# Use logger.debug for stdout, logger.error for stderr
sys.stdout = LoggerWriter(logger.debug)
sys.stderr = LoggerWriter(logger.error)

# Log initialization message (goes to file)
logger.info(f"[+] Logging initialized. Log file: {os.path.abspath(log_filename)}")

# ===============================
# Stage helpers (minimal)
# ===============================
def stage_start(name):
    print("\n" + "="*70)
    print(f"[Stage] {name} — Started")
    print("="*70)

def stage_success(name):
    print(f"✅ [Stage: {name}] Completed Successfully")
    print("-"*70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    # Log traceback for debugging (detailed)
    tb = traceback.format_exc()
    logger.error(tb)
    print("-"*70)

# ===============================
# Environment variables
# ===============================
PALO_IP = os.getenv("PALO_IP")
PALO_API_KEY = os.getenv("PALO_API_KEY")
LAB_IP = os.getenv("LAB_IP")
LAB_API_KEY = os.getenv("LAB_API_KEY")
QUALYS_USER = os.getenv("QUALYS_USER")
QUALYS_PASS = os.getenv("QUALYS_PASS")
QUALYS_GROUP_ID = os.getenv("QUALYS_GROUP_ID")
QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"

# Basic validation of required envs
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
    logger.critical(f"[FATAL] Missing environment variables: {', '.join(missing)}")
    # Final short message to user on console (only)
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(2)

# We'll track overall status
overall_ok = True

# ===============================
# Stage 1 - Fetch IPs from Prod Palo Alto
# ===============================
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)
prod_ips = set()
try:
    # Use api_key param explicitly (avoid empty username/password)
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
            # preserve behavior but log
            print(f"[WARN] Could not read system settings for a prod device: {e}")

    print(f"[INFO] IPs fetched from Prod ({len(prod_ips)}):")
    for ip in sorted(prod_ips):
        print("   ", ip)

    stage_success(stage_name)
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# ===============================
# Stage 2 - Fetch IPs from Lab Palo Alto
# ===============================
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

    stage_success(stage_name)
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# If either fetch failed, we should not proceed to destructive Qualys operations.
if not overall_ok:
    logger.warning("One or more stages failed before Qualys operations, aborting further steps.")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(3)

# ===============================
# Stage 3 - Combine both Prod and Lab IP Addresses
# ===============================
stage_name = "Combine both Prod and Lab IP Addresses"
stage_start(stage_name)
try:
    combined_ips = sorted(set(prod_ips) | set(lab_ips))
    print(f"[INFO] Combined unique IP count: {len(combined_ips)}")
    for ip in combined_ips:
        print("   ", ip)
    stage_success(stage_name)
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# If combine failed, stop
if not overall_ok:
    logger.warning("Combine stage failed, aborting.")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(4)

# ===============================
# Stage 4 - Remove current IP list from Qualys Asset group
# ===============================
stage_name = "Remove current IP list from Qualys Asset group"
stage_start(stage_name)
try:
    # clear group by setting set_ips to empty string
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
    # Print truncated response for visibility (goes to log only)
    print(clear_resp.text[:1000])

    if clear_resp.status_code != 200:
        raise RuntimeError(f"Qualys clear failed: HTTP {clear_resp.status_code}")

    stage_success(stage_name)
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    logger.warning("Qualys clear step failed, aborting.")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(5)

# ===============================
# Stage 5 - Add the latest Palo Alto Combined list to Qualys Asset group
# ===============================
stage_name = "Add the latest Palo Alto Combined list to Qualys Asset group"
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

    stage_success(stage_name)
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# ===============================
# Final summary and exit
# ===============================
if overall_ok:
    logger.info("Script completed successfully.")
    # final short message to console
    print("Script Execution Successfully, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    # final short message to console
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(6)