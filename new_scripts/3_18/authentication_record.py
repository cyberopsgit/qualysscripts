import os
import sys
import requests
from datetime import datetime
from dotenv import load_dotenv
import logging
import urllib3
import traceback

# ---------------------------------
# Setup & Initialization
# ---------------------------------
# load .env file
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# logging setup
date_str = datetime.now().strftime("%Y%m%d")
log_filename = f"qualys_oracle_update_{date_str}.log"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
for h in list(logger.handlers):
    logger.removeHandler(h)

fh = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(fh)

ch = logging.StreamHandler(sys.__stdout__)
ch.setLevel(logging.CRITICAL) # Keeps terminal clean, sends output to file
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

# ---------------------------------
# Helper Functions
# ---------------------------------
def stage_start(name):
    print("\n" + "="*70)
    print(f"[Stage] {name} — Started")
    print("="*70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(traceback.format_exc())
    print("-"*70)

# ---------------------------------
# Environment Variables
# ---------------------------------
QUALYS_USER = os.getenv("QUALYS_USERNAME")
QUALYS_PASS = os.getenv("QUALYS_PASSWORD")
AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")
TARGET_IPS = os.getenv("TARGET_IPS")

QUALYS_URL = "https://qualysapi.qualys.com/api/3.0/fo/auth/oracle/"

required = {
    "QUALYS_USERNAME": QUALYS_USER,
    "QUALYS_PASSWORD": QUALYS_PASS,
    "AUTH_RECORD_ID": AUTH_RECORD_ID,
    "TARGET_IPS": TARGET_IPS
}

missing = [k for k, v in required.items() if not v]
if missing:
    logger.critical(f"Missing environment variables: {', '.join(missing)}")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(2)

overall_ok = True

# ---------------------------------
# Stage 1 - Process IPs
# ---------------------------------
stage_name = "Process Target IPs from .env"
stage_start(stage_name)
ip_list = []
set_ips_str = ""

try:
    ip_list = [ip.strip() for ip in TARGET_IPS.split(",") if ip.strip()]
    if not ip_list:
        raise ValueError("No valid IPs found in TARGET_IPS variable")
        
    print(f"[INFO] Target IPs loaded ({len(ip_list)}):")
    for ip in ip_list:
        print("   ", ip)
        
    set_ips_str = ",".join(ip_list)
    logger.info("✅ [Stage: %s] Completed Successfully with %d IPs", stage_name, len(ip_list))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

if not overall_ok:
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(3)

# ---------------------------------
# Stage 2 - Update Oracle Auth Record
# ---------------------------------
stage_name = f"Update Qualys Oracle Authentication Record ID {AUTH_RECORD_ID}"
stage_start(stage_name)

try:
    update_payload = {
        "action": "update",
        "ids": AUTH_RECORD_ID, 
        "ips": set_ips_str,   # Use 'ips' as required by the endpoint to avoid 400 error
        "echo_request": "1"
    }
    
    update_resp = requests.post(
        QUALYS_URL,
        data=update_payload,
        auth=(QUALYS_USER, QUALYS_PASS),
        verify=False,
        headers={"X-Requested-With": "python-requests"},
        timeout=120
    )
    
    print(f"[DEBUG] Qualys update HTTP status: {update_resp.status_code}")
    print(update_resp.text[:1000])
    
    logger.debug("Auth update response status: %s", update_resp.status_code)
    logger.debug("Auth update response body (truncated): %s", update_resp.text[:2000])
    
    if update_resp.status_code != 200:
        raise RuntimeError(f"Auth record update failed: HTTP {update_resp.status_code}")

    logger.info(
        "✅ [Stage: %s — List of %d IPs] Completed Successfully (auth record updated)",
        stage_name,
        len(ip_list)
    )

    logger.info(
        "Summary: %d total IPs processed (auth record updated with %d IPs)",
        len(ip_list),
        len(ip_list)
    )

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)

# ---------------------------------
# Final Summary Output
# ---------------------------------
if overall_ok:
    logger.info("Script completed successfully.")
    print("Script Execution Successfully, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(6)
