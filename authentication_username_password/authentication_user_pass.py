import os
import sys
import subprocess
import datetime
import logging
import traceback
import urllib3

# ---------------------------------
# Auto Install Required Packages
# ---------------------------------
required_packages = ["requests", "python-dotenv", "urllib3", "pandas", "openpyxl"]

for package in required_packages:
    try:
        __import__(package.replace("-", "_"))
    except ImportError:
        # Silently install missing packages
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )

# ---------------------------------
# Imports
# ---------------------------------
import requests
import pandas as pd
from dotenv import load_dotenv

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------
# Logging Setup (Quiet Mode)
# ---------------------------------
date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"qualys_credential_update_{date_str}.log"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
for h in list(logger.handlers):
    logger.removeHandler(h)

fh = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(fh)

# Save the real standard output for the final message only
ORIGINAL_STDOUT = sys.__stdout__

# Intercept rogue print statements
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
# Helper Functions & Config
# ---------------------------------
def stage_start(name):
    logger.info("="*70)
    logger.info(f"[Stage] {name} — Started")
    logger.info("="*70)

def stage_fail(name, err):
    logger.error(f"[Stage: {name}] Failed — {err}")
    logger.error(traceback.format_exc())
    logger.error("-" * 70)

ENDPOINT_MAP = {
    "unix": "https://qualysapi.qualys.com/api/3.0/fo/auth/unix/",
    "windows": "https://qualysapi.qualys.com/api/3.0/fo/auth/windows/",
    "oracle": "https://qualysapi.qualys.com/api/3.0/fo/auth/oracle/",
    "cisco": "https://qualysapi.qualys.com/api/3.0/fo/auth/cisco/"
}

# ---------------------------------
# Load Environment Variables
# ---------------------------------
load_dotenv()

QUALYS_USER = os.getenv("QUALYS_USERNAME")
QUALYS_PASS = os.getenv("QUALYS_PASSWORD")
EXCEL_FILE = os.getenv("EXCEL_FILE")

if not QUALYS_USER or not QUALYS_PASS or not EXCEL_FILE:
    logger.critical("Missing variables in .env.")
    print("Script failed", file=ORIGINAL_STDOUT)
    sys.exit(2)

# ---------------------------------
# Stage 1 - Read Excel File
# ---------------------------------
stage_name = f"Read and Parse Excel Data ({EXCEL_FILE})"
stage_start(stage_name)
overall_ok = True

try:
    if not os.path.exists(EXCEL_FILE):
        raise FileNotFoundError(f"Could not find the Excel file: {EXCEL_FILE}")
    
    # dtype=str prevents pandas from altering passwords that look like numbers (e.g. 123456)
    df = pd.read_excel(EXCEL_FILE, dtype=str)
    
    # Fill empty cells with empty strings to prevent 'nan' strings
    df.fillna('', inplace=True)
    df.columns = df.columns.str.strip().str.lower()
    
    required_cols = ['authentication id', 'record type', 'target username', 'target password']
    missing_cols = [col for col in required_cols if col not in df.columns]
    
    if missing_cols:
        raise ValueError(f"Missing columns: {', '.join(missing_cols)}")
        
    total_rows = len(df)
    logger.info("✅ [Stage: %s] Completed. Loaded %d rows.", stage_name, total_rows)

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)
    print("Script failed", file=ORIGINAL_STDOUT)
    sys.exit(3)

# ---------------------------------
# Stage 2 - Process & Update Records
# ---------------------------------
stage_name = "Bulk Update Qualys Credentials"
stage_start(stage_name)

success_count = 0
fail_count = 0

for index, row in df.iterrows():
    auth_id = str(row['authentication id']).strip()
    record_type = str(row['record type']).strip().lower()
    target_user = str(row['target username']).strip()
    target_pass = str(row['target password']).strip()
    
    row_num = index + 2 
    
    if not auth_id or not record_type:
        logger.warning(f"[Row {row_num}] Skipping row due to missing ID or Record Type.")
        fail_count += 1
        continue

    api_url = ENDPOINT_MAP.get(record_type)
    
    if not api_url:
        logger.error(f"[Row {row_num}] Unsupported Record Type '{record_type}'. ID: {auth_id}")
        fail_count += 1
        continue

    # Dynamically build the payload based on what is provided in the Excel sheet
    update_payload = {
        "action": "update",
        "ids": auth_id,
        "echo_request": "1"
    }
    
    if target_user:
        update_payload["username"] = target_user
    if target_pass:
        update_payload["password"] = target_pass
        
    if not target_user and not target_pass:
        logger.warning(f"[Row {row_num}] ID {auth_id}: No username or password provided. Skipping.")
        fail_count += 1
        continue

    try:
        logger.info(f"Processing Row {row_num}: Updating credentials for {record_type.capitalize()} ID {auth_id}...")
        
        response = requests.post(
            api_url,
            data=update_payload,
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            headers={"X-Requested-With": "python-requests"},
            timeout=120
        )
        
        if response.status_code == 200:
            logger.info(f"✅ Success - Credentials for ID {auth_id} updated.")
            success_count += 1
        else:
            logger.error(f"❌ Failed - ID {auth_id} HTTP {response.status_code}. Response: {response.text[:500]}")
            fail_count += 1
            overall_ok = False

    except Exception as e:
        logger.error(f"❌ Exception on Row {row_num} (ID {auth_id}): {str(e)}")
        fail_count += 1
        overall_ok = False

# ---------------------------------
# Final Summary Output
# ---------------------------------
logger.info("="*70)
logger.info("Execution Summary:")
logger.info(f"  Total Processed: {success_count + fail_count}")
logger.info(f"  Successful: {success_count}")
logger.info(f"  Failed/Skipped: {fail_count}")
logger.info("="*70)

# Exact output requested
if overall_ok and fail_count == 0:
    logger.info("Script completed perfectly with zero failures.")
    print("Script successful", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error(f"Script completed with {fail_count} failures.")
    print("Script failed", file=ORIGINAL_STDOUT)
    sys.exit(6)
