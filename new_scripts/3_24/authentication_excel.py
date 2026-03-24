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
        print(f"Installing missing package: {package}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# ---------------------------------
# Imports
# ---------------------------------
import requests
import pandas as pd
from dotenv import load_dotenv

# Suppress the InsecureRequestWarning caused by verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------
# Logging Setup
# ---------------------------------
date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"qualys_bulk_update_{date_str}.log"

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
# Helper Functions & Config
# ---------------------------------
def stage_start(name):
    print("\n" + "="*70)
    print(f"[Stage] {name} — Started")
    print("="*70)

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(traceback.format_exc())
    print("-"*70)

# Map human-readable record types from Excel to the Qualys API 3.0 Endpoints
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
    error_msg = "Missing variables in .env. Ensure QUALYS_USERNAME, QUALYS_PASSWORD, and EXCEL_FILE are set."
    logger.critical(error_msg)
    print(error_msg, file=ORIGINAL_STDOUT)
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
    
    # dtype=str prevents pandas from turning numerical IDs into floats (e.g., 12345.0)
    df = pd.read_excel(EXCEL_FILE, dtype=str)
    
    # Normalize column names to lowercase and strip spaces to avoid case-sensitivity issues
    df.columns = df.columns.str.strip().str.lower()
    
    # Validate required columns exist based on your input
    required_cols = ['authentication id', 'ip address', 'record type']
    missing_cols = [col for col in required_cols if col not in df.columns]
    
    if missing_cols:
        raise ValueError(f"Excel file is missing required columns: {', '.join(missing_cols)}")
        
    total_rows = len(df)
    logger.info("✅ [Stage: %s] Completed Successfully. Loaded %d rows.", stage_name, total_rows)
    print(f"[INFO] Loaded {total_rows} records to process.", file=ORIGINAL_STDOUT)

except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)
    print("Script Execution failed during Excel parsing. Check log.", file=ORIGINAL_STDOUT)
    sys.exit(3)

# ---------------------------------
# Stage 2 - Process & Update Records
# ---------------------------------
stage_name = "Bulk Update Qualys Authentication Records"
stage_start(stage_name)

success_count = 0
fail_count = 0

for index, row in df.iterrows():
    # Retrieve data using the normalized column names
    auth_id = str(row['authentication id']).strip()
    raw_ips = str(row['ip address']).strip()
    record_type = str(row['record type']).strip().lower()
    
    row_num = index + 2 # +2 accounts for 0-index and header row
    
    if auth_id.lower() == 'nan' or raw_ips.lower() == 'nan' or record_type.lower() == 'nan':
        logger.warning(f"[Row {row_num}] Skipping row due to missing data.")
        fail_count += 1
        continue

    # Clean IP formatting
    ip_list = [ip.strip() for ip in raw_ips.split(",") if ip.strip()]
    formatted_ips = ",".join(ip_list)
    
    # Determine Endpoint
    api_url = ENDPOINT_MAP.get(record_type)
    
    if not api_url:
        logger.error(f"[Row {row_num}] Unsupported Record Type '{record_type}'. ID: {auth_id}")
        print(f"❌ [Row {row_num}] Failed: Unsupported type '{record_type}'", file=ORIGINAL_STDOUT)
        fail_count += 1
        continue

    # Execute API Call
    try:
        update_payload = {
            "action": "update",
            "ids": auth_id,  # Uses "ids" per the Qualys requirement
            "ips": formatted_ips,
            "echo_request": "1"
        }
        
        logger.info(f"Processing Row {row_num}: Updating {record_type.capitalize()} ID {auth_id} with {len(ip_list)} IPs...")
        
        response = requests.post(
            api_url,
            data=update_payload,
            auth=(QUALYS_USER, QUALYS_PASS),
            verify=False,
            headers={"X-Requested-With": "python-requests"},
            timeout=120
        )
        
        if response.status_code == 200:
            logger.info(f"✅ Success - ID {auth_id} updated.")
            print(f"✅ [Row {row_num}] ID {auth_id} updated successfully.", file=ORIGINAL_STDOUT)
            success_count += 1
        else:
            logger.error(f"❌ Failed - ID {auth_id} HTTP {response.status_code}. Response: {response.text[:500]}")
            print(f"❌ [Row {row_num}] Failed to update ID {auth_id}. HTTP {response.status_code}", file=ORIGINAL_STDOUT)
            fail_count += 1
            overall_ok = False

    except Exception as e:
        logger.error(f"❌ Exception on Row {row_num} (ID {auth_id}): {str(e)}")
        print(f"❌ [Row {row_num}] Error updating ID {auth_id}.", file=ORIGINAL_STDOUT)
        fail_count += 1
        overall_ok = False

# ---------------------------------
# Final Summary Output
# ---------------------------------
print("\n" + "="*70, file=ORIGINAL_STDOUT)
print(f"Execution Summary:", file=ORIGINAL_STDOUT)
print(f"  Total Processed: {success_count + fail_count}", file=ORIGINAL_STDOUT)
print(f"  Successful: {success_count}", file=ORIGINAL_STDOUT)
print(f"  Failed/Skipped: {fail_count}", file=ORIGINAL_STDOUT)
print("="*70, file=ORIGINAL_STDOUT)

if overall_ok and fail_count == 0:
    logger.info("Script completed perfectly with zero failures.")
    print("Script Executed Successfully, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error(f"Script completed with {fail_count} failures.")
    print("Script Executed with some failures, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(6)
