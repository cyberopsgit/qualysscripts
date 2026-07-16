import os
import sys
import requests
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
    logger.info(f"--- [Stage] {name} — Started ---")

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(f"Stage {name} Failed: {err}")
    logger.error(traceback.format_exc())
    print("-"*70)

# environment variables
PALO_IP = os.getenv("PALO_IP")
PALO_API_KEY = os.getenv("PALO_API_KEY")

LAB_IP = os.getenv("LAB_IP")
LAB_API_KEY = os.getenv("LAB_API_KEY")

PCI1_HOST = os.getenv("PCI1_HOST")
PCI1_API_KEY = os.getenv("PCI1_API_KEY")

PCI2_HOST = os.getenv("PCI2_HOST")
PCI2_API_KEY = os.getenv("PCI2_API_KEY")

required = {
    "PALO_IP": PALO_IP,
    "PALO_API_KEY": PALO_API_KEY,
    "LAB_IP": LAB_IP,
    "LAB_API_KEY": LAB_API_KEY,
    "PCI1_HOST": PCI1_HOST,
    "PCI1_API_KEY": PCI1_API_KEY,
    "PCI2_HOST": PCI2_HOST,
    "PCI2_API_KEY": PCI2_API_KEY
}

missing = [k for k, v in required.items() if not v]
if missing:
    logger.critical(f"Missing environment variables: {', '.join(missing)}")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(2)

# Global trackers for final summary
total_devices_found = 0
total_ips_fetched = 0
failed_logs = []  

# ==========================================
# Stage 1 - fetch from prod
# ==========================================
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)
prod_ips = set()
try:
    pano = Panorama(PALO_IP, api_key=PALO_API_KEY)
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    total_devices_found += len(devices)
    print(f"[+] Production Panorama devices count: {len(devices)}")
    logger.info(f"Found {len(devices)} devices in Production Panorama.")
    
    for dev in devices:
        # Fetch hostname directly from the device object (not SystemSettings)
        hostname = getattr(dev, "hostname", "Unknown_Hostname")
        
        try:
            ss = dev.find("", SystemSettings)
            if ss:
                ip = getattr(ss, "ip_address", None)
                if ip:
                    prod_ips.add(ip)
                    total_ips_fetched += 1
                    logger.debug(f"Successfully fetched IP ({ip}) for Prod device: {hostname}")
                else:
                    failed_logs.append({"env": "Prod", "host": hostname, "reason": "No IP address returned"})
            else:
                failed_logs.append({"env": "Prod", "host": hostname, "reason": "No SystemSettings found for device"})
        except Exception as e:
            failed_logs.append({"env": "Prod", "host": hostname, "reason": str(e)})
            continue
            
    logger.info("✅ [Stage: %s] Completed with %d IPs fetched", stage_name, len(prod_ips))
except Exception as e:
    failed_logs.append({"env": "Prod Panorama", "host": PALO_IP, "reason": f"Complete connection failure: {e}"})
    stage_fail(stage_name, f"Could not connect to Prod Panorama at {PALO_IP}. Reason: {e}")


# ==========================================
# Stage 2 - fetch from lab
# ==========================================
stage_name = "Fetch IPs from Lab Palo Alto"
stage_start(stage_name)
lab_ips = set()
try:
    lab_pano = Panorama(LAB_IP, api_key=LAB_API_KEY)
    lab_devices = lab_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    total_devices_found += len(lab_devices)
    print(f"[+] Lab Panorama devices count: {len(lab_devices)}")
    logger.info(f"Found {len(lab_devices)} devices in Lab Panorama.")
    
    for dev in lab_devices:
        hostname = getattr(dev, "hostname", "Unknown_Hostname")
        try:
            ss = dev.find("", SystemSettings)
            if ss:
                ip = getattr(ss, "ip_address", None)
                if ip:
                    lab_ips.add(ip)
                    total_ips_fetched += 1
                    logger.debug(f"Successfully fetched IP ({ip}) for Lab device: {hostname}")
                else:
                    failed_logs.append({"env": "Lab", "host": hostname, "reason": "No IP address returned"})
            else:
                failed_logs.append({"env": "Lab", "host": hostname, "reason": "No SystemSettings found for device"})
        except Exception as e:
            failed_logs.append({"env": "Lab", "host": hostname, "reason": str(e)})
            continue
            
    logger.info("✅ [Stage: %s] Completed with %d IPs fetched", stage_name, len(lab_ips))
except Exception as e:
    failed_logs.append({"env": "Lab Panorama", "host": LAB_IP, "reason": f"Complete connection failure: {e}"})
    stage_fail(stage_name, f"Could not connect to Lab Panorama at {LAB_IP}. Reason: {e}")


# ==========================================
# Stage 3 - fetch from PCI 1
# ==========================================
stage_name = "Fetch IPs from PCI 1 Palo Alto"
stage_start(stage_name)
pci1_ips = set()
try:
    pci1_pano = Panorama(PCI1_HOST, api_key=PCI1_API_KEY)
    pci1_devices = pci1_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    total_devices_found += len(pci1_devices)
    print(f"[+] PCI 1 Panorama devices count: {len(pci1_devices)}")
    logger.info(f"Found {len(pci1_devices)} devices in PCI 1 Panorama.")
    
    for dev in pci1_devices:
        hostname = getattr(dev, "hostname", "Unknown_Hostname")
        try:
            ss = dev.find("", SystemSettings)
            if ss:
                ip = getattr(ss, "ip_address", None)
                if ip:
                    pci1_ips.add(ip)
                    total_ips_fetched += 1
                    logger.debug(f"Successfully fetched IP ({ip}) for PCI 1 device: {hostname}")
                else:
                    failed_logs.append({"env": "PCI-1", "host": hostname, "reason": "No IP address returned"})
            else:
                failed_logs.append({"env": "PCI-1", "host": hostname, "reason": "No SystemSettings found for device"})
        except Exception as e:
            failed_logs.append({"env": "PCI-1", "host": hostname, "reason": str(e)})
            continue
            
    logger.info("✅ [Stage: %s] Completed with %d IPs fetched", stage_name, len(pci1_ips))
except Exception as e:
    failed_logs.append({"env": "PCI-1 Panorama", "host": PCI1_HOST, "reason": f"Complete connection failure: {e}"})
    stage_fail(stage_name, f"Could not connect to PCI 1 Panorama at {PCI1_HOST}. Reason: {e}")


# ==========================================
# Stage 4 - fetch from PCI 2
# ==========================================
stage_name = "Fetch IPs from PCI 2 Palo Alto"
stage_start(stage_name)
pci2_ips = set()
try:
    pci2_pano = Panorama(PCI2_HOST, api_key=PCI2_API_KEY)
    pci2_devices = pci2_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    total_devices_found += len(pci2_devices)
    print(f"[+] PCI 2 Panorama devices count: {len(pci2_devices)}")
    logger.info(f"Found {len(pci2_devices)} devices in PCI 2 Panorama.")
    
    for dev in pci2_devices:
        hostname = getattr(dev, "hostname", "Unknown_Hostname")
        try:
            ss = dev.find("", SystemSettings)
            if ss:
                ip = getattr(ss, "ip_address", None)
                if ip:
                    pci2_ips.add(ip)
                    total_ips_fetched += 1
                    logger.debug(f"Successfully fetched IP ({ip}) for PCI 2 device: {hostname}")
                else:
                    failed_logs.append({"env": "PCI-2", "host": hostname, "reason": "No IP address returned"})
            else:
                failed_logs.append({"env": "PCI-2", "host": hostname, "reason": "No SystemSettings found for device"})
        except Exception as e:
            failed_logs.append({"env": "PCI-2", "host": hostname, "reason": str(e)})
            continue
            
    logger.info("✅ [Stage: %s] Completed with %d IPs fetched", stage_name, len(pci2_ips))
except Exception as e:
    failed_logs.append({"env": "PCI-2 Panorama", "host": PCI2_HOST, "reason": f"Complete connection failure: {e}"})
    stage_fail(stage_name, f"Could not connect to PCI 2 Panorama at {PCI2_HOST}. Reason: {e}")


# ==========================================
# Stage 5 - combine
# ==========================================
stage_name = "Combine All IP Addresses"
stage_start(stage_name)
combined_ips = sorted(set(prod_ips) | set(lab_ips) | set(pci1_ips) | set(pci2_ips))
print(f"[INFO] Combined unique IP count: {len(combined_ips)}")
logger.info("Final Combined IP List:")
for ip in combined_ips:
    logger.info(f" - {ip}")


# ==========================================
# FINAL SUMMARY REPORT
# ==========================================
print("\n" + "="*70)
print(" FINAL EXECUTION SUMMARY ")
print("="*70)
print(f"Total Devices Attempted : {total_devices_found}")
print(f"Total Successful IPs    : {total_ips_fetched}")
print(f"Total Failed Devices    : {len(failed_logs)}")

logger.info("=== FINAL EXECUTION SUMMARY ===")
logger.info(f"Total Devices Attempted: {total_devices_found}")
logger.info(f"Total Successful IPs: {total_ips_fetched}")
logger.info(f"Total Failed Devices: {len(failed_logs)}")

if failed_logs:
    print("\n[Failure Details]")
    logger.info("[Failure Details]")
    for fail in failed_logs:
        fail_str = f" - [{fail['env']}] Host: {fail['host']} | Reason: {fail['reason']}"
        print(fail_str)
        logger.error(fail_str)

print("\n" + "="*70)

# Determine exit status
if len(failed_logs) == 0:
    print("Script Executed Successfully with 0 errors. Check the log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(0)
elif total_ips_fetched > 0:
    print("Script Executed with Partial Success (Some devices failed). Check the summary/log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(1)
else:
    print("Script Failed Completely (0 IPs fetched). Check the summary/log file for details.", file=ORIGINAL_STDOUT)
    sys.exit(5)