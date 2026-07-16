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

overall_ok = True

# Stage 1 - fetch from prod
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)
prod_ips = set()
try:
    pano = Panorama(PALO_IP, api_key=PALO_API_KEY)
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] Production Panorama devices count: {len(devices)}")
    logger.info(f"Found {len(devices)} devices in Production Panorama.")
    
    for dev in devices:
        dev_name = getattr(dev, "name", "Unknown_Device")
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None)
            if ip:
                prod_ips.add(ip)
                logger.debug(f"Successfully fetched IP ({ip}) for Prod device: {dev_name}")
            else:
                logger.warning(f"Prod device {dev_name} did not return an IP address. Skipping.")
        except Exception as e:
            logger.error(f"Failed to fetch SystemSettings for Prod device '{dev_name}'. Reason: {e}")
            print(f"[WARN] Failed to read settings for Prod device '{dev_name}'. Skipping.")
            continue
            
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
    logger.info(f"Found {len(lab_devices)} devices in Lab Panorama.")
    
    for dev in lab_devices:
        dev_name = getattr(dev, "name", "Unknown_Device")
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None)
            if ip:
                lab_ips.add(ip)
                logger.debug(f"Successfully fetched IP ({ip}) for Lab device: {dev_name}")
            else:
                logger.warning(f"Lab device {dev_name} did not return an IP address. Skipping.")
        except Exception as e:
            logger.error(f"Failed to fetch SystemSettings for Lab device '{dev_name}'. Reason: {e}")
            print(f"[WARN] Failed to read settings for Lab device '{dev_name}'. Skipping.")
            continue
            
    print(f"[INFO] IPs fetched from Lab ({len(lab_ips)}):")
    for ip in sorted(lab_ips):
        print("   ", ip)
        
    logger.info("✅ [Stage: %s] Completed Successfully with %d IPs fetched", stage_name, len(lab_ips))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)


# Stage 3 - fetch from PCI 1
stage_name = "Fetch IPs from PCI 1 Palo Alto"
stage_start(stage_name)
pci1_ips = set()
try:
    pci1_pano = Panorama(PCI1_HOST, api_key=PCI1_API_KEY)
    pci1_devices = pci1_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] PCI 1 Panorama devices count: {len(pci1_devices)}")
    logger.info(f"Found {len(pci1_devices)} devices in PCI 1 Panorama.")
    
    for dev in pci1_devices:
        dev_name = getattr(dev, "name", "Unknown_Device")
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None)
            if ip:
                pci1_ips.add(ip)
                logger.debug(f"Successfully fetched IP ({ip}) for PCI 1 device: {dev_name}")
            else:
                logger.warning(f"PCI 1 device {dev_name} did not return an IP address. Skipping.")
        except Exception as e:
            logger.error(f"Failed to fetch SystemSettings for PCI 1 device '{dev_name}'. Reason: {e}")
            print(f"[WARN] Failed to read settings for PCI 1 device '{dev_name}'. Skipping.")
            continue
            
    print(f"[INFO] IPs fetched from PCI 1 ({len(pci1_ips)}):")
    for ip in sorted(pci1_ips):
        print("   ", ip)
        
    logger.info("✅ [Stage: %s] Completed Successfully with %d IPs fetched", stage_name, len(pci1_ips))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)


# Stage 4 - fetch from PCI 2
stage_name = "Fetch IPs from PCI 2 Palo Alto"
stage_start(stage_name)
pci2_ips = set()
try:
    pci2_pano = Panorama(PCI2_HOST, api_key=PCI2_API_KEY)
    pci2_devices = pci2_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] PCI 2 Panorama devices count: {len(pci2_devices)}")
    logger.info(f"Found {len(pci2_devices)} devices in PCI 2 Panorama.")
    
    for dev in pci2_devices:
        dev_name = getattr(dev, "name", "Unknown_Device")
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None)
            if ip:
                pci2_ips.add(ip)
                logger.debug(f"Successfully fetched IP ({ip}) for PCI 2 device: {dev_name}")
            else:
                logger.warning(f"PCI 2 device {dev_name} did not return an IP address. Skipping.")
        except Exception as e:
            logger.error(f"Failed to fetch SystemSettings for PCI 2 device '{dev_name}'. Reason: {e}")
            print(f"[WARN] Failed to read settings for PCI 2 device '{dev_name}'. Skipping.")
            continue
            
    print(f"[INFO] IPs fetched from PCI 2 ({len(pci2_ips)}):")
    for ip in sorted(pci2_ips):
        print("   ", ip)
        
    logger.info("✅ [Stage: %s] Completed Successfully with %d IPs fetched", stage_name, len(pci2_ips))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)


if not overall_ok:
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(3)


# Stage 5 - combine
stage_name = "Combine All IP Addresses (Prod, Lab, PCI 1, PCI 2)"
stage_start(stage_name)
try:
    combined_ips = sorted(set(prod_ips) | set(lab_ips) | set(pci1_ips) | set(pci2_ips))
    print(f"[INFO] Combined unique IP count: {len(combined_ips)}")
    
    logger.info("Final Combined IP List:")
    for ip in combined_ips:
        print("   ", ip)
        logger.info(f" - {ip}")
        
    logger.info("✅ [Stage: %s] Completed Successfully with combined list of %d IPs", stage_name, len(combined_ips))
except Exception as e:
    overall_ok = False
    stage_fail(stage_name, e)


if not overall_ok:
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(4)

# final summary
if overall_ok:
    logger.info("Script completed successfully.")
    print("\nScript Executed Successfully, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    print("\nScript Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(5)