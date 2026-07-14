import os
import sys
import traceback
from datetime import datetime
from panos.panorama import Panorama
from panos.device import SystemSettings
from dotenv import load_dotenv
import logging
import urllib3

# Load .env file
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------
# Logging & Output Setup
# ---------------------------
date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"extraction_log_{date_str}.log"
ip_output_filename = f"palo_alto_ips_{date_str}.txt"

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

logger.info(f"Logging initialized. Execution log: {os.path.abspath(log_filename)}")

# ---------------------------
# Helper Functions
# ---------------------------
def stage_start(name):
    print("\n" + "="*70)
    print(f"[*] {name}")
    print("="*70)

def fetch_ips_from_host(host, api_key, label):
    """Connect to a single Panorama host and return a set of device IPs discovered."""
    ips = set()
    if not host or not api_key:
        logger.info("Skipping %s because host or api_key not provided", label)
        return ips
    
    try:
        print(f"[+] Connecting to Panorama {host} ({label})")
        pano = Panorama(host, api_key=api_key)
        devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
        print(f"    -> Devices found: {len(devices)}")
        
        fetched = 0
        for dev in devices:
            try:
                ss = dev.find("", SystemSettings)
                ip = getattr(ss, "ip_address", None)
                if ip:
                    ips.add(ip)
                    fetched += 1
            except Exception as e:
                logger.warning("Device read failed on %s: %s", host, str(e))
                
        logger.info("Host %s (%s) fetched %d IPs", host, label, fetched)
    except Exception as e:
        print(f"[ERROR] Failed to connect or fetch devices from {host} ({label}): {e}")
        logger.error("Panorama host %s (%s) failed: %s\n%s", host, label, str(e), traceback.format_exc())
        
    return ips

# ---------------------------
# Main Execution: Fetch IPs
# ---------------------------
stage_start("Extracting IPs from configured Palo Alto Panorama hosts")

all_ips = set()
ips_by_env = {}
overall_ok = True

try:
    # Define your environments here matching your .env file
    hosts = [
        (os.getenv("PALO_PROD_HOST"), os.getenv("PALO_PROD_API_KEY"), "PROD"),
        (os.getenv("LAB_HOST"), os.getenv("LAB_API_KEY"), "LAB"),
        (os.getenv("PCI1_HOST"), os.getenv("PCI1_API_KEY"), "PCI1"),
        (os.getenv("PCI2_HOST"), os.getenv("PCI2_API_KEY"), "PCI2"),
    ]

    used_hosts = [h for h in hosts if h[0] and h[1]]
    if not used_hosts:
        print("[WARN] No Panorama hosts with both host and API key provided in .env.", file=ORIGINAL_STDOUT)
        raise RuntimeError("No Panorama hosts configured")

    # Fetch IPs for each configured host
    for host, key, label in used_hosts:
        env_ips = fetch_ips_from_host(host, key, label)
        if env_ips:
            ips_by_env[label] = sorted(env_ips)
            all_ips |= env_ips

    print(f"\n[INFO] Extraction complete. Total unique IPs: {len(all_ips)}")
    logger.info("Successfully fetched %d total IPs", len(all_ips))
    
    if not all_ips:
        print("[WARN] No IPs were found across any configured panoramas.", file=ORIGINAL_STDOUT)
        sys.exit(0)

    # Write IPs to the dedicated output file
    with open(ip_output_filename, "w") as f:
        f.write(f"Palo Alto IPs Extracted on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        
        for env, ips in ips_by_env.items():
            f.write(f"--- {env} ({len(ips)} IPs) ---\n")
            for ip in ips:
                f.write(f"{ip}\n")
            f.write("\n")
            
        f.write(f"--- COMBINED UNIQUE LIST ({len(all_ips)} IPs) ---\n")
        for ip in sorted(all_ips):
            f.write(f"{ip}\n")
            
    print(f"[INFO] IP List saved to: {os.path.abspath(ip_output_filename)}", file=ORIGINAL_STDOUT)
    print(f"[INFO] Execution log saved to: {os.path.abspath(log_filename)}", file=ORIGINAL_STDOUT)

except Exception as e:
    overall_ok = False
    print(f"â Critical Failure â {e}")
    logger.error(traceback.format_exc())

# Final Summary
if overall_ok:
    logger.info("Script completed successfully.")
    sys.exit(0)
else:
    logger.error("Script completed with failures.")
    sys.exit(1)