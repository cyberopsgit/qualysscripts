#!/usr/bin/env python3

import ipaddress
import os
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse

# ---------------------------------------------------------------------------
# Auto-install dependencies
# ---------------------------------------------------------------------------
try:
    import requests
    from dotenv import load_dotenv
except ImportError:
    cmd = [sys.executable, "-m", "pip", "install", "requests", "python-dotenv"]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        subprocess.check_call(cmd + ["--break-system-packages"])
    import requests
    from dotenv import load_dotenv

import urllib3

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", encoding="utf-8-sig")

FMG_URL = os.getenv("FMG_URL", "").strip().rstrip("/")
API_KEY = os.getenv("FMG_API_KEY", "").strip()
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").strip().lower() == "true"

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT = BASE_DIR / "output"
OUTPUT.mkdir(exist_ok=True)

IP_FILE = OUTPUT / f"fortinet_ip_{STAMP}.txt"
LOG_FILE = OUTPUT / f"fortinet_inventory_{STAMP}.log"


def log(message):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} - {message}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def api_call(url):
    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "get",
        "params": [{"url": url}],
    }

    response = requests.post(
        f"{FMG_URL}/jsonrpc",
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
        json=payload,
        verify=VERIFY_SSL,
        timeout=60,
    )
    response.raise_for_status()
    body = response.json()

    if "result" not in body or not body["result"]:
        raise RuntimeError(f"Invalid FortiManager API response for {url}")

    result = body["result"][0]
    status = result.get("status", {})
    if status.get("code") not in (0, None):
        raise RuntimeError(
            f"FortiManager API error on {url}: "
            f"{status.get('code')} {status.get('message')}"
        )

    data = result.get("data", [])
    if isinstance(data, dict):
        data = [data]

    # Log only the URL and record count (raw data may contain sensitive fields)
    log(f"API {url} -> {len(data)} record(s)")
    return data


def get_ip(device):
    for field in ("ip", "ip_address", "mgmt_ip", "management_ip"):
        value = device.get(field)
        if not value:
            continue
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_unspecified:
            return str(ip)
    return None


def device_type(device):
    platform = str(device.get("platform_str", "")).lower()
    serial = str(device.get("sn", "")).upper()

    if platform.startswith("fortigate") or platform.startswith("fortiwifi"):
        return "FORTIGATE"
    if platform.startswith("fortianalyzer"):
        return "FORTIANALYZER"
    if platform.startswith("fortimanager"):
        return "FORTIMANAGER"

    # Fallback to serial number prefix when platform is empty
    if serial.startswith(("FAZ",)):
        return "FORTIANALYZER"
    if serial.startswith(("FMG", "FMGVM")):
        return "FORTIMANAGER"
    if serial.startswith(("FG", "FW")):
        return "FORTIGATE"

    return "OTHER"


def fmg_host_ip():
    host = urlparse(FMG_URL).hostname or ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def main():
    log("Script started")

    try:
        if not FMG_URL:
            raise RuntimeError("FMG_URL is missing in .env")
        if not API_KEY:
            raise RuntimeError("FMG_API_KEY is missing in .env")

        log(f"FortiManager: {FMG_URL}")
        log(f"SSL verification: {VERIFY_SSL}")

        groups = {
            "FORTIGATE": set(),
            "FORTIMANAGER": set(),
            "FORTIANALYZER": set(),
            "OTHER": set(),
        }

        fmg_ip = fmg_host_ip()
        if fmg_ip:
            groups["FORTIMANAGER"].add(fmg_ip)
            log(f"FORTIMANAGER (self): {fmg_ip}")
        else:
            log("Could not determine FortiManager's own IP from FMG_URL")

        log("Getting ADOMs...")
        adoms = api_call("/dvmdb/adom")

        total_devices = 0
        seen = set()

        for adom in adoms:
            adom_name = adom.get("name")
            if not adom_name:
                continue

            log(f"Processing ADOM: {adom_name}")

            try:
                devices = api_call(f"/dvmdb/adom/{quote(adom_name, safe='')}/device")
            except Exception as e:
                log(f"WARNING: skipped ADOM {adom_name}: {e}")
                continue

            for device in devices:
                if not isinstance(device, dict):
                    continue

                dev_name = device.get("name") or device.get("hostname") or "UNKNOWN"
                key = (dev_name, device.get("sn", ""))
                if key in seen:
                    continue
                seen.add(key)
                total_devices += 1

                ip = get_ip(device)
                if not ip:
                    log(f"No valid IP found: {dev_name}")
                    continue

                dtype = device_type(device)
                log(f"{dtype}: {dev_name} - {ip}")
                groups[dtype].add(ip)

        if total_devices == 0:
            raise RuntimeError("No managed devices returned by FortiManager")

        with open(IP_FILE, "w", encoding="utf-8") as f:
            for title, key in (
                ("FORTIGATE DEVICES", "FORTIGATE"),
                ("FORTIMANAGER DEVICES", "FORTIMANAGER"),
                ("FORTIANALYZER DEVICES", "FORTIANALYZER"),
                ("OTHER DEVICES", "OTHER"),
            ):
                f.write("=" * 40 + "\n")
                f.write(title + "\n")
                f.write("=" * 40 + "\n\n")
                for ip in sorted(groups[key], key=lambda x: int(ipaddress.ip_address(x))):
                    f.write(ip + "\n")
                f.write("\n")

        log(f"Total devices: {total_devices}")
        for key, addrs in groups.items():
            log(f"{key} IPs: {len(addrs)}")
        log(f"IP file: {IP_FILE}")
        log("SCRIPT COMPLETED SUCCESSFULLY")

        print("\n========================================")
        print("SCRIPT COMPLETED SUCCESSFULLY")
        print("========================================")
        print(f"IP file : {IP_FILE}")
        print(f"Log file: {LOG_FILE}")
        return 0

    except Exception as e:
        log(f"SCRIPT FAILED - {e}")

        print("\n========================================")
        print("SCRIPT FAILED")
        print("========================================")
        print(f"Error: {e}")
        print(f"Log file: {LOG_FILE}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
