#!/usr/bin/env python3

import os
import sys
import json
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

try:
    import requests
    from dotenv import load_dotenv
except ImportError:
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        "requests", "python-dotenv"
    ])
    import requests
    from dotenv import load_dotenv

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

FMG_URL = os.getenv("FMG_URL", "").rstrip("/")
API_KEY = os.getenv("FMG_API_KEY", "")

DATE = datetime.now().strftime("%Y%m%d")
OUTPUT = Path("output")
OUTPUT.mkdir(exist_ok=True)

IP_FILE = OUTPUT / f"fortinet_ip_{DATE}.txt"
LOG_FILE = OUTPUT / f"fortinet_inventory_{DATE}.log"


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
        "params": [{"url": url}]
    }

    response = requests.post(
        f"{FMG_URL}/jsonrpc",
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        },
        json=payload,
        verify=False,
        timeout=60
    )

    response.raise_for_status()
    result = response.json()

    # Save raw API response in log
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n")
        f.write(f"RAW API RESPONSE: {url}\n")
        f.write(json.dumps(result, indent=2))
        f.write("\n\n")

    if "result" not in result:
        raise Exception("Invalid FortiManager API response")

    result = result["result"][0]

    status = result.get("status", {})
    if status.get("code") not in (0, None):
        raise Exception(
            f"FortiManager API error: {status.get('message')}"
        )

    return result.get("data", [])


def get_ip(device):
    for field in ("ip", "ip_address", "mgmt_ip", "management_ip"):
        value = device.get(field)

        try:
            ip = ipaddress.ip_address(str(value))
            if ip.version == 4:
                return str(ip)
        except ValueError:
            pass

    return None


def device_type(device):
    text = " ".join(
        str(device.get(x, "")).lower()
        for x in (
            "platform",
            "platform_str",
            "type",
            "device_type",
            "devtype",
            "model",
            "name",
            "hostname"
        )
    )

    if "fortianalyzer" in text or "forti analyzer" in text:
        return "FORTIANALYZER"

    if "fortimanager" in text or "forti manager" in text:
        return "FORTIMANAGER"

    return "FORTIGATE"


def main():

    if not FMG_URL:
        print("SCRIPT FAILED - FMG_URL is missing")
        return 1

    if not API_KEY:
        print("SCRIPT FAILED - FMG_API_KEY is missing")
        return 1

    try:
        log("Script started")
        log(f"FortiManager: {FMG_URL}")

        fortigate = set()
        fortimanager = set()
        fortianalyzer = set()

        # FortiManager itself
        hostname = FMG_URL.split("//")[-1].split("/")[0].split(":")[0]

        try:
            ipaddress.ip_address(hostname)
            fortimanager.add(hostname)
            log(f"FORTIMANAGER: {hostname}")
        except ValueError:
            pass

        # Get ADOMs
        log("Getting ADOMs...")
        adoms = api_call("/dvmdb/adom")

        if isinstance(adoms, dict):
            adoms = [adoms]

        total_devices = 0

        for adom in adoms:

            name = (
                adom.get("name")
                or adom.get("adom")
                or adom.get("adom_name")
            )

            if not name:
                continue

            log(f"Processing ADOM: {name}")

            devices = api_call(
                f"/dvmdb/adom/{quote(name, safe='')}/device"
            )

            if isinstance(devices, dict):
                devices = [devices]

            for device in devices:

                if not isinstance(device, dict):
                    continue

                total_devices += 1

                hostname = (
                    device.get("name")
                    or device.get("hostname")
                    or "UNKNOWN"
                )

                ip = get_ip(device)

                if not ip:
                    log(f"No IP found: {hostname}")
                    continue

                dtype = device_type(device)

                log(f"{dtype}: {hostname} - {ip}")

                if dtype == "FORTIANALYZER":
                    fortianalyzer.add(ip)
                elif dtype == "FORTIMANAGER":
                    fortimanager.add(ip)
                else:
                    fortigate.add(ip)

        # Write IP file
        with open(IP_FILE, "w", encoding="utf-8") as f:

            for title, addresses in (
                ("FORTIGATE DEVICES", fortigate),
                ("FORTIMANAGER DEVICES", fortimanager),
                ("FORTIANALYZER DEVICES", fortianalyzer)
            ):
                f.write("=" * 40 + "\n")
                f.write(title + "\n")
                f.write("=" * 40 + "\n\n")

                for ip in sorted(
                    addresses,
                    key=lambda x: int(ipaddress.ip_address(x))
                ):
                    f.write(ip + "\n")

                f.write("\n")

        log(f"Total devices: {total_devices}")
        log(f"FortiGate IPs: {len(fortigate)}")
        log(f"FortiManager IPs: {len(fortimanager)}")
        log(f"FortiAnalyzer IPs: {len(fortianalyzer)}")
        log(f"IP file: {IP_FILE}")

        if total_devices == 0:
            raise Exception("No managed devices returned by FortiManager")

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
