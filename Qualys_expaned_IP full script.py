#!/usr/bin/env python3
"""
Simple script — minimal changes, follows your original style.
Purpose:
 - Fetch IP addresses from Panorama / Palo Alto devices
 - Ensure a Qualys Asset Group contains exactly those IPs:
     * Remove any IPs in the Qualys group that are not in Palo Alto
     * Add any missing Palo Alto IPs to Qualys
 - Supports Qualys returning single IPs, CIDR (e.g. 10.0.0.0/24) or dash ranges (e.g. 10.0.0.1-10.0.0.255)
 - Expands ranges into individual IPs for exact comparison (with a safety limit)

Keep backups before running this against production Qualys groups (removals are destructive).
"""

import os
import requests
import xml.etree.ElementTree as ET
import ipaddress                    # <<< CHANGED: to validate/expand IPs
from panos.panorama import Panorama

# -------------------------
# Config (from environment)
# -------------------------
PALO_HOST = os.getenv("PALO_HOST", "10.43.206.92")
PALO_API_KEY = os.getenv("PALO_API_KEY", "")

QUALYS_USER = os.getenv("QUALYS_USER", "")
QUALYS_PASS = os.getenv("QUALYS_PASS", "")
QUALYS_GROUP_ID = os.getenv("QUALYS_GROUP_ID", "")

# Small behavior knobs (change via env if needed)
BATCH_SIZE = int(os.getenv("QUALYS_BATCH_SIZE", "200"))         # batch size for add/remove calls
MAX_EXPAND = int(os.getenv("MAX_QUALYS_EXPAND", "10000"))      # safety limit for expanding ranges

QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"

# -------------------------
# Helpers for expanding & validating Qualys entries
# -------------------------
def expand_dash_range(start_ip, end_ip):
    """Expand dash-range start_ip-end_ip into list of IP strings.
       Raises ValueError on invalid ranges or on ranges > MAX_EXPAND."""
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    if start.version != end.version:
        raise ValueError("Range endpoints must be same IP version")
    if int(end) < int(start):
        raise ValueError("Range end is smaller than start")
    size = int(end) - int(start) + 1
    if size > MAX_EXPAND:
        raise ValueError(f"Range too large ({size} > {MAX_EXPAND})")
    return [str(ipaddress.ip_address(n)) for n in range(int(start), int(end) + 1)]

def normalize_qualys_entry(entry):
    """
    Accepts: "1.2.3.4", "10.0.0.0/24", "10.0.0.1-10.0.0.255"
    Returns: list of individual IP strings (may be empty)
    Raises ValueError for bad input or too-large expansions.
    """
    entry = entry.strip()
    if not entry:
        return []

    # CIDR
    if '/' in entry:
        try:
            net = ipaddress.ip_network(entry.strip(), strict=False)
        except Exception as e:
            raise ValueError(f"Invalid CIDR '{entry}': {e}")
        size = net.num_addresses
        if size > MAX_EXPAND:
            raise ValueError(f"CIDR {entry} expands to {size} addresses exceeding MAX_EXPAND={MAX_EXPAND}")
        # list(net) produces all addresses (works for /32 too). Be careful: checked size above.
        return [str(ip) for ip in list(net)]

    # Dash-range (allow spaces around dash)
    if '-' in entry:
        parts = entry.split('-')
        if len(parts) != 2:
            raise ValueError(f"Invalid range format: {entry}")
        start = parts[0].strip()
        end = parts[1].strip()
        return expand_dash_range(start, end)

    # Single IP
    try:
        ip = ipaddress.ip_address(entry)
        return [str(ip)]
    except Exception:
        raise ValueError(f"Invalid IP entry: {entry}")

# -------------------------
# Stage 1: Fetch Palo Alto IPs (keeps original logic)
# -------------------------
print("Connecting to Panorama:", PALO_HOST)
pano = Panorama(PALO_HOST, "", "", PALO_API_KEY)

devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)

palo_ips = set()
for device in devices:
    try:
        # Try to get SystemSettings similar to your original script (keeps it simple)
        try:
            sys_settings = device.find("", "SystemSettings")
        except Exception:
            sys_settings = None

        dev_ip = None
        if sys_settings is not None:
            dev_ip = getattr(sys_settings, "ip_address", None) or getattr(sys_settings, "ip", None)

        if not dev_ip:
            # fallback to common attributes
            dev_ip = getattr(device, "ip_address", None) or getattr(device, "address", None) or getattr(device, "management_ip", None)

        if dev_ip:
            palo_ips.add(str(dev_ip).strip())
        else:
            # keep behavior simple
            print("No IP found for one device; skipping.")
    except Exception as e:
        print("Exception reading device (continuing):", e)
        continue

print("Palo Alto IPs collected (count={}):".format(len(palo_ips)))

# -------------------------
# Stage 2: Fetch Qualys group entries and expand into individual IPs
# -------------------------
print("\nFetching Qualys group entries...")

qualys_ips = []    # will store individual IP strings after expansion

list_data = {
    "action": "list",
    "ids": QUALYS_GROUP_ID
}

try:
    resp = requests.post(QUALYS_URL, data=list_data, auth=(QUALYS_USER, QUALYS_PASS))
    if resp.status_code != 200:
        print("Qualys returned non-200 status:", resp.status_code)
        print(resp.text[:500])
        raise SystemExit(1)

    root = ET.fromstring(resp.text)
    # Qualys returns <IP> nodes; they might be single IPs, CIDRs, or dash-ranges
    ip_nodes = root.findall(".//IP")
    for ipn in ip_nodes:
        if ipn is None or not ipn.text:
            continue
        raw = ipn.text.strip()
        try:
            expanded = normalize_qualys_entry(raw)
            for e in expanded:
                qualys_ips.append(e)
        except ValueError as ve:
            # Simple behavior: skip invalid/too-large entries and print a message
            print(f"Skipping Qualys entry '{raw}': {ve}")
            continue
except Exception as e:
    print("Exception while fetching/parsing Qualys group:", e)
    raise SystemExit(1)

qualys_ips = set(qualys_ips)
print("Qualys (expanded) IPs collected (count={}):".format(len(qualys_ips)))

# -------------------------
# Stage 3: Sync Qualys group to exactly match Palo Alto IPs (minimal changes)
# -------------------------
print("\nSyncing Qualys group to match Panorama IPs exactly...")

# Normalize sets
palo_ips = {ip.strip() for ip in palo_ips if ip and ip.strip()}
qualys_ips = {ip.strip() for ip in qualys_ips if ip and ip.strip()}

to_add = sorted(list(palo_ips - qualys_ips))
to_remove = sorted(list(qualys_ips - palo_ips))

if not to_add and not to_remove:
    print("Qualys group already exactly matches Palo Alto IPs — nothing to change.")
else:
    print("IPs to add ({}): {}".format(len(to_add), to_add))
    print("IPs to remove ({}): {}".format(len(to_remove), to_remove))

    # Remove extras first (batched)
    if to_remove:
        for i in range(0, len(to_remove), BATCH_SIZE):
            batch = to_remove[i:i+BATCH_SIZE]
            remove_data = {
                "action": "edit",
                "id": QUALYS_GROUP_ID,
                "remove_ips": ",".join(batch)   # <<< CHANGED: remove param analogous to add_ips
            }
            try:
                r = requests.post(QUALYS_URL, data=remove_data, auth=(QUALYS_USER, QUALYS_PASS))
                print("Removed batch status:", r.status_code)
                print("Remove response (truncated):", r.text[:400])
            except Exception as e:
                print("Exception while removing batch:", e)
                # continue with next batch

    # Add missing IPs (batched)
    if to_add:
        for i in range(0, len(to_add), BATCH_SIZE):
            batch = to_add[i:i+BATCH_SIZE]
            add_data = {
                "action": "edit",
                "id": QUALYS_GROUP_ID,
                "add_ips": ",".join(batch)
            }
            try:
                r = requests.post(QUALYS_URL, data=add_data, auth=(QUALYS_USER, QUALYS_PASS))
                print("Added batch status:", r.status_code)
                print("Add response (truncated):", r.text[:400])
            except Exception as e:
                print("Exception while adding batch:", e)
                # continue with next batch

    print("Sync complete — Qualys group should now match Palo Alto IPs.")

# -------------------------
# Done
# -------------------------
print("\nDone.")