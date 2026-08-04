# Fortinet Asset Tag Script Explanation

## Overview

This Python script synchronizes Fortinet firewall IP addresses from **SolarWinds** (a network monitoring tool) to **Qualys** (a vulnerability management platform). It automates the process of keeping asset lists in sync across two systems.

## High-Level Flow

1. **Auto-install dependencies** — Ensures required packages (`requests`, `urllib3`, `python-dotenv`) are installed
2. **Fetch IPs from SolarWinds** — Queries for all Fortinet devices
3. **Clear old IPs from Qualys** — Removes existing IPs from an Asset Group
4. **Add new IPs to Qualys** — Uploads the fresh SolarWinds IP list
5. **Update Auth Records** — (Optional) Syncs IPs to a Qualys authentication record
6. **Update Asset Tags** — (Optional) Syncs IPs to a Qualys asset tag using QPS API

---

## Detailed Breakdown

### Setup & Configuration

- **Environment variables** loaded from `.env` file for credentials:
  - `SOLARWINDS_USERNAME`, `SOLARWINDS_PASSWORD`
  - `QUALYS_USER`, `QUALYS_PASS`, `QUALYS_GROUP_ID`
  - `AUTH_RECORD_ID` (optional)
  - `QUALYS_TAG_ID` (optional)
  
- **Logging** — Creates timestamped log files (`sync_solarwinds_qualys_YYYYMMDD_HHMMSS.log`)
  
- **SSL warnings suppressed** — Allows `verify=False` for self-signed certificates

### Stage 1: Fetch from SolarWinds

**Query:**
```sql
SELECT IPAddress FROM Orion.Nodes WHERE Vendor LIKE '%Fortinet%'
```

**Process:**
- POSTs a query to SolarWinds API endpoint: `https://solarwinds.int.ally.com:17774/SolarWinds/InformationService/v3/Json/Query`
- Extracts IP addresses from the response
- Deduplicates and sorts the list
- Exits with error code `3` if fetch fails

**Output:** List of unique Fortinet IPs from SolarWinds

---

### Stage 2: Clear Qualys Asset Group

**Purpose:** Remove all existing IPs from the target Qualys asset group before adding new ones

**Action:**
- Sends an "edit" request to Qualys API
- Sets `set_ips` field to empty string to clear existing inventory
- Endpoint: `https://qualysapi.qualys.com/api/2.0/fo/asset/group/`

**Validation:** Checks for HTTP 200 response

---

### Stage 3: Add IPs to Qualys Asset Group

**Purpose:** Core synchronization step—upload the latest IPs from SolarWinds

**Process:**
- Joins all fetched IPs with commas (CSV format)
- POSTs them to Qualys API to update the asset group
- Endpoint: `https://qualysapi.qualys.com/api/2.0/fo/asset/group/`
- Uses basic auth with Qualys credentials

**Success Indicator:** HTTP 200 response confirms all IPs were added

---

### Stage 4: Update Qualys Authentication Record (Optional)

**Condition:** Only runs if `AUTH_RECORD_ID` is provided and IPs were fetched

**Purpose:** Update credentials/IP list in a Qualys authentication profile for automated scanning

**Details:**
- Endpoint: `https://qualysapi.qualys.com/api/2.0/fo/auth/unix/`
- Action: `update` with comma-separated IP list
- Timeout: 120 seconds

---

### Stage 5: Update Qualys Asset Tag (Optional)

**Condition:** Only runs if `QUALYS_TAG_ID` is provided and IPs were fetched

**Purpose:** Sync IPs to a Qualys static IP tag rule using QPS (XML-based) API

**Details:**
- Endpoint: `https://qualysapi.qualys.com/qps/rest/2.0/update/am/tag/{QUALYS_TAG_ID}`
- Payload format: XML with `ruleType: STATIC` and `ruleText` containing comma-separated IPs
- Headers: `Content-Type: text/xml`
- Timeout: 120 seconds

---

## Error Handling

- **Independent stage failures** — Each stage can fail without stopping subsequent stages
- **overall_ok flag** — Tracks if any stage failed during execution
- **Exit codes:**
  - `0` = ✅ All stages completed successfully
  - `2` = ❌ Missing required environment variables
  - `3` = ❌ SolarWinds fetch error
  - `5` = ❌ Qualys asset group clear error
  - `7` = ❌ General script failure (one or more stages failed)

- **Logging** — All errors logged to file with full traceback

---

## Key Design Patterns

### Defensive Imports
```python
for package in required_packages:
    try:
        __import__(import_name)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
```
Automatically installs missing dependencies to prevent ImportError crashes.

### Detailed Logging
- All actions logged to file while printing summary to console
- Enables troubleshooting even if script runs in background
- Timestamped log filenames prevent overwrites

### SSL Certificate Handling
- Uses `verify=False` to allow self-signed certificates on internal endpoints
- Suppresses urllib3 warnings with `urllib3.disable_warnings()`

### Timeout Protection
- Short timeouts (60-120 seconds) on API calls prevent indefinite hangs
- Helps script fail fast on network issues

---

## Use Case

**Automated nightly/periodic sync** to ensure Qualys vulnerability scans target the latest Fortinet infrastructure discovered by SolarWinds.

### Typical Workflow
1. SolarWinds discovers new Fortinet devices or removes old ones
2. Script runs on schedule (cron/Task Scheduler)
3. Latest IP list fetched and validated
4. Qualys asset group, auth records, and tags updated automatically
5. Next Qualys scan uses updated asset inventory

---

## Environment Variables Required

| Variable | Purpose | Required |
|----------|---------|----------|
| `SOLARWINDS_USERNAME` | SolarWinds API auth | ✅ Yes |
| `SOLARWINDS_PASSWORD` | SolarWinds API auth | ✅ Yes |
| `QUALYS_USER` | Qualys API auth | ✅ Yes |
| `QUALYS_PASS` | Qualys API auth | ✅ Yes |
| `QUALYS_GROUP_ID` | Target asset group ID | ✅ Yes |
| `AUTH_RECORD_ID` | Qualys auth record ID | ⚠️ Optional |
| `QUALYS_TAG_ID` | Qualys asset tag ID | ⚠️ Optional |

Create a `.env` file in the script directory with these variables.

---

## Dependencies

- `requests` — HTTP library for API calls
- `urllib3` — SSL/HTTPS support
- `python-dotenv` — Load environment variables from `.env` file

All installed automatically by the script if missing.
