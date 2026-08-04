# Fortinet IP Synchronization Script - Complete Setup Guide

## Overview

This script automates the synchronization of Fortinet firewall IPs from **SolarWinds** and **CMDB Excel** into **Qualys** with automatic segregation to multiple tags.

---

## Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Prepare Your Data Files                                 │
├─────────────────────────────────────────────────────────────────┤
│ 1. fortinet_cmdb_ips.xlsx     (Excel with CMDB IPs)             │
│ 2. tag_assignment_inventory.csv (IP → Tag ID mapping)           │
│ 3. tag_reference.csv           (Tag Name → Tag ID lookup)       │
│ 4. .env                        (Qualys credentials)             │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Run Script                                               │
│ python fortinet_asset_tag_v2.py                                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Script Processing                                        │
├─────────────────────────────────────────────────────────────────┤
│ Stage 1: Fetch IPs from SolarWinds                              │
│ Stage 2: Read CMDB IPs from Excel                               │
│ Stage 3: Merge & Deduplicate IPs                                │
│ Stage 4: Load IP to Tag mapping from CSV                        │
│ Stage 5: Build Tag to IPs mapping                               │
│ Stage 6: Update Qualys Asset Group (all IPs)                    │
│ Stage 7: Update Auth Record (if configured)                     │
│ Stage 8: Update Multiple Qualys Tags (segregated)               │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Results                                                  │
├─────────────────────────────────────────────────────────────────┤
│ ✅ All merged IPs in Asset Group                                │
│ ✅ IPs segregated to multiple tags                              │
│ ✅ Log file: sync_fortinet_qualys_YYYYMMDD_HHMMSS.log          │
└─────────────────────────────────────────────────────────────────┘
```

---

## File Setup Instructions

### 1. **Environment Variables (.env)**

Create a `.env` file in the same directory as the script with:

```env
# SolarWinds Credentials
SOLARWINDS_USERNAME=your_solarwinds_username
SOLARWINDS_PASSWORD=your_solarwinds_password

# Qualys Credentials
QUALYS_USER=your_qualys_username
QUALYS_PASS=your_qualys_password
QUALYS_GROUP_ID=your_asset_group_id

# Optional: Auth Record ID for credential-based scanning
AUTH_RECORD_ID=your_auth_record_id

# Optional: File paths (defaults shown)
CMDB_EXCEL_FILE=fortinet_cmdb_ips.xlsx
TAG_MAPPING_CSV=tag_assignment_inventory.csv
```

---

### 2. **CMDB Excel File** (`fortinet_cmdb_ips.xlsx`)

**Purpose:** Manually enter Fortinet IPs from CMDB that need to be added to Qualys

**Format:**
- **Column A:** IP Address
- Other columns: Optional (Business Unit, Location, Environment, Device Name, Notes)

**Example:**
```
┌──────────────┬──────────────┬──────────┬─────────────┬──────────────────┐
│ IP Address   │ Business Unit│ Location │ Environment │ Device Name      │
├──────────────┼──────────────┼──────────┼─────────────┼──────────────────┤
│ 10.0.1.1     │ Finance      │ US-East  │ PROD        │ FortiGate-FIN-01 │
│ 10.0.1.2     │ Finance      │ US-East  │ PROD        │ FortiGate-FIN-02 │
│ 10.0.2.1     │ Engineering  │ US-West  │ DEV         │ FortiGate-ENG-01 │
│ 10.0.3.1     │ HR           │ EU       │ PROD        │ FortiGate-HR-01  │
└──────────────┴──────────────┴──────────┴─────────────┴──────────────────┘
```

**How to Create:**
1. Open Excel
2. Add header: "IP Address" in A1
3. Add IPs from A2 onwards
4. Save as `fortinet_cmdb_ips.xlsx`

---

### 3. **Tag Assignment Inventory** (`tag_assignment_inventory.csv`)

**Purpose:** Map each IP to its Qualys Tag ID

**Format:**
```csv
IP Address,Qualys Tag ID
10.0.1.1,123456
10.0.1.2,123456
10.0.2.1,123457
10.0.3.1,123458
```

**How it works:**
- Column 1: IP Address (must match IPs from SolarWinds or CMDB)
- Column 2: Qualys Tag ID (the unique ID of the tag in Qualys)

**Important:**
- Get Tag IDs from Qualys Console → Assets → Tags → Note the ID for each tag
- IPs not in this CSV file will be added to Asset Group but NOT to specific tags
- Multiple IPs can map to the same tag

**How to Create:**
1. Open Excel or Notepad
2. Type header: `IP Address,Qualys Tag ID`
3. Add rows: `10.0.1.1,123456`
4. Save as `tag_assignment_inventory.csv` (CSV format, not Excel)

---

### 4. **Tag Reference** (`tag_reference.csv`) - Optional

**Purpose:** Reference document to keep track of Tag Names and their IDs

**Format:**
```csv
TAG_NAME,TAG_ID
PROD_FINANCE,123456
DEV_ENGINEERING,123457
PROD_HR,123458
STAGING_IT,123459
```

**How to Create:**
1. Go to Qualys Console → Assets → Tags
2. Note each tag's Name and ID
3. Create CSV with TAG_NAME and TAG_ID columns
4. Save as `tag_reference.csv`

---

## How to Get Qualys Tag IDs

1. **Login to Qualys Console**
2. Navigate to **Assets → Tags**
3. Look at your existing tags
4. Note the **Tag ID** (usually a number or code)
5. Copy to `tag_assignment_inventory.csv`

Example Qualys Tags:
```
Tag Name              Tag ID
─────────────────────────────
PROD_FINANCE          123456
DEV_ENGINEERING       123457
PROD_HR               123458
STAGING_IT            123459
PROD_NETWORKING       123460
```

---

## Data Flow Example

### **Scenario:**

You have:
- **SolarWinds IPs:** 10.0.1.1, 10.0.1.2, 10.0.4.5
- **CMDB IPs:** 10.0.1.1, 10.0.1.2, 10.0.2.1, 10.0.3.1

### **Step 1: Create CMDB Excel**
```
fortinet_cmdb_ips.xlsx
├─ 10.0.1.1  → Finance
├─ 10.0.1.2  → Finance
├─ 10.0.2.1  → Engineering
└─ 10.0.3.1  → HR
```

### **Step 2: Create Tag Assignment CSV**
```
tag_assignment_inventory.csv
├─ 10.0.1.1 → TAG_ID: 123456 (Finance tag)
├─ 10.0.1.2 → TAG_ID: 123456 (Finance tag)
├─ 10.0.2.1 → TAG_ID: 123457 (Engineering tag)
└─ 10.0.3.1 → TAG_ID: 123458 (HR tag)
Note: 10.0.4.5 from SolarWinds NOT in CSV → Won't go to specific tag
```

### **Step 3: Run Script**
```bash
python fortinet_asset_tag_v2.py
```

### **Step 4: Results in Qualys**

**Asset Group (All IPs):**
- 10.0.1.1 ✅
- 10.0.1.2 ✅
- 10.0.2.1 ✅
- 10.0.3.1 ✅
- 10.0.4.5 ✅ (from SolarWinds)

**TAG_ID 123456 (Finance):**
- 10.0.1.1 ✅
- 10.0.1.2 ✅

**TAG_ID 123457 (Engineering):**
- 10.0.2.1 ✅

**TAG_ID 123458 (HR):**
- 10.0.3.1 ✅

---

## Running the Script

### **Prerequisites:**
```bash
pip install requests urllib3 python-dotenv openpyxl
```

Or the script auto-installs them.

### **Execute:**
```bash
python fortinet_asset_tag_v2.py
```

### **Output:**
- Console output with progress
- Log file: `sync_fortinet_qualys_YYYYMMDD_HHMMSS.log`

### **Example Console Output:**
```
======================================================================
[Stage] Fetch IPs from SolarWinds ⏳ Started
======================================================================
[*] Fetching Fortinet IPs from SolarWinds...
[✅] Found 3 Fortinet IPs in SolarWinds.

======================================================================
[Stage] Read CMDB IPs from Excel ⏳ Started
======================================================================
[*] Reading IPs from Excel: fortinet_cmdb_ips.xlsx...
[✅] Found 4 IPs in CMDB Excel.

======================================================================
[Stage] Merge SolarWinds and CMDB IPs ⏳ Started
======================================================================
[*] SolarWinds IPs: 3
[*] CMDB IPs: 4
[*] Common IPs: 2
[*] New from CMDB: 2
[*] New from SolarWinds: 1
[✅] Total merged IPs: 5

[... more stages ...]

======================================================================
[📊] FINAL SUMMARY:
    SolarWinds IPs fetched: 3
    CMDB IPs read: 4
    Total merged IPs: 5
    Asset Group 12345: Updated with 5 IPs
    Asset Tags updated: 3
======================================================================

✅ Script Execution Successfully! Please check the log file for details.
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Excel file not found" | Check `CMDB_EXCEL_FILE` path in `.env` |
| "CSV file not found" | Check `TAG_MAPPING_CSV` path in `.env` |
| "No tag mappings found" | Ensure CSV has correct header: `IP Address,Qualys Tag ID` |
| "Tag update failed: HTTP 401" | Check Qualys credentials in `.env` |
| "Unmapped IPs" | IPs from SolarWinds not in CSV - add them to CSV if needed |
| "Connection timeout" | Check network, Qualys API endpoint is reachable |

---

## File Checklist Before Running

- [ ] `.env` file created with credentials
- [ ] `fortinet_cmdb_ips.xlsx` created with IPs
- [ ] `tag_assignment_inventory.csv` created with IP→Tag mappings
- [ ] `tag_reference.csv` created (optional, for reference)
- [ ] All files in same directory as script
- [ ] Python 3.6+ installed
- [ ] Required packages: `requests`, `urllib3`, `python-dotenv`, `openpyxl`

---

## Log File Location

After running, check the log file for detailed output:

```
sync_fortinet_qualys_20260804_125330.log
```

This file contains:
- Detailed stage-by-stage execution
- All IPs fetched, merged, mapped
- API response codes
- Any errors with full traceback

---

## Support

For issues:
1. Check the log file first
2. Verify file formats and paths
3. Confirm Qualys credentials and permissions
4. Ensure tag IDs exist in Qualys Console
