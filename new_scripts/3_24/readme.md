Here is a comprehensive breakdown of the script formatted specifically so you can copy and paste it directly into your README.md file.

Qualys Bulk Authentication Record Updater
Overview
This Python script automates the process of bulk updating IP addresses across various Qualys Authentication Records (Unix, Windows, Oracle, Cisco). Instead of manually updating records one by one in the Qualys UI, this script reads target IDs and IP addresses from a standard Excel spreadsheet and pushes the updates via the Qualys v3.0 API.

Key Features
Auto-Dependency Management: Automatically checks for and installs required Python libraries (requests, python-dotenv, pandas, openpyxl) if they are missing.

Excel-Driven: Reads configuration from an Excel sheet, making it easy to manage large batches of updates. It handles case-insensitive column headers and skips blank rows automatically.

Dynamic Endpoint Routing: Automatically determines the correct Qualys API endpoint based on the "Record Type" specified in the spreadsheet.

Enterprise Environment Ready: Includes built-in SSL verification bypass (verify=False) to operate seamlessly behind corporate proxies or firewalls that perform SSL inspection.

Robust Logging: Outputs a clean, high-level summary to the terminal while writing deep, granular debug data (including exact API responses) to a timestamped .log file.

Prerequisites
Python 3.x installed on your machine.

Network access to https://qualysapi.qualys.com.

Configuration & Setup
1. The .env File

Create a file named exactly .env in the same directory as the script. This keeps your credentials secure and out of the source code.

Code snippet
# Qualys API Credentials
QUALYS_USERNAME="your_qualys_username"
QUALYS_PASSWORD="your_qualys_password"

# The exact filename of your tracking spreadsheet
EXCEL_FILE="qualys_records.xlsx"
2. The Excel Spreadsheet

Create an Excel file matching the name specified in your .env file. The script requires the following three columns (header names are case-insensitive):

Authentication ID	IP Address	Record Type
12345	10.10.10.1, 10.10.10.2	Oracle
67890	192.168.1.50	Unix
11223	172.16.0.5, 172.16.0.6	Windows
Authentication ID: The unique ID of the record found in Qualys.

IP Address: A single IP or a comma-separated list of IPs to apply to the record. (Note: This overwrites the existing IPs on the record).

Record Type: Must be unix, windows, oracle, or cisco.

How the Script Works (Execution Flow)
Initialization: The script loads variables from the .env file and sets up the logging mechanism. It suppresses insecure request warnings to keep the terminal output clean.

Stage 1: Parse Excel Data: It reads the specified Excel file using pandas. It validates that the required columns exist, normalizes the headers, and counts the total number of records to process.

Stage 2: Process & Update: * The script iterates through each row of the spreadsheet.

It cleans up formatting (e.g., stripping accidental spaces around IPs).

It maps the Record Type to the specific Qualys v3.0 API endpoint.

It sends a POST request with the action=update, ids, and ips payload to Qualys.

Summary & Teardown: Upon completion, it prints a success/failure summary to the terminal and exits with a standard status code (0 for perfect success, 6 if any rows failed).

Execution
To run the script, open your terminal or command prompt, navigate to the folder containing the script, and execute:

Bash
python your_script_name.py
Logging and Troubleshooting
Every time the script runs, it generates a log file in the same directory (e.g., qualys_bulk_update_20260324_153000.log).

Terminal Output: Shows which stages are starting and a simple ✅ Success or ❌ Failed for each row.

Log File: If a row fails, open the .log file to see the exact HTTP status code and XML error message returned by the Qualys API for that specific ID.
