# Event Log Threat Hunter

## Purpose
This PowerShell script analyzes the Windows Security Event Log for signs of brute-force attacks by detecting high numbers of failed logon attempts (Event ID 4625).

## Security+ Objectives Demonstrated
- **2.2** – Identify indicators of malicious activity (brute-force, credential stuffing)
- **4.1** – Implement logging and monitoring (event log analysis)

## Features
- Filters Security log for failed logons (Event ID 4625)
- Groups by target username and source IP
- Flags accounts/IPs exceeding a threshold (default: 10 failed attempts in 24 hours)
- Exports results to CSV report
- Configurable time range and threshold

## How to Run
1. Open PowerShell as Administrator (some events require elevated privileges)
2. Run: `.\EventLogAnalyzer.ps1 -Hours 24 -Threshold 10`

## Sample Output
(See screenshots in this folder once added)
