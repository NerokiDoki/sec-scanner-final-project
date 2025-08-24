# 🛡️ Final project: Network Security Scan & Vulnerability Report Script 
## ⚠️ **Disclaimer**:  
This script is provided **for educational purposes only**.  
Do not use it on networks or systems you do not own or have explicit authorization to test. Unauthorized use may be illegal.

## 📌 Features  
###  📑Overview
This Bash script automates a **basic security scan** of a target IP or domain.  
It performs the following tasks:
-   Detects **open ports and running services** using `nmap`.
-   Checks for **potential vulnerabilities** in common services (Apache, OpenSSH, MySQL, PostgreSQL, Microsoft-IIS, FTP, Samba, Redis, Docker, etc.).
-   Queries the **NVD (National Vulnerability Database)** for known CVEs.
-   Provides **remediation recommendations**.
-   Generates both a **text report** and an **HTML report**.
- --
 ### 🎯 Target Input  
- Accepts a target IP or domain as a command-line argument.  
- Validates format for IPv4 addresses and domains.  
---
### 🔍 Port and Service Scanning  
- Uses **nmap** with service/version detection (`-sV`) to identify open ports.  
- Detects common services such as:  
  - **Web servers:** Apache, Nginx, Microsoft-IIS, Tomcat 
  - **Databases:** MySQL, PostgreSQL, MongoDB, Redis  
  - **Remote access:** OpenSSH, Telnet  
  - **File servers:** Samba, VSFTPD, ProFTPD  
  - **Applications:** PHP, Docker  
---
### 🛡️ Vulnerability Identification  
- Uses **nmap NSE scripts** (`--script vuln`) to detect known vulnerabilities.  
- Cross-references each detected service with the **NVD API**.  
- Limits maximum reported vulnerabilities to **16 unique services**.    
----
### 📑 Report Generation  
- Generates **Text** and **HTML reports**.  
- Includes:  
  - Target information  
  - Open ports and running services  
  - Detected vulnerabilities  
  - Recommended remediation actions  
- Provides **live feedback** in the terminal during scanning and report generation.  
---
### 🛠️ Remediation Recommendations  
- Pulls actionable guidance from **NVD** when available.  
- Provides general security recommendations if no vulnerabilities are found.  

----------
## ⚙️ Requirements

If you don’t use the quick start, manually install:
-   **Linux/MacOS** or WSL (Windows Subsystem for Linux)
-   `nmap` – for network scanning
-   `jq` – for parsing JSON results from NVD API 
-   `curl` – for querying vulnerability databases
    
To install:

	    ---------------------------------------
	    # Update package index
        sudo apt update
        ---------------------------------------
        # Install required tools
        sudo apt install nmap jq curl -y
        ---------------------------------------
        # Verify installations
        nmap --version
        jq --version
        curl --version
        ---------------------------------------

----------
## 🚀 Usage
Run the script with the target IP or domain:
`./sec_report_final.sh <target_ip_or_domain>` 
After execution, two reports will be generated in the current directory:
-   `network_scan_report_<timestamp>.txt`
-   `network_scan_report_<timestamp>.html`
----------

## 📑 Example Reports

### ✅ Example 1: Vulnerabilities Found


    ******************************************
             Security Scan Report
    ******************************************
    
    Target: 192.168.1.10
    
    =========================================
    Open Ports and Services
    =========================================
    22/tcp   open   OpenSSH 8.2
    80/tcp   open   Apache httpd 2.4.49
    
    =========================================
    Potential Vulnerabilities
    =========================================
    [+] Found targeted services (showing up to 16):
    80/tcp   open   Apache httpd 2.4.49
    
    [*] Checking Apache 2.4.49 for known vulnerabilities...
    CVE-2021-41773|Apache HTTP Server Path Traversal Vulnerability|HIGH
    CVE-2021-42013|Apache HTTP Server RCE Vulnerability|CRITICAL
    
    =========================================
    Remediation Recommendations
    =========================================
    [+] CVE-2021-41773 (HIGH)
        - Summary: Apache HTTP Server Path Traversal Vulnerability
        - Recommended Action: Apply patches/workarounds recommended by vendor.
    
    [+] CVE-2021-42013 (CRITICAL)
        - Summary: Apache HTTP Server RCE Vulnerability
        - Recommended Action: Apply latest vendor patch and follow best practices.
    
    ******************************************
    Report completed
    Generated on: 2025-08-24_11-30
    ******************************************
----------

### ❌ Example 2: No Vulnerabilities Found
    ******************************************
             Security Scan Report
    ******************************************
    
    Target: 192.168.1.15
    
    =========================================
    Open Ports and Services
    =========================================
    No open ports detected.
    
    =========================================
    Potential Vulnerabilities
    =========================================
    [-] No targeted services detected.
    
    [*] Vulnerability analysis complete.
    No vulnerabilities identified.
    
    =========================================
    Remediation Recommendations
    =========================================
    No specific vulnerabilities identified in the scan.
    General recommendations:
     - Keep all services updated and patched.
     - Restrict unnecessary open ports.
     - Enforce strong authentication for remote access.
     - Regularly scan and monitor services.
    ******************************************
    Report completed
    Generated on: 2025-08-24_11-45
    ******************************************
---
## 👨‍💻 Author notes

Created for **educational purposes** in network and cybersecurity studies for NTS370 at UAT.

---
