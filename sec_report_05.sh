#!/bin/bash

# Header section
write_header() {
    local entered_IP=$1
    echo "******************************************"
    echo "         Security Scan Report     "
    echo "******************************************"
    echo ""
    # displays entered ip
    echo "Entered IP: $entered_IP"
    echo ""
}

# Port listing
write_ports_section() {
    local TARGET=$entered_IP
    echo "========================================="
    echo "Open Ports and Services"
    echo "========================================="

    # Run a service/version detection scan with nmap
    # Pipe output to grep to extract lines indicating open ports only
    # This enables focused reporting on relevant, active services
    nmap -sV "$TARGET" 2>/dev/null | grep -E "^[0-9]+/tcp\s+(open)" || echo "No open ports detected."
    
    echo ""
}

# Vulnerability list
write_vulns_section() {
    local TARGET=$entered_IP
    echo "========================================="
    echo "Potential Vulnerabilities Identified"
    echo "========================================="

    echo "[*] Initiating vulnerability scan on $TARGET ..."
    echo "[*] This may take several minutes depending on host responsiveness."

    local SCAN_RESULTS
    SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET" 2>/dev/null)

    
    # Vulnerability Results
    local VULN_MATCHES
    VULN_MATCHES=$(echo "$SCAN_RESULTS" | grep -i "VULNERABLE")

    if [[ -n "$VULN_MATCHES" ]]; then
        echo "[+] Found Vulnerabilities:"
        echo "$VULN_MATCHES"
    else
        echo "[-] No Vulnerabilities found."
    fi

    echo ""
    echo "--- Analyzing Service Versions for Known Risks ---"

    
    # Scan of Vulnerabilities
    echo "$SCAN_RESULTS" | while read -r line; do
        case "$line" in
            *"vsftpd 2.3.4"*)
                echo "[!!] CRITICAL: vsftpd 2.3.4 detected — known backdoor vulnerability (CVE-2011-2523)."
                ;;
            *"Apache httpd 2.4.49"*)
                echo "[!!] HIGH: Apache 2.4.49 detected — vulnerable to path traversal and RCE (CVE-2021-41773)."
                ;;
            *"OpenSSL 1.0.1"*)
                echo "[!!] HIGH: OpenSSL 1.0.1 detected — vulnerable to Heartbleed (CVE-2014-0160)."
                ;;
            *"Samba 3.5.0"*)
                echo "[!!] HIGH: Samba 3.5.0 detected — vulnerable to remote code execution (CVE-2012-1182)."
                ;;
        esac
    done

    echo ""
    echo "[*] Vulnerability analysis complete."
}


# Recommendations
write_recs_section() {
    echo "========================================="
    echo "Remediation Actions Required"
    echo "========================================="
    #place holder data
    echo "1. Disable or secure Telnet." 
    echo "2. Ensure SSH services are configured securely."
    echo "3. Apply security patches for services and restrict access to ports."
    echo "4. Disable Teamspeak."
    echo "5. Patch all services/applications to latest versions."
    echo "6. Scan database/sanitize all databases."
    echo "7. Regularly monitor logs and establish detection system/process."
    echo ""
}

# Footer with timestamp
write_footer() {
    echo "******************************************"
    echo "Report completed"
    echo "Generated on: $(date +"%Y-%m-%d_%H-%M")" 
    #year month day hour min time stamp
    echo "******************************************"
}

# Main program
main() {
    # Input validation
    if [ $# -eq 0 ]; then
    echo "Error: No IP address or domain provided."
    echo "Usage: $0 <target_ip_or_domain>"
    exit 1
    fi

    if [ $# -gt 1 ]; then
    echo "Error: Too many arguments provided."
    echo "Usage: $0 <target_ip_or_domain>"
    exit 1
    fi

    # Extract and validate IP address or domain
    local entered_IP=$1
    if [[ $entered_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    :
    elif [[ $entered_IP =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
    :
    else
    echo "Error: Invalid format. Provide a valid IPv4 address (e.g., 192.168.1.1) or domain (e.g., example.com)."
    exit 1
    fi

    #Feed back report is in progress
    echo "******************************************"
    echo "This scan may take several minutes depending on the responsiveness of the host."
    echo "Please be patient while the report is generated..."
    echo "******************************************"

    # Variables for output file
    #provides year month day hour min time stamp
    local entered_IP=$1
    local timestamp=$(date +"%Y-%m-%d_%H-%M")
    local REPORT_FILE="network_scan_report_${timestamp}.txt" 

    # Report generation
    #writes out sections for the report
    write_header "$entered_IP" > "$REPORT_FILE"
    write_ports_section >> "$REPORT_FILE" 
    write_vulns_section >> "$REPORT_FILE"
    write_recs_section >> "$REPORT_FILE"
    write_footer >> "$REPORT_FILE"

    # Report gen message
    echo "+++++++++++++++++++++++++++++++++++++++++++"
    echo "Security report complete."
    echo "Report saved as: $REPORT_FILE"
    echo "+++++++++++++++++++++++++++++++++++++++++++"
}

# Script validation point for all fuctions
main "$@"
