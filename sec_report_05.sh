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
    echo "========================================="
    echo "Vulnerabilities Identified"
    echo "========================================="
    #place holder data
    echo "CVE-2025-49706 - Microsoft SharePoint Authentication Vulnerability" 
    echo "CVE-2025-6558 - Chromium and GPU Improper Input Validation Vulnerability"
    echo "CVE-2025-25257 - SQL Injection Vulnerability"
    echo "CVE-2020-16846 - Shell Injection Vulnerability"
    echo ""
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
        echo "Error: No IP address provided Use IPv4 format (e.g., 192.168.1.1)." >&2
        echo "Usage: $0 <target_ip>" >&2
        exit 1
    fi

    if [ $# -gt 1 ]; then
        echo "Error: To many IPs or Invalid IP format. Use IPv4 format (e.g., 192.168.1.1)." >&2
        echo "Usage: $0 <target_ip>" >&2
        exit 1
    fi

    # Extract and validate IP address format (basic IPv4 x.x.x.x)
    local entered_IP=$1
    if [[ ! $entered_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "Error: Invalid IP format. Use IPv4 format (e.g., 192.168.1.1)." >&2
        echo "Usage: $0 <target_ip>" >&2
        exit 1
    fi

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
    echo ""
    echo "Security report complete."
    echo "Report saved as: $REPORT_FILE"
    echo ""
}

# Script validation point for all fuctions
main "$@"
