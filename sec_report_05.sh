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
    nmap -sV "$TARGET" 2>/dev/null | grep -E "^[0-9]+/tcp\s+(open)" || echo "No open ports detected."
    
    echo ""
}

# Vulnerability list
write_vulns_section() {
    local TARGET=$entered_IP
    echo "========================================="
    echo "Targeted Vulnerabilities Identified"
    echo "========================================="

    echo "[*] Initiating targeted vulnerability scan on $TARGET ..."
    echo "[*] This may take several minutes depending on host responsiveness."

    # Run Nmap scan with vuln scripts
    local SCAN_RESULTS
    SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET" 2>/dev/null)

    # Filter for targeted services: Apache, OpenSSH, Nginx
    local FILTERED_RESULTS
    FILTERED_RESULTS=$(echo "$SCAN_RESULTS" | grep -E "Apache httpd|OpenSSH|nginx")

    if [[ -n "$FILTERED_RESULTS" ]]; then
        echo "[+] Found the following targeted services:"
        echo "$FILTERED_RESULTS"
    else
        echo "[-] No targeted services detected (Apache, OpenSSH, Nginx)."
    fi

    echo ""
    echo "--- Querying NVD for Targeted Services ---"

    # Loop through the filtered services to query NVD
    echo "$FILTERED_RESULTS" | while read -r port proto state service rest; do
        product_name=$(echo "$rest" | awk '{print $1}')
        product_version=$(echo "$rest" | awk '{print $2}')

        if [[ -n "$product_name" && -n "$product_version" ]]; then
            echo "[*] Checking $product_name $product_version for known vulnerabilities..."
            query_nvd "$product_name" "$product_version"
        else
            echo "[-] Could not determine version for service: $service"
        fi
    done

    echo ""
    echo "[*] Vulnerability analysis complete."
}

# NVD API quary
query_nvd() {
        local product="$1"
    local version="$2"
    local results_limit=3

    echo ""
    echo ">>> Querying NVD for vulnerabilities in: $product $version"

    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

    local vulnerabilities_json
    vulnerabilities_json=$(curl -s "$nvd_api_url")

    if [[ -z "$vulnerabilities_json" ]]; then
        echo "  [!] Error: Failed to fetch data from NVD."
        return
    fi
    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null; then
        echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
        return
    fi
    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
        echo "  [+] No vulnerabilities found in NVD for this service."
        return
    fi

    echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] |
        "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang==\"en\")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"'
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
    echo "Error: Too many IPs or Domains entered only use one IP or one domain."
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
    write_header "$entered_IP"   | tee    "$REPORT_FILE"
    write_ports_section          | tee -a "$REPORT_FILE"
    write_vulns_section          | tee -a "$REPORT_FILE"
    write_recs_section           | tee -a "$REPORT_FILE"
    write_footer                 | tee -a "$REPORT_FILE"

    # Report gen message
    echo "+++++++++++++++++++++++++++++++++++++++++++"
    echo "Security report complete."
    echo "Report saved as: $REPORT_FILE"
    echo "+++++++++++++++++++++++++++++++++++++++++++"
}

# Script validation point for all fuctions
main "$@"
