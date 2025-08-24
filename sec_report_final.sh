#!/bin/bash

#Veriables
MAX_VULNS=16  # Maximum number of vulnerabilities to display


# Header Section
write_header() {
    local entered_IP=$1
    echo "******************************************"
    echo "         Security Scan Report             "
    echo "******************************************"
    echo ""
    echo "Target: $entered_IP"
    echo ""
}

# Port Listing Section
write_ports_section() {
    local TARGET=$entered_IP
    echo "========================================="
    echo "Open Ports and Services"
    echo "========================================="
    nmap -sV "$TARGET" 2>/dev/null | grep -E "^[0-9]+/tcp\s+(open)" || echo "No open ports detected."
    echo ""
}


# Vulnerability Section
write_vulns_section() {
    local TARGET=$entered_IP
    echo "========================================="
    echo "Potential  Vulnerabilities"
    echo "========================================="

    echo "[*] Initiating targeted vulnerability scan..."
    local SCAN_RESULTS
    SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET" 2>/dev/null)

    local FILTERED_RESULTS
    FILTERED_RESULTS=$(echo "$SCAN_RESULTS" | grep -E "Apache|OpenSSH|nginx|MySQL|PostgreSQL|Microsoft-IIS|FTP|Telnet|Samba|Docker|Redis|MongoDB|Tomcat|PHP|VSFTPD|ProFTPD" | head -n "$MAX_VULNS")


    if [[ -n "$FILTERED_RESULTS" ]]; then
        echo "[+] Found targeted services (showing up to $MAX_VULNS):"
        echo "$FILTERED_RESULTS"
    else
        echo "[-] No targeted services detected."
    fi

    echo ""
    echo "--- Querying NVD for Targeted Services ---"

    # Track vulnerabilities for remediation
    FOUND_VULNS=""
    NVD_JSON_RESULTS=""

    # Loop through filtered services to query NVD
    echo "$FILTERED_RESULTS" | while read -r port proto state service rest; do
        product_name=$(echo "$rest" | awk '{print $1}')
        product_version=$(echo "$rest" | awk '{print $2}')

        if [[ -n "$product_name" && -n "$product_version" ]]; then
            echo "[*] Checking $product_name $product_version for known vulnerabilities..."
            vuln_result=$(query_nvd "$product_name" "$product_version")
            # Append to found vulnerabilities, respecting max limit
            if [[ $(echo "$FOUND_VULNS" | wc -l) -lt "$MAX_VULNS" ]]; then
                FOUND_VULNS+="$vuln_result"$'\n'
            fi
        else
            echo "[-] Could not determine version for service: $service"
        fi
    done

    echo ""
    echo "[*] Vulnerability analysis complete."
    echo "$FOUND_VULNS"
}


# NVD API Query Section
query_nvd() {
    local product="$1"
    local version="$2"
    local results_limit=16

    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

    local vulnerabilities_json
    vulnerabilities_json=$(curl -s "$nvd_api_url")

    # Save last query results for remediation section
    NVD_JSON_RESULTS="$vulnerabilities_json"

    if [[ -z "$vulnerabilities_json" ]]; then
    echo "[!] Failed to fetch data from NVD for $product $version." 
    return
    fi
    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null; then
    echo "[!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
    return
    fi
    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
    echo "[+] No vulnerabilities found in NVD for $product $version."
    return
    fi

    # Extract CVE, Description, Severity
    echo "$vulnerabilities_json" | jq -r \
    --arg product "$product" \
    --arg version "$version" \
    '.vulnerabilities[] |
    "\(.cve.id)|\((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))|\(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")"'
}


# Remediation Section
write_recs_section() {
    echo "========================================="
    echo "Remediation Recommendations"
    echo "========================================="

    if [[ -z "$FOUND_VULNS" ]]; then
        echo "No specific vulnerabilities identified in the scan."
        echo "General recommendations:"
        echo " - Keep all services updated and patched."
        echo " - Restrict unnecessary open ports."
        echo " - Enforce strong authentication for remote access."
        echo " - Regularly scan and monitor services."
        echo ""
        return
    fi

    echo "$FOUND_VULNS" | while read -r vuln_line; do
        CVE_ID=$(echo "$vuln_line" | awk -F'|' '{print $1}')
        DESC=$(echo "$vuln_line" | awk -F'|' '{print $2}')
        SEVERITY=$(echo "$vuln_line" | awk -F'|' '{print $3}')

        echo "[+] $CVE_ID ($SEVERITY)"
        echo "    - Summary: $DESC"

        RECOMMEND=$(echo "$NVD_JSON_RESULTS" | jq -r \
            --arg cve "$CVE_ID" \
            '.vulnerabilities[] | select(.cve.id==$cve) 
            | .cve.configurations.nodes[0].negate as $neg 
            | if .cve.weaknesses then "Apply patches/workarounds recommended by vendor." else "General hardening required." end' 2>/dev/null)

        if [[ -n "$RECOMMEND" && "$RECOMMEND" != "null" ]]; then
            echo "    - Recommended Action: $RECOMMEND"
        else
            echo "    - Recommended Action: Apply latest vendor patch and follow best practices."
        fi

        echo ""
    done
}


# Footer Section
write_footer() {
    echo "******************************************"
    echo "Report completed"
    echo "Generated on: $(date +"%Y-%m-%d_%H-%M")"
    echo "******************************************"
}


# Main Program
main() {
    if [ $# -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_domain>"
    exit 1
    fi

    local entered_IP=$1
    local timestamp=$(date +"%Y-%m-%d_%H-%M")
    local REPORT_FILE="network_scan_report_${timestamp}.txt"
    local HTML_REPORT_FILE="network_scan_report_${timestamp}.html"

    echo "******************************************"
    echo "This scan may take several minutes depending on the responsiveness of the host."
    echo "Please be patient while the report is generated..."
    echo "******************************************"
    echo ""

    # Initialize HTML report
    echo "<!DOCTYPE html>
    <html>
    <head>
    <title>Security Scan Report - $entered_IP</title>
    <meta charset='UTF-8'>
    <style>
    body { font-family: Arial, sans-serif; line-height: 1.5; }
    h2 { color: #2E86C1; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }
    </style>
    </head>
    <body>
    <h1>Security Scan Report</h1>
    <p>Target: $entered_IP</p>
    <p>Generated on: $(date +"%Y-%m-%d %H:%M")</p>" > "$HTML_REPORT_FILE"

    #Text report and print out to screen
    echo "[*] Writing report header..."
    write_header "$entered_IP" | tee "$REPORT_FILE"
    write_header "$entered_IP" | sed 's/^/<p>/' | sed 's/$/<\/p>/' >> "$HTML_REPORT_FILE"

    echo "[*] Scanning and writing open ports/services..."
    write_ports_section | tee -a "$REPORT_FILE"
    write_ports_section | sed 's/^/<p>/' | sed 's/$/<\/p>/' >> "$HTML_REPORT_FILE"

    echo "[*] Performing vulnerability analysis..."
    VULN_OUTPUT=$(write_vulns_section | tee -a "$REPORT_FILE")
    echo "$VULN_OUTPUT" | sed 's/^/<p>/' | sed 's/$/<\/p>/' >> "$HTML_REPORT_FILE"

    echo "[*] Writing remediation recommendations..."
    write_recs_section | tee -a "$REPORT_FILE"
    write_recs_section | sed 's/^/<p>/' | sed 's/$/<\/p>/' >> "$HTML_REPORT_FILE"

    echo "[*] Finalizing report..."
    write_footer | tee -a "$REPORT_FILE"
    write_footer | sed 's/^/<p>/' | sed 's/$/<\/p>/' >> "$HTML_REPORT_FILE"

    echo "</body></html>" >> "$HTML_REPORT_FILE"

    echo "+++++++++++++++++++++++++++++++++++++++++++"
    echo "Security report complete."
    echo "Report saved as: $REPORT_FILE (text) and $HTML_REPORT_FILE (HTML)"
    echo "+++++++++++++++++++++++++++++++++++++++++++"
}


# Execute Script
main "$@"

