#!/bin/bash

# Title: Nmap Automation Script
# Description: A script to automate various Nmap scans for penetration testing purposes.
# Author: [Your Name]
# Date: [Date]
# GitHub: [Your GitHub URL]

# Function to validate if the target input is not empty
validate_target() {
    if [ -z "$target" ]; then
        echo "Error: Target IP or network range is required."
        exit 1
    fi
}

# Function to perform host discovery
host_discovery() {
    echo "[*] Running Host Discovery..."
    nmap -sn $target -oN host_discovery_results.txt
    echo "[+] Host discovery completed. Results saved in host_discovery_results.txt."
}

# Function to perform a full port scan
port_scan() {
    echo "[*] Running Full Port Scanning..."
    nmap -p 1-65535 $target -oN port_scan_results.txt
    echo "[+] Port scanning completed. Results saved in port_scan_results.txt."
}

# Function to detect service versions
service_version_detection() {
    echo "[*] Running Service Version Detection..."
    nmap -sV $target -oN service_version_results.txt
    echo "[+] Service version detection completed. Results saved in service_version_results.txt."
}

# Function to detect the target's operating system
os_detection() {
    echo "[*] Running OS Detection..."
    nmap -O $target -oN os_detection_results.txt
    echo "[+] OS detection completed. Results saved in os_detection_results.txt."
}

# Function to scan for known vulnerabilities using NSE scripts
vulnerability_scan() {
    echo "[*] Running Vulnerability Scan..."
    nmap --script=vuln $target -oN vuln_scan_results.txt
    echo "[+] Vulnerability scan completed. Results saved in vuln_scan_results.txt."
}

# Function to perform firewall/IDS evasion
firewall_evasion() {
    echo "[*] Running Firewall/IDS Evasion..."
    nmap -f $target -oN firewall_evasion_results.txt
    echo "[+] Firewall/IDS evasion completed. Results saved in firewall_evasion_results.txt."
}

# Function to perform UDP port scanning
udp_scan() {
    echo "[*] Running UDP Port Scanning..."
    nmap -sU $target -oN udp_scan_results.txt
    echo "[+] UDP port scanning completed. Results saved in udp_scan_results.txt."
}

# Main menu for selecting the scan type
main_menu() {
    echo "================================================"
    echo "              Nmap Penetration Testing"
    echo "================================================"
    echo "Target: $target"
    echo "Please select the type of scan you want to run:"
    echo "1) Host Discovery"
    echo "2) Full Port Scanning"
    echo "3) Service Version Detection"
    echo "4) OS Detection"
    echo "5) Vulnerability Scan"
    echo "6) Firewall/IDS Evasion"
    echo "7) UDP Port Scanning"
    echo "0) Exit"
    echo "================================================"
    read -p "Enter your choice (0-7): " choice

    case $choice in
        1) host_discovery ;;
        2) port_scan ;;
        3) service_version_detection ;;
        4) os_detection ;;
        5) vulnerability_scan ;;
        6) firewall_evasion ;;
        7) udp_scan ;;
        0) echo "Exiting the script. Goodbye!" ; exit 0 ;;
        *) echo "Invalid option, please select a valid scan type." ; main_menu ;;
    esac
}

# Main program starts here
echo "================================================"
echo "             Welcome to Nmap Automation"
echo "================================================"
read -p "Enter the target IP or network range: " target
validate_target

main_menu
