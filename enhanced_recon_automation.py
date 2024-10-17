import os
import subprocess
import sys
from datetime import datetime
import time

# ANSI color codes for pretty printing
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def print_info(message):
    print(f"{Colors.CYAN}[INFO] {message}{Colors.RESET}")

def print_success(message):
    print(f"{Colors.GREEN}[SUCCESS] {message}{Colors.RESET}")

def print_warning(message):
    print(f"{Colors.YELLOW}[WARNING] {message}{Colors.RESET}")

def print_error(message):
    print(f"{Colors.RED}[ERROR] {message}{Colors.RESET}")

# Get domain input from user
target_domain = input("Enter the target domain: ")

# Create directory for the output
output_dir = f"{target_domain}_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(output_dir, exist_ok=True)

def run_command(command):
    """Runs a shell command and captures output"""
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        if stderr:
            print_warning(f"Command '{command}' produced an error:\n{stderr.decode('utf-8')}")
        return stdout.decode('utf-8').strip()
    except Exception as e:
        print_error(f"Failed to run command: {command}. Error: {e}")

def subdomain_enum(domain):
    """Runs subfinder and amass for subdomain enumeration"""
    print_info(f"[*] Starting Subdomain Enumeration for {domain}...")

    # Running Subfinder
    subfinder_output = os.path.join(output_dir, "subfinder.txt")
    run_command(f"subfinder -d {domain} -o {subfinder_output}")
    print_success(f"Subfinder results saved in {subfinder_output}")

    # Running Amass
    amass_output = os.path.join(output_dir, "amass.txt")
    run_command(f"amass enum -d {domain} -o {amass_output}")
    print_success(f"Amass results saved in {amass_output}")

    # Combine results
    combined_output = os.path.join(output_dir, "all_subdomains.txt")
    run_command(f"cat {subfinder_output} {amass_output} | sort -u > {combined_output}")
    print_success(f"Combined subdomains saved in {combined_output}")

    return combined_output

def probe_http(subdomains_file):
    """Use httpx to check for live hosts and get HTTP status codes"""
    print_info("[*] Probing for live hosts with HTTPX...")

    httpx_output = os.path.join(output_dir, "live_hosts_with_status.txt")
    httpx_cmd = f"httpx -l {subdomains_file} -status-code -o {httpx_output}"
    run_command(httpx_cmd)
    print_success(f"HTTP probing results saved in {httpx_output}")

    return httpx_output

def dns_resolution(subdomains_file):
    """Check DNS resolution of subdomains"""
    print_info("[*] Performing DNS resolution on subdomains...")

    dns_resolved_output = os.path.join(output_dir, "dns_resolved_subdomains.txt")
    resolved_domains = run_command(f"dig -f {subdomains_file} +short")
    
    with open(dns_resolved_output, 'w') as f:
        f.write(resolved_domains)
    print_success(f"DNS resolution results saved in {dns_resolved_output}")

    return dns_resolved_output

def create_summary_report(subdomains_file, live_hosts_file, dns_file):
    """Create a summary report of the recon results"""
    print_info("[*] Creating summary report...")

    summary_report = os.path.join(output_dir, "summary_report.txt")
    with open(summary_report, 'w') as report:
        report.write("Recon Summary for Domain: {}\n".format(target_domain))
        report.write("="*50 + "\n\n")

        # Subdomain enumeration
        report.write("1. Subdomain Enumeration Results:\n")
        report.write("-"*50 + "\n")
        with open(subdomains_file, 'r') as f:
            report.write(f.read())
        report.write("\n\n")

        # Live hosts
        report.write("2. Live Hosts (HTTP Probing Results):\n")
        report.write("-"*50 + "\n")
        with open(live_hosts_file, 'r') as f:
            report.write(f.read())
        report.write("\n\n")

        # DNS resolution
        report.write("3. DNS Resolved Subdomains:\n")
        report.write("-"*50 + "\n")
        with open(dns_file, 'r') as f:
            report.write(f.read())
        report.write("\n\n")

    print_success(f"Summary report saved in {summary_report}")

# Run the automation workflow
subdomains_file = subdomain_enum(target_domain)
live_hosts_file = probe_http(subdomains_file)
dns_file = dns_resolution(subdomains_file)
create_summary_report(subdomains_file, live_hosts_file, dns_file)

print_success(f"[*] Recon process completed. Check the {output_dir} folder for results.")
