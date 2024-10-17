import os
import subprocess
import sys
from datetime import datetime

# Get domain input from user
target_domain = input("Enter the target domain: ")

# Create directory for the output
output_dir = f"{target_domain}_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(output_dir, exist_ok=True)

def run_command(command):
    """Runs a shell command and captures output"""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    if stderr:
        print(f"[Error] {stderr.decode('utf-8')}")
    return stdout.decode('utf-8')

def subdomain_enum(domain):
    """Runs subfinder and amass for subdomain enumeration"""
    print("[*] Starting Subdomain Enumeration...")

    # Running Subfinder
    subfinder_output = os.path.join(output_dir, "subfinder.txt")
    run_command(f"subfinder -d {domain} -o {subfinder_output}")
    print(f"[*] Subfinder results saved in {subfinder_output}")

    # Running Amass
    amass_output = os.path.join(output_dir, "amass.txt")
    run_command(f"amass enum -d {domain} -o {amass_output}")
    print(f"[*] Amass results saved in {amass_output}")

    # Combine results
    combined_output = os.path.join(output_dir, "all_subdomains.txt")
    run_command(f"cat {subfinder_output} {amass_output} | sort -u > {combined_output}")
    print(f"[*] Combined subdomains saved in {combined_output}")

    return combined_output

def probe_http(subdomains_file):
    """Use httpx to check for live hosts"""
    print("[*] Probing for live hosts with httpx...")
    httpx_output = os.path.join(output_dir, "live_hosts.txt")
    run_command(f"httpx -l {subdomains_file} -o {httpx_output}")
    print(f"[*] Live hosts saved in {httpx_output}")

    return httpx_output

def scan_ports(live_hosts_file):
    """Use nmap to identify open ports on live hosts"""
    print("[*] Scanning for open ports with nmap...")
    nmap_output = os.path.join(output_dir, "nmap_results.txt")
    with open(live_hosts_file, 'r') as f:
        for line in f:
            target = line.strip()
            print(f"[*] Scanning {target}")
            run_command(f"nmap -sV {target} -oN {nmap_output} --append-output")
    
    print(f"[*] Nmap scan results saved in {nmap_output}")

def take_screenshots(live_hosts_file):
    """Use gowitness to take screenshots of live hosts"""
    print("[*] Taking screenshots of live hosts with gowitness...")
    gowitness_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(gowitness_dir, exist_ok=True)
    run_command(f"gowitness file -f {live_hosts_file} --destination {gowitness_dir}")
    print(f"[*] Screenshots saved in {gowitness_dir}")

# Run the automation workflow
subdomains_file = subdomain_enum(target_domain)
live_hosts_file = probe_http(subdomains_file)
scan_ports(live_hosts_file)
take_screenshots(live_hosts_file)

print(f"[*] Recon process completed. Check the {output_dir} folder for results.")
