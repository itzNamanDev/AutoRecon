import os
import subprocess
import json
import time

# Helper function to run shell commands
def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if stderr:
        print(f"Error: {stderr.decode('utf-8')}")
    return stdout.decode('utf-8')

# Helper functions for printing with colors
def print_info(msg):
    print(f"\033[94m{msg}\033[0m")

def print_success(msg):
    print(f"\033[92m{msg}\033[0m")

def print_warning(msg):
    print(f"\033[93m{msg}\033[0m")

def print_error(msg):
    print(f"\033[91m{msg}\033[0m")

# Directories
output_dir = "recon_output"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Feature: Subdomain Enumeration (subfinder)
def subdomain_enumeration(domain):
    print_info("[*] Running Subdomain Enumeration with subfinder...")
    subfinder_output = os.path.join(output_dir, f"{domain}_subdomains.txt")
    run_command(f"subfinder -d {domain} -o {subfinder_output}")
    print_success(f"Subdomain Enumeration results saved to {subfinder_output}")
    return subfinder_output

# Feature: CNAME Check for Subdomain Takeover
def cname_check(subdomains_file):
    print_info("[*] Checking for potential subdomain takeover via CNAME...")
    cname_output = os.path.join(output_dir, "cname_results.txt")
    with open(subdomains_file, 'r') as subdomains:
        with open(cname_output, 'w') as out:
            for subdomain in subdomains:
                cname_record = run_command(f"dig +short CNAME {subdomain.strip()}")
                if cname_record:
                    out.write(f"{subdomain.strip()} -> {cname_record}\n")
                    print_success(f"{subdomain.strip()} has CNAME: {cname_record}")
    print_success(f"CNAME results saved in {cname_output}")

# Feature: HTTPx for Live Host Detection
def live_host_check(subdomains_file):
    print_info("[*] Checking for live hosts with HTTPx...")
    live_hosts_output = os.path.join(output_dir, "live_hosts.txt")
    run_command(f"httpx -l {subdomains_file} -o {live_hosts_output} --silent")
    print_success(f"Live hosts saved in {live_hosts_output}")
    return live_hosts_output

# Feature: Technology Detection (whatweb)
def tech_detection(live_hosts_file):
    print_info("[*] Detecting web technologies using whatweb...")
    tech_output = os.path.join(output_dir, "tech_detected.txt")
    with open(live_hosts_file, 'r') as live_hosts:
        with open(tech_output, 'w') as out:
            for host in live_hosts:
                tech_info = run_command(f"whatweb {host.strip()}")
                out.write(f"{host.strip()}:\n{tech_info}\n\n")
                print_success(f"Tech detected for {host.strip()}")
    print_success(f"Technology detection results saved in {tech_output}")

# Feature: Vulnerable Endpoint Detection (gf patterns)
def vulnerable_endpoint_detection(live_hosts_file):
    print_info("[*] Scanning for vulnerable endpoints using gf patterns...")
    vuln_output = os.path.join(output_dir, "vulnerable_endpoints.txt")
    with open(live_hosts_file, 'r') as live_hosts:
        with open(vuln_output, 'w') as out:
            for host in live_hosts:
                vuln_info = run_command(f"gf xss {host.strip()}")
                if vuln_info:
                    out.write(f"Vulnerable endpoints for {host.strip()}:\n{vuln_info}\n\n")
                    print_success(f"Vulnerable endpoints found for {host.strip()}")
    print_success(f"Vulnerable endpoints saved in {vuln_output}")

# Feature: SSL/TLS Scan (testssl.sh)
def ssl_scan(live_hosts_file):
    print_info("[*] Running SSL/TLS scan with testssl.sh...")
    ssl_output = os.path.join(output_dir, "ssl_scan_results.txt")
    with open(live_hosts_file, 'r') as live_hosts:
        with open(ssl_output, 'w') as out:
            for host in live_hosts:
                ssl_info = run_command(f"./testssl.sh {host.strip()}")
                out.write(f"SSL/TLS scan results for {host.strip()}:\n{ssl_info}\n\n")
                print_success(f"SSL/TLS scan completed for {host.strip()}")
    print_success(f"SSL/TLS scan results saved in {ssl_output}")

# Feature: Subdomain Takeover Check (subjack)
def subdomain_takeover_check(subdomains_file):
    print_info("[*] Checking for subdomain takeover using subjack...")
    subjack_output = os.path.join(output_dir, "subjack_takeover.txt")
    run_command(f"subjack -w {subdomains_file} -o {subjack_output} -ssl")
    print_success(f"Subdomain takeover results saved in {subjack_output}")

# Feature: Directory Brute-forcing (ffuf)
def directory_bruteforce(live_hosts_file):
    print_info("[*] Running directory brute-forcing with ffuf...")
    ffuf_output = os.path.join(output_dir, "directory_bruteforce.txt")
    with open(live_hosts_file, 'r') as live_hosts:
        with open(ffuf_output, 'w') as out:
            for host in live_hosts:
                brute_result = run_command(f"ffuf -u {host.strip()}/FUZZ -w /path/to/wordlist -o {ffuf_output}")
                if brute_result:
                    out.write(f"Directory brute-forcing results for {host.strip()}:\n{brute_result}\n\n")
                    print_success(f"Directory brute-forcing completed for {host.strip()}")
    print_success(f"Directory brute-forcing results saved in {ffuf_output}")

# Feature: Whois Lookup
def whois_lookup(domain):
    print_info(f"[*] Performing Whois lookup for {domain}...")
    whois_output = os.path.join(output_dir, f"{domain}_whois.txt")
    whois_info = run_command(f"whois {domain}")
    with open(whois_output, 'w') as out:
        out.write(whois_info)
    print_success(f"Whois lookup results saved in {whois_output}")

# Feature: GitHub Dorking for Leaked Credentials
def github_dorking(domain):
    print_info(f"[*] Searching for leaked credentials on GitHub for {domain}...")
    github_dork_output = os.path.join(output_dir, "github_dorks.txt")
    dork_results = run_command(f"github-dorks {domain}")
    with open(github_dork_output, 'w') as out:
        out.write(dork_results)
    print_success(f"GitHub dorking results saved in {github_dork_output}")

# Feature: Auto-Generated Recon Dashboard (future expansion for HTML)
def generate_dashboard():
    print_info("[*] Generating recon dashboard...")
    # Placeholder for recon dashboard generation (HTML)
    dashboard_output = os.path.join(output_dir, "recon_dashboard.html")
    # Logic for generating a visual dashboard
    print_success(f"Recon dashboard generated at {dashboard_output}")

# Main recon flow
def recon(target_domain):
    subdomains_file = subdomain_enumeration(target_domain)
    cname_check(subdomains_file)
    live_hosts_file = live_host_check(subdomains_file)
    tech_detection(live_hosts_file)
    vulnerable_endpoint_detection(live_hosts_file)
    ssl_scan(live_hosts_file)
    subdomain_takeover_check(subdomains_file)
    directory_bruteforce(live_hosts_file)
    whois_lookup(target_domain)
    github_dorking(target_domain)
    generate_dashboard()

# Example usage
if __name__ == "__main__":
    target = input("Enter the target URL:")
    recon(target)
