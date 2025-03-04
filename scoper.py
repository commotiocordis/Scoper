#!/usr/bin/env python3

import argparse, ipaddress, readline, socket, os, subprocess, re, sys
from dotenv import load_dotenv

# Global variables
TARGETS = []
SCOPE = []
EXCLUSIONS = []
VERBOSE = False
DEBUG = False

# Load .env variables
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)
SCOPE_FILE_PATH = os.getenv('SCOPE_FILE_PATH', 'scope.txt')
EXCLUDE_FILE_PATH = os.getenv('EXCLUDE_FILE_PATH', 'exclude.txt')


def format_output(greppable_output, firewall, list_in, list_ex, list_out, list_not, csv, legacy_fw):
    global SCOPE, TARGETS, EXCLUSIONS, VERBOSE

    # Main loop for each Target
    for target in TARGETS:
        if not target.valid:
            print("[!] Skipping unresolvable target '{}'".format(target.hostname))
            continue
        target.state, target.source = check_target_scope(target.ip_address)

        # We just care about firewalls, skip the rest
        if firewall:
            continue

        # Handle greppable
        if greppable_output:
            print(f"{target.target} : {target.state}")
            continue


        # Handle CSV
        if csv:
            print(f"{target.target},{target.state}")
            continue
        
        # Handle -li, -lo, and -le
        if list_in or list_ex or list_out or list_not:
            if list_in and target.state == "InScope":
                print(f"{target}")
            elif list_ex and target.state == "Excluded":
                print(f"{target}")
            elif list_out and target.state == "OutOfScope":
                print(f"{target}")
            elif list_not and (target.state == "Excluded" or target.state == "OutOfScope"):
                print(f"{target}")
            continue

        # Normal output
        if target.state == "InScope":
            print(f"[+] The target {target} is in scope", end='')
            if VERBOSE:
                print(f", matching line: {target.source}")
            else:
                print("")
        elif target.state == "Excluded":
            print(f"[X] The target {target} is explicitly excluded from the scope", end='')
            if VERBOSE:
                print(f", matching line: {target.source}")
            else:
                print("")
        else:
            print(f"[-] The target {target} is out of scope.")

    if firewall:
        generate_iptables_rules()
    
    if legacy_fw:
        legacy_iptables_output()

def run_loop():
    global SCOPE, EXCLUSIONS
    print("Enter targets, one at a time. Type 'exit' or 'quit' to stop.")
    try:
        while True:
            line = input("[>] ")
            if line == "exit" or line == "quit":
                print("Exiting...")
                return
            target = Target(line)
            if not target.valid:
                continue
            target.state, target.source = check_target_scope(target.ip_address)
            if target.state == "InScope":
                print(f"[+] The target {target} is in scope", end='')
                if VERBOSE:
                    print(f", matching line: {target.source}")
                else:
                    print("")
            elif target.state == "Excluded":
                print(f"[X] The target {target} is explicitly excluded from the scope", end='')
                if VERBOSE:
                    print(f", matching line: {target.source}")
                else:
                    print("")
            else:
                print(f"[-] The target {target} is out of scope.")
    except KeyboardInterrupt:
        print("\nExiting...")
        return


class Target:
    def __init__(self, target):
        self.target = target
        self.ip_address = None
        self.hostname = None
        self.valid = True

        # State can be one of "InScope", "OutOfScope", or "Excluded"
        self.state = None

        # Source refers to the line in the scope or exclusion file which matches
        self.source = None

        # Parse the target and set the appropriate variable
        self.parse_target(target)

    def parse_target(self, targetstring):
        # IPv4
        try:
            ipaddress.IPv4Address(targetstring)
            self.ip_address = targetstring
            return
        except ipaddress.AddressValueError:
            pass

        # Hostname
        self.hostname = targetstring
        self.ip_address = resolve_hostname(targetstring)
        if self.ip_address is None:
            self.valid = False
        return

    def __str__(self):
        if self.hostname is not None:
            return f"{self.ip_address} ({self.hostname})"
        else:
            return f"{self.ip_address}"


def load_file(file_path, file_type):

    loaded_list = []

    try:
        if DEBUG:
            print(f"[@] Loading {file_type} from {file_path}")
        
        with open(file_path, 'r') as file:
            # Read each line and strip whitespaces, ignoring empty lines
            for line in file:
                line = line.strip()
                if line:
                    if file_type == 'scope' or file_type == 'exclude':
                        loaded_list.append(line)
                    elif file_type == 'target':
                        # For target files, create Target objects and append to the list
                        target = Target(line)
                        if target.valid:
                            loaded_list.append(target)
                        else:
                            print(f"[!] Invalid target: {line}")
                    else:
                        print(f"[!] Unknown file type: {file_type}")
        
        if DEBUG:
            print(f"[@] Loaded {len(loaded_list)} {file_type} entries")

    except FileNotFoundError:
        print(f"[!] Warning: {file_type.capitalize()} file '{file_path}' not found, bailing\n", file=sys.stderr)
        exit(1)

    return loaded_list
    
def check_target_scope(ip_address):
    global EXCLUSIONS, SCOPE
    # Check exclusions first
    for address_range in EXCLUSIONS:
        if is_ip_in_range(str(ip_address), address_range):
            return "Excluded", address_range

    # Check scope list
    for address_range in SCOPE:
        if is_ip_in_range(str(ip_address), address_range):
            return "InScope", address_range

    # If not in either, it is out-of-scope
    return "OutOfScope", "not in scope or exclusion files"


def is_ip_in_range(ip, address_range):
    if '/' in address_range:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(address_range, strict=False)
    elif '-' in address_range:
        start_ip, end_ip_part = address_range.split('-')
        if len(end_ip_part.split('.')) == 1:
            start_ip_base = start_ip.rsplit('.', 1)[0]
            end_ip = f"{start_ip_base}.{end_ip_part}"
        else:
            end_ip = end_ip_part
        return ipaddress.ip_address(ip) >= ipaddress.ip_address(start_ip) and ipaddress.ip_address(
            ip) <= ipaddress.ip_address(end_ip)
    else:
        return ipaddress.ip_address(ip) == ipaddress.ip_address(address_range)


def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        if DEBUG:
            print(f"[!] Could not resolve '{hostname}'", file=sys.stderr)
        return None
        
        
# Function to create an IP set
def create_ipset(ipset_name, set_type='hash:ip'):
    try:
        # If we're creating a CIDR set, we need to use 'hash:net'
        subprocess.run(['ipset', 'create', ipset_name, set_type], check=True, stderr=subprocess.DEVNULL)
        print(f"IP set {ipset_name} created with type {set_type}.")
    except subprocess.CalledProcessError:
        # Flush the ipset if it has already been created 
        subprocess.run(['ipset', 'flush', ipset_name], check=True)
        if DEBUG:
            print(f"IP set {ipset_name} already exists.")
            print(f"IP set {ipset_name} flushed.")

# Function to add IPs or ranges to the set
def add_to_ipset(ipset_name, item):
    try:
        if isinstance(item, ipaddress.IPv4Network):
            # It's a CIDR range, use 'hash:net' for adding network ranges
            subprocess.run(['ipset', 'add', ipset_name, str(item)], check=True)
            if DEBUG:
                print(f"CIDR block {item} added to {ipset_name}.")
        else:
            # It's a single IP, use 'hash:ip' for individual IPs
            subprocess.run(['ipset', 'add', ipset_name, str(item)], check=True)
            if DEBUG:
                print(f"IP {item} added to {ipset_name}.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add {item} to {ipset_name}: {e}")

# Function to check if ipset is installed
def check_ipset_installed():
    try:
        # Try to run `ipset -v` to check if ipset is installed
        subprocess.run(['ipset', '-v'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if DEBUG:
            print("[+] ipset is installed.")
        return True
    except:
        print("[!] ipset is not installed. Attempting to install now")
        return False

# Function to install ipset (Linux only, for example)
def install_ipset():
    try:
        # Prompt the user to install ipset
        user_input = input("[?] Would you like to install ipset? (y/n): ").strip().lower()
        if user_input in ['y', 'yes']:
            # Try to install ipset (assumes apt package manager for Debian-based systems)
            print("[*] Installing ipset...")
            subprocess.run(['apt-get', 'install', '-y', 'ipset'], check=True)
            return True
        else:
            print("[!] Exiting. ipset is required for the script.")
            sys.exit(1)  # Exit if user does not want to install ipset
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install ipset: {e}")
        return False

# Function to check if user has sudo privileges
def check_sudo():
    if os.geteuid() != 0:
        print("[!] This script must be run with sudo. Exiting...")
        sys.exit(1)
    else:
        if DEBUG:
            print("Running with sudo. Proceeding... ")
        return True

# Function to create an iptables rule using the IP set
def apply_iptables_rule(ipset_name): 
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-m', 'set', '--match-set', ipset_name, 'dst', '-j', 'DROP'], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-m', 'set', '--match-set', ipset_name, 'src', '-j', 'DROP'], check=True)
        
        print(f"iptables rules applied for IP set {ipset_name}.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to apply iptables rule: {e}")
        
def generate_iptables_rules():
    # Check for sudo privileges before continuing
    check_sudo()
    
    # Check to see if ipset is installed
    if not check_ipset_installed():
        # Attempt to install ipset
        if install_ipset():
            print("[+] ipset installed. Proceeding...")
        else:
            sys.exit(1)  # Exit if installation failed
        
    ipset_name_ips = "blocked_ips"  # Set for individual IPs
    ipset_name_cidr = "blocked_cidrs"  # Set for CIDR blocks

    # Create separate ipsets for individual IPs and CIDR blocks
    create_ipset(ipset_name_ips, 'hash:ip')  # Create a hash set for individual IPs
    create_ipset(ipset_name_cidr, 'hash:net')  # Create a hash set for CIDR blocks
    
    global EXCLUSIONS
    for exclusion in EXCLUSIONS:
        try:
            # Handle both individual IPs and CIDR ranges
            if '/' in exclusion:
                # It's a CIDR block, use ipaddress module to parse and add the entire range
                network = ipaddress.IPv4Network(exclusion)
                add_to_ipset(ipset_name_cidr, network)
            else:
                # It's a single IP, add it directly
                ip = ipaddress.IPv4Address(exclusion)
                add_to_ipset(ipset_name_ips, ip)
        except ValueError as e:
            print(f"Skipping invalid IP/range {exclusion}: {e}")

    # Apply iptables rule to accept all IPs in the ipset
    apply_iptables_rule(ipset_name_cidr)
    apply_iptables_rule(ipset_name_ips)
    
def legacy_iptables_output():
    global TARGETS
    for target in TARGETS:
        if target.state == "Excluded":
            print(f"iptables -A INPUT -s {target.ip_address} -j DROP")
            print(f"iptables -A OUTPUT -d {target.ip_address} -j DROP")

def banner():
    print(""" _____ _____ _____ _____ _____ _____ 
|   __|     |     |  _  |   __| __  |
|__   |   --|  +  |   __|   __|    -|
|_____|_____|_____|__|  |_____|__|__| v1.1.0 by @TactiFail
""")


def main():
    global TARGETS, VERBOSE, SCOPE, EXCLUSIONS, DEBUG

    parser = argparse.ArgumentParser(description='Check whether target machines are in scope. Optionally generate iptables rules if not.')

    # Main args
    parser.add_argument('target', nargs='?', type=str, help='IP address, hostname, or a file containing targets to check')
    parser.add_argument('-sf', '--scope-file', type=str, default=SCOPE_FILE_PATH, help='file containing a list of in-scope IP addresses or ranges')
    parser.add_argument('-ef', '--exclude-file', type=str, default=EXCLUDE_FILE_PATH, help='file containing a list of excluded IP addresses or ranges')
    parser.add_argument('-i',  '--interactive', action='store_true', help='interactive mode')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    parser.add_argument('-d', '--debug', action='store_true', help='verbose output')

    # Output args
    list_opts_group = parser.add_argument_group("output", "mutually exclusive, choose one or none")
    list_opts_group_ex = list_opts_group.add_mutually_exclusive_group()

    list_opts_group_ex.add_argument('-fw', '--firewall',  action='store_true', help='create ip sets from exclusion file (not just those found in targets) and apply the firewall rules (requires sudo)')
    list_opts_group_ex.add_argument('-lfw', '--legacy-fw',  action='store_true', help='generate a list iptables rules for excluded targets found in target list')
    list_opts_group_ex.add_argument('-g',  '--greppable', action='store_true', help='output in greppable format')
    list_opts_group_ex.add_argument('-li', '--list-in',   action='store_true', help='only list in-scope targets')
    list_opts_group_ex.add_argument('-le', '--list-ex',   action='store_true', help='only list excluded targets')
    list_opts_group_ex.add_argument('-lo', '--list-out',  action='store_true', help='only list out-of-scope targets')
    list_opts_group_ex.add_argument('-ln', '--list-not',  action='store_true', help='only list not-in-scope targets (combines -le and -lo)')
    list_opts_group_ex.add_argument('-c', '--csv',  action='store_true', help='only list not-in-scope targets (combines -le and -lo)')

    args = parser.parse_args()

    if (args.target is None and not args.interactive) or args.scope_file is None:
        parser.print_help()
        exit()

    VERBOSE = args.verbose
    DEBUG = args.debug

    # Only show banner in some cases
    if not args.greppable and not args.firewall and not args.list_in and not args.list_ex and not args.list_out and not args.list_not:
        banner()

    # Load scope
    SCOPE = load_file(args.scope_file, 'scope')

    # Load exclusions
    if args.exclude_file:
        EXCLUSIONS = load_file(args.exclude_file, 'exclude')
    else:
        print(f"[!] Warning: Exclude file not found - will not check for exclusions\n", file=sys.stderr)
     
    # Load targets
    if args.target:
        if os.path.isfile(args.target):
            TARGETS = load_file(args.target, 'target')
        else:
            TARGETS = [Target(target)]  # If it's a single target passed directly
    

    if not args.interactive:
        format_output(args.greppable, args.firewall, args.list_in, args.list_ex, args.list_out, args.list_not, args.csv, args.legacy_fw)
    else:
        run_loop()

if __name__ == "__main__":
    main()
