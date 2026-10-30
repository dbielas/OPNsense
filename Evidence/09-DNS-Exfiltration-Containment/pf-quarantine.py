#!/usr/bin/env python3
"""
Dynamic Layer 3 Host Containment via FreeBSD pfctl
Injects host into in-memory table and tears down active session states.
"""
import argparse
import ipaddress
import subprocess
import sys

# Immutable Tier-0 Exclusions: Protected Infrastructure
IMMUTABLE_EXCLUSIONS = {
    ipaddress.ip_address("192.168.20.1"),   # Gateway / Perimeter Resolver
    ipaddress.ip_address("192.168.20.75"),  # DC01 Active Directory Server
}

TABLE_NAME = "Quarantined_Hosts"

def isolate_host(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    
    if ip in IMMUTABLE_EXCLUSIONS:
        print(f"[!] CRITICAL SAFETY ABORT: {ip} is in Tier-0 exclusions list.")
        sys.exit(2)

    try:
        # Step 1: Inject IP into in-memory kernel table
        cmd_add = ["pfctl", "-t", TABLE_NAME, "-T", "add", str(ip)]
        subprocess.run(cmd_add, check=True, capture_output=True, text=True)
        print(f"[+] Injected {ip} into pf table '{TABLE_NAME}'.")

        # Step 2: Sever all established TCP/UDP states
        cmd_kill = ["pfctl", "-k", str(ip)]
        subprocess.run(cmd_kill, check=True, capture_output=True, text=True)
        print(f"[+] Successfully terminated all active session states for {ip}.")

    except subprocess.CalledProcessError as err:
        print(f"[-] Execution failed: {err.stderr.strip() if err.stderr else err}")
        sys.exit(1)

def release_host(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    try:
        cmd_del = ["pfctl", "-t", TABLE_NAME, "-T", "delete", str(ip)]
        subprocess.run(cmd_del, check=True, capture_output=True, text=True)
        print(f"[+] Successfully removed {ip} from pf table '{TABLE_NAME}'.")
    except subprocess.CalledProcessError as err:
        print(f"[-] Execution failed: {err.stderr.strip() if err.stderr else err}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="L3 Host Isolation Engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--isolate", help="Workstation IP to block and terminate")
    group.add_argument("--release", help="Workstation IP to release from quarantine")
    args = parser.parse_args()

    if args.isolate:
        isolate_host(args.isolate)
    elif args.release:
        release_host(args.release)
