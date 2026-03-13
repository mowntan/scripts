#!/usr/bin/env python3
"""Lab network discovery script.

Scans a /24 network, connects via SSH to live hosts, and gathers
system information including hostname, CPU, memory, disk, and
BMC (iLO/iDRAC) details. Outputs CSV for Google Sheets import.
"""

import argparse
import csv
import ipaddress
import logging
import os
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import paramiko

logger = logging.getLogger(__name__)

CSV_COLUMNS = [
    "ip", "hostname", "os", "kernel", "cpu_model", "cpu_cores",
    "memory_total_mb", "memory_used_mb", "memory_pct",
    "disk_total_gb", "disk_used_gb", "disk_pct",
    "bmc_type", "bmc_ip", "bmc_firmware",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Discover and inventory hosts on a /24 network via SSH."
    )
    parser.add_argument(
        "network",
        help="Target network in CIDR notation (e.g. 192.168.1.0/24)",
    )
    parser.add_argument(
        "--user", "-u",
        default=os.environ.get("USER", "root"),
        help="SSH username (default: current user)",
    )
    parser.add_argument(
        "--key", "-k",
        default=os.path.expanduser("~/.ssh/id_rsa"),
        help="Path to SSH private key (default: ~/.ssh/id_rsa)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int, default=5,
        help="SSH connect timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int, default=30,
        help="Max parallel workers (default: 30)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output CSV file path (default: discovery_<network>_<date>.csv)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    return parser.parse_args()


def ping_host(ip, timeout=2):
    """Return True if the host responds to a single ICMP ping."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def discover_live_hosts(network, timeout=2, max_workers=50):
    """Ping sweep a /24 network and return list of responding IPs."""
    hosts = [str(ip) for ip in network.hosts()]
    live = []
    logger.info("Ping sweeping %s (%d hosts)...", network, len(hosts))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(ping_host, ip, timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                live.append(ip)
                logger.debug("Host %s is alive", ip)

    live.sort(key=lambda x: ipaddress.IPv4Address(x))
    logger.info("Found %d live hosts", len(live))
    return live


def ssh_exec(client, command, timeout=10):
    """Execute a command over SSH and return stripped stdout, or empty string on failure."""
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()
    except Exception as e:
        logger.debug("Command failed (%s): %s", command, e)
        return ""


def parse_os_release(raw):
    """Extract PRETTY_NAME from /etc/os-release content."""
    for line in raw.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip('"')
    return "N/A"


def parse_cpu_model(raw):
    """Parse 'model name : ...' from /proc/cpuinfo."""
    for line in raw.splitlines():
        if "model name" in line:
            return line.split(":", 1)[1].strip()
    return "N/A"


def parse_mem_total(raw):
    """Parse MemTotal from /proc/meminfo, return MB as int or N/A."""
    try:
        for line in raw.splitlines():
            if "MemTotal" in line:
                kb = int(line.split()[1])
                return kb // 1024
    except (IndexError, ValueError):
        pass
    return "N/A"


def parse_mem_used(raw):
    """Parse used memory from 'free -m' output, return MB as int or N/A."""
    try:
        for line in raw.splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                return int(parts[2])
    except (IndexError, ValueError):
        pass
    return "N/A"


def parse_disk(raw):
    """Parse total and used GB from 'df -BG --total' output. Returns (total, used) or (N/A, N/A)."""
    try:
        for line in raw.splitlines():
            if line.startswith("total"):
                parts = line.split()
                total = int(parts[1].rstrip("G"))
                used = int(parts[2].rstrip("G"))
                return total, used
    except (IndexError, ValueError):
        pass
    return "N/A", "N/A"


def calc_pct(used, total):
    """Calculate percentage, handling N/A values."""
    if isinstance(used, int) and isinstance(total, int) and total > 0:
        return round(used / total * 100, 1)
    return "N/A"


def gather_bmc_info(client):
    """Attempt to detect BMC (iLO/iDRAC/IPMI) info via SSH session.

    Tries ipmitool first, falls back to dmidecode.
    Returns dict with bmc_type, bmc_ip, bmc_firmware.
    """
    result = {"bmc_type": "N/A", "bmc_ip": "N/A", "bmc_firmware": "N/A"}

    # Determine manufacturer for BMC type classification
    manufacturer = ssh_exec(client, "sudo dmidecode -s system-manufacturer 2>/dev/null").lower()
    if not manufacturer:
        manufacturer = ssh_exec(client, "dmidecode -s system-manufacturer 2>/dev/null").lower()

    def classify_bmc():
        if "hp" in manufacturer or "hewlett" in manufacturer:
            return "iLO"
        elif "dell" in manufacturer:
            return "iDRAC"
        elif manufacturer:
            return "IPMI"
        return "IPMI"

    # Tier 1: ipmitool
    ipmi_out = ssh_exec(client, "sudo ipmitool lan print 2>/dev/null")
    if not ipmi_out:
        ipmi_out = ssh_exec(client, "ipmitool lan print 2>/dev/null")

    if ipmi_out:
        for line in ipmi_out.splitlines():
            line_lower = line.lower()
            if "ip address" in line_lower and "source" not in line_lower:
                val = line.split(":", 1)[1].strip()
                if val and val != "0.0.0.0":
                    result["bmc_ip"] = val
            if "firmware" in line_lower:
                result["bmc_firmware"] = line.split(":", 1)[1].strip()

        if result["bmc_ip"] != "N/A":
            result["bmc_type"] = classify_bmc()
            return result

    # Tier 2: dmidecode type 38 (IPMI device)
    dmi_out = ssh_exec(client, "sudo dmidecode -t 38 2>/dev/null")
    if not dmi_out:
        dmi_out = ssh_exec(client, "dmidecode -t 38 2>/dev/null")

    if dmi_out and "IPMI" in dmi_out:
        result["bmc_type"] = classify_bmc()
        # dmidecode type 38 doesn't always have the IP, but confirms BMC exists
        for line in dmi_out.splitlines():
            if "base address" in line.lower():
                result["bmc_firmware"] = "detected (see ipmitool for details)"
        return result

    # Tier 3: check for management interface in ip addr
    ip_out = ssh_exec(client, "ip addr show 2>/dev/null")
    if ip_out:
        for line in ip_out.splitlines():
            line_lower = line.lower()
            if any(name in line_lower for name in ["ilo", "idrac", "bmc"]):
                result["bmc_type"] = classify_bmc()
                return result

    return result


def gather_host_info(ip, username, key_path, timeout):
    """Connect to a host via SSH and gather system information.

    Returns a dict suitable for CSV output. On connection failure,
    returns a dict with just the IP populated and N/A for everything else.
    """
    info = {col: "N/A" for col in CSV_COLUMNS}
    info["ip"] = ip

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            ip,
            username=username,
            key_filename=key_path,
            timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=True,
            allow_agent=True,
        )
    except paramiko.AuthenticationException:
        logger.warning("Authentication failed for %s — skipping", ip)
        return info
    except (paramiko.SSHException, socket.timeout, OSError) as e:
        logger.warning("SSH connection failed for %s: %s — skipping", ip, e)
        return info

    try:
        # Hostname
        info["hostname"] = ssh_exec(client, "hostname -f") or "N/A"

        # OS
        os_raw = ssh_exec(client, "cat /etc/os-release 2>/dev/null")
        info["os"] = parse_os_release(os_raw)

        # Kernel
        info["kernel"] = ssh_exec(client, "uname -r") or "N/A"

        # CPU
        cpu_raw = ssh_exec(client, "grep -m1 'model name' /proc/cpuinfo 2>/dev/null")
        info["cpu_model"] = parse_cpu_model(cpu_raw)
        info["cpu_cores"] = ssh_exec(client, "nproc 2>/dev/null") or "N/A"

        # Memory
        mem_raw = ssh_exec(client, "cat /proc/meminfo 2>/dev/null")
        info["memory_total_mb"] = parse_mem_total(mem_raw)
        free_raw = ssh_exec(client, "free -m 2>/dev/null")
        info["memory_used_mb"] = parse_mem_used(free_raw)
        info["memory_pct"] = calc_pct(info["memory_used_mb"], info["memory_total_mb"])

        # Disk
        disk_raw = ssh_exec(client, "df -BG --total 2>/dev/null")
        info["disk_total_gb"], info["disk_used_gb"] = parse_disk(disk_raw)
        info["disk_pct"] = calc_pct(info["disk_used_gb"], info["disk_total_gb"])

        # BMC (iLO/iDRAC)
        bmc = gather_bmc_info(client)
        info.update(bmc)

    except Exception as e:
        logger.error("Error gathering info from %s: %s", ip, e)
    finally:
        client.close()

    return info


def truncate(value, width):
    """Truncate a string to fit within width, adding ellipsis if needed."""
    s = str(value)
    if len(s) <= width:
        return s
    return s[:width - 1] + "\u2026"


def print_summary_table(results):
    """Print a formatted summary table of discovery results."""
    if not results:
        return

    # Define table columns: (header, data key, width, align)
    table_cols = [
        ("IP",       "ip",              15, "<"),
        ("Hostname", "hostname",        20, "<"),
        ("OS",       "os",              25, "<"),
        ("CPU",      "cpu_cores",        4, ">"),
        ("Mem (MB)", "memory_total_mb",  9, ">"),
        ("Mem %",    "memory_pct",       6, ">"),
        ("Disk (GB)","disk_total_gb",   10, ">"),
        ("Disk %",   "disk_pct",         6, ">"),
        ("BMC",      "bmc_type",         5, "<"),
        ("BMC IP",   "bmc_ip",          15, "<"),
    ]

    # Header
    header = ""
    sep = ""
    for name, _, width, align in table_cols:
        header += f"  {name:{align}{width}}"
        sep += f"  {'-' * width}"

    print(f"\n{'=' * len(sep)}")
    print("  DISCOVERY RESULTS")
    print(f"{'=' * len(sep)}")
    print(header)
    print(sep)

    # Rows
    for row in results:
        line = ""
        for _, key, width, align in table_cols:
            val = truncate(row.get(key, "N/A"), width)
            line += f"  {val:{align}{width}}"
        print(line)

    print(f"{'=' * len(sep)}\n")


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Validate network
    try:
        network = ipaddress.IPv4Network(args.network, strict=False)
    except ValueError as e:
        logger.error("Invalid network: %s", e)
        sys.exit(1)

    if network.prefixlen != 24:
        logger.error("Only /24 networks are supported (got /%d)", network.prefixlen)
        sys.exit(1)

    # Validate SSH key exists
    if not os.path.isfile(args.key):
        logger.warning("SSH key not found at %s — will rely on SSH agent", args.key)

    # Phase 1: Discover live hosts
    live_hosts = discover_live_hosts(network, timeout=2, max_workers=args.workers)

    if not live_hosts:
        logger.info("No live hosts found. Exiting.")
        sys.exit(0)

    print(f"\nDiscovered {len(live_hosts)} live hosts. Gathering system info...\n")

    # Phase 2: Gather info from each host in parallel
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(gather_host_info, ip, args.user, args.key, args.timeout): ip
            for ip in live_hosts
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                info = future.result()
                results.append(info)
                status = info["hostname"] if info["hostname"] != "N/A" else "no SSH access"
                print(f"  {ip:>15}  ->  {status}")
            except Exception as e:
                logger.error("Unexpected error for %s: %s", ip, e)

    # Sort by IP
    results.sort(key=lambda r: ipaddress.IPv4Address(r["ip"]))

    # Phase 3: Write CSV
    if args.output:
        output_path = args.output
    else:
        net_str = str(network.network_address).replace(".", "-")
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"discovery_{net_str}_{date_str}.csv"

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(results)

    # Summary table
    print_summary_table(results)

    # Summary
    accessible = sum(1 for r in results if r["hostname"] != "N/A")
    bmc_found = sum(1 for r in results if r["bmc_type"] != "N/A")

    print(f"Results written to {output_path}")
    print(f"  Total live hosts: {len(results)}")
    print(f"  SSH accessible:   {accessible}")
    print(f"  BMC detected:     {bmc_found}")


if __name__ == "__main__":
    main()
