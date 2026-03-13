# scripts
Various Scripts

## discover.py

Scans a /24 network or single host (/32), connects to live hosts via SSH, and gathers system inventory (hostname, OS, CPU, memory, disk, iLO/iDRAC). Outputs CSV for Google Sheets import.

### Setup

```bash
pip install -r requirements.txt
```

### Usage

```bash
# Basic scan of a /24 network
python3 discover.py 192.168.1.0/24

# Scan a single host
python3 discover.py 10.0.5.42/32

# Specify SSH user and key
python3 discover.py 10.0.5.0/24 --user admin --key ~/.ssh/lab_key

# Custom output file and more parallelism
python3 discover.py 10.0.5.0/24 --output lab_inventory.csv --workers 50

# Verbose logging
python3 discover.py 192.168.1.0/24 -v
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--user`, `-u` | current user | SSH username |
| `--key`, `-k` | `~/.ssh/id_rsa` | SSH private key path |
| `--timeout`, `-t` | 5 | SSH connect timeout (seconds) |
| `--workers`, `-w` | 30 | Max parallel threads |
| `--output`, `-o` | auto-generated | Output CSV file path |
| `--verbose`, `-v` | off | Debug logging |

### CSV Columns

`ip`, `hostname`, `os`, `kernel`, `form_factor`, `manufacturer`, `model`, `serial_number`, `cpu_model`, `cpu_cores`, `memory_total_mb`, `memory_used_mb`, `disk_total_gb`, `disk_used_gb`, `pci_devices`, `bmc_type`, `bmc_ip`, `bmc_firmware`

### BMC Detection

The script attempts to detect out-of-band management (iLO, iDRAC, IPMI) using:

1. `ipmitool lan print` (most reliable, may need sudo)
2. `dmidecode -t 38` (confirms BMC exists)
3. Network interface names (looks for ilo/idrac/bmc interfaces)

The `bmc_type` field is classified based on the system manufacturer (HP -> iLO, Dell -> iDRAC, other -> IPMI).
