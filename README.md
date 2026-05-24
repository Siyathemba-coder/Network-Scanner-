# Network Scanner (Python)

A multithreaded network scanner that discovers active hosts and open ports across a user-specified subnet. Built for learning purposes and local network analysis.

---

## Features

- **Threaded host discovery** - pings all IPs in a subnet in parallel
- **Threaded port scanning** - scans port ranges concurrently per host
- **Service name resolution** - identifies services on open ports (e.g. `80 → http`)
- **Hostname resolution** - shows device names alongside IPs
- **Banner grabbing** - detects software running on open ports (e.g. `SSH-2.0-OpenSSH_9.1`)
- **Scan duration timer** - shows total time elapsed at the end of every scan
- **Three report formats** - plain text, JSON, and CSV output
- **CLI + interactive modes** - pass arguments directly or be prompted step by step
- **Input validation** - rejects invalid networks, port ranges, and thread counts
- **Clean Ctrl+C exit** - saves partial results if scan is interrupted
- Cross-platform (Windows / Linux / macOS)
- No external dependencies - standard library only

---

## How to Run

### Interactive mode (prompted)
```bash
python3 network_scanner.py
```

### CLI mode (all arguments passed directly)
```bash
python3 network_scanner.py -n 192.168.1.0/24 -s 1 -e 1024 -t 50 -f json
```

### Mix — supply some arguments, get prompted for the rest
```bash
python3 network_scanner.py -n 192.168.1.0/24 -f csv
```

---

## CLI Arguments

| Flag | Long form | Description |
|------|-----------|-------------|
| `-n` | `--network` | Target network in CIDR notation (e.g. `192.168.1.0/24`) |
| `-s` | `--start-port` | Start of port range (1–65535, default: 1) |
| `-e` | `--end-port` | End of port range (1–65535, default: 1024) |
| `-t` | `--threads` | Number of threads (1–200, default: 50) |
| `-f` | `--format` | Report format: `txt`, `json`, or `csv` |
| `-h` | `--help` | Show help message and exit |

---

## Thread Count Guide

| Range | When to use |
|-------|-------------|
| 10–30 | Slow or unstable networks (WiFi, VPN, remote hosts) |
| 50 | Default — good for most local networks |
| 100–200 | Fast local networks with large port ranges |

---

## Report Formats

| Format | File | Best for |
|--------|------|----------|
| `txt` | `scan_report.txt` | Human-readable, quick review |
| `json` | `scan_report.json` | Parsing programmatically or feeding into other tools |
| `csv` | `scan_report.csv` | Opening in Excel or Google Sheets |

All reports include: date, network, port range, scan duration, hostnames, open ports, service names, and banners.

---

## Technologies Used

- `socket` — TCP port scanning, service names, hostname resolution, banner grabbing
- `subprocess` — host discovery via ping
- `threading` — concurrent host discovery and port scanning
- `ipaddress` — network and IP handling
- `argparse` — CLI argument parsing
- `json` / `csv` — report generation

---

## Legal Notice

For educational and authorized use only. Only scan networks you own or have explicit permission to scan.
# Network Scanner (Python)

A complete multithreaded network scanning tool that performs both host discovery and port scanning across a user-specified IP range. This tool was built for learning purposes and for analysing small, local networks.

---

## 🔍 Features
- Detects all active devices on a given subnet
- Performs multithreaded TCP port scanning on each active host
- User inputs IP range and port range
- Structured, readable output for analysis
- Cross-platform (Windows/Linux/macOS)
- Fast, lightweight, and simple to use

---

## 🛠 Technologies Used
- Python
- `socket` for TCP port scanning
- `subprocess` for host discovery
- `threading` for concurrency
- `ipaddress` for network handling

---

## How to Run
```
python3 network_scanner.py
```

## Legal Notice
For educational and authorized use only.

