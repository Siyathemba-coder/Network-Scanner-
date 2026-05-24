import sys
import csv
import json
import argparse
import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", PING_PARAM, "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError) as e:
        print(f"[ERROR] ping failed for {ip}: {e}")
        return False

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    except (socket.error, OSError, OverflowError):
        return False

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror):
        return None

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        sock.connect((str(ip), port))
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except (socket.error, OSError):
            pass
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        for line in banner.splitlines():
            line = line.strip()
            if line:
                return line[:120]
        return None
    except (socket.error, OSError):
        return None

def print_progress(scanned, total, bar_width=40):
    filled = int(bar_width * scanned / total)
    bar = "#" * filled + "-" * (bar_width - filled)
    sys.stdout.write(f"\r  [{bar}] {scanned}/{total} ports scanned")
    sys.stdout.flush()

def port_scan_worker(ip, ports, open_ports_list, lock, progress_counter, total):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        with lock:
            progress_counter[0] += 1
            print_progress(progress_counter[0], total)
        ports.task_done()

def host_discovery_worker(ip_queue, active_hosts, lock):
    while not ip_queue.empty():
        ip = ip_queue.get()
        if ping_host(ip):
            hostname = get_hostname(ip)
            label = f"{ip} ({hostname})" if hostname else str(ip)
            with lock:
                active_hosts.append(str(ip))
                print(f"[ACTIVE] {label}")
        ip_queue.task_done()

def scan_active_hosts(network, thread_count=50):
    all_hosts = list(ipaddress.ip_network(network, strict=False).hosts())
    total = len(all_hosts)
    active_hosts = []
    lock = threading.Lock()
    ip_queue = Queue()

    print(f"\nScanning {total} hosts for activity...")
    print("----------------------------------")

    for ip in all_hosts:
        ip_queue.put(ip)

    actual_threads = min(thread_count, total)
    for _ in range(actual_threads):
        t = threading.Thread(target=host_discovery_worker, args=(ip_queue, active_hosts, lock))
        t.daemon = True
        t.start()

    ip_queue.join()

    if not active_hosts:
        print("\nNo active hosts found.")
    return active_hosts

def scan_ports_for_host(ip, start_port, end_port, thread_count=50):
    hostname = get_hostname(ip)
    label = f"{ip} ({hostname})" if hostname else ip
    print(f"\nScanning ports on {label} with {thread_count} threads...")
    print("----------------------------------")
    port_queue = Queue()
    open_ports = []
    lock = threading.Lock()
    progress_counter = [0]
    total = end_port - start_port + 1

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    actual_threads = min(thread_count, total)
    for _ in range(actual_threads):
        t = threading.Thread(
            target=port_scan_worker,
            args=(ip, port_queue, open_ports, lock, progress_counter, total)
        )
        t.daemon = True
        t.start()

    port_queue.join()
    print()

    port_info = {}
    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {label}:")
        for port in sorted_ports:
            service = get_service_name(port)
            banner = grab_banner(ip, port)
            banner_display = f"  ->  {banner}" if banner else ""
            print(f"  {port:<6} {service}{banner_display}")
            port_info[port] = {"service": service, "banner": banner or ""}
    else:
        print(f"No open ports found on {label}")

    return {
        "hostname": hostname or "N/A",
        "ports": port_info
    }

def generate_report(network, start_port, end_port, report_data, fmt="txt", duration="N/A"):
    if fmt == "json":
        _generate_json(network, start_port, end_port, report_data, duration)
    elif fmt == "csv":
        _generate_csv(network, start_port, end_port, report_data)
    else:
        _generate_txt(network, start_port, end_port, report_data, duration)

def _generate_txt(network, start_port, end_port, report_data, duration="N/A"):
    with open("scan_report.txt", "w") as file:
        file.write("========== Network Scan Report ==========\n")
        file.write(f"Date: {datetime.now()}\n")
        file.write(f"Network: {network}\n")
        file.write(f"Port Range: {start_port}-{end_port}\n")
        file.write(f"Duration: {duration}\n")
        file.write("-----------------------------------------\n\n")

        if not report_data:
            file.write("No active hosts found.\n")
        else:
            for host, data in report_data.items():
                hostname = data.get("hostname", "N/A")
                ports = data.get("ports", {})
                file.write(f"Host: {host} ({hostname})\n")
                if ports:
                    for port, info in ports.items():
                        service = info.get("service", "unknown")
                        banner = info.get("banner", "")
                        line = f"  {port:<6} {service}"
                        if banner:
                            line += f"  ->  {banner}"
                        file.write(line + "\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")
    print("\nReport saved to scan_report.txt")

def _generate_json(network, start_port, end_port, report_data, duration="N/A"):
    output = {
        "date": str(datetime.now()),
        "network": network,
        "port_range": {"start": start_port, "end": end_port},
        "duration": duration,
        "hosts": []
    }
    for host, data in report_data.items():
        ports_list = []
        for port, info in data.get("ports", {}).items():
            ports_list.append({
                "port": port,
                "service": info.get("service", "unknown"),
                "banner": info.get("banner", "")
            })
        output["hosts"].append({
            "ip": host,
            "hostname": data.get("hostname", "N/A"),
            "open_ports": ports_list
        })
    with open("scan_report.json", "w") as f:
        json.dump(output, f, indent=2)
    print("\nReport saved to scan_report.json")

def _generate_csv(network, start_port, end_port, report_data):
    with open("scan_report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "hostname", "port", "service", "banner"])
        for host, data in report_data.items():
            hostname = data.get("hostname", "N/A")
            ports = data.get("ports", {})
            if ports:
                for port, info in ports.items():
                    writer.writerow([
                        host,
                        hostname,
                        port,
                        info.get("service", "unknown"),
                        info.get("banner", "")
                    ])
            else:
                writer.writerow([host, hostname, "", "", ""])
    print("\nReport saved to scan_report.csv")

def get_valid_network():
    while True:
        network_input = input("Enter network (e.g., 192.168.1.0/24): ").strip()
        try:
            ipaddress.ip_network(network_input, strict=False)
            return network_input
        except ValueError:
            print(f"  [!] '{network_input}' is not a valid network. Try something like 192.168.1.0/24.")

def get_valid_ports():
    while True:
        try:
            start_port = int(input("Enter start port (e.g., 1): ").strip())
            if not (1 <= start_port <= 65535):
                print("  [!] Port must be between 1 and 65535.")
                continue
            end_port = int(input("Enter end port (e.g., 1024): ").strip())
            if not (1 <= end_port <= 65535):
                print("  [!] Port must be between 1 and 65535.")
                continue
            if start_port > end_port:
                print(f"  [!] Start port ({start_port}) must be less than or equal to end port ({end_port}).")
                continue
            return start_port, end_port
        except ValueError:
            print("  [!] Please enter a valid integer.")

def get_valid_thread_count():
    print("\nThread count guide:")
    print("  10 - 30  : slow or unstable networks (WiFi, VPN, remote hosts)")
    print("  50       : default, good for most local networks")
    print("  100 - 200: fast local networks with large port ranges")
    while True:
        try:
            thread_count = int(input("Enter thread count (1-200): ").strip())
            if not (1 <= thread_count <= 200):
                print("  [!] Thread count must be between 1 and 200.")
                continue
            return thread_count
        except ValueError:
            print("  [!] Please enter a valid integer.")

def parse_args():
    parser = argparse.ArgumentParser(
        prog="network_scanner.py",
        description="Multithreaded network scanner — discovers active hosts and open ports.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-n", "--network",    help="Target network in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument("-s", "--start-port", type=int, help="Start of port range (1-65535, default: 1)",    default=None)
    parser.add_argument("-e", "--end-port",   type=int, help="End of port range (1-65535, default: 1024)",  default=None)
    parser.add_argument("-t", "--threads",    type=int, help="Number of threads (1-200, default: 50)",      default=None)
    parser.add_argument("-f", "--format",     choices=["txt", "json", "csv"], default=None,
                        help="Report format:\n  txt  - plain text (default)\n  json - structured JSON\n  csv  - one row per open port")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    report_data = {}
    fmt = "txt"
    network_input = ""
    start_port = end_port = 1

    try:
        print("\n----- Network Scanner -----\n")

        # Network
        if args.network:
            try:
                ipaddress.ip_network(args.network, strict=False)
                network_input = args.network
            except ValueError:
                print(f"  [!] Invalid network '{args.network}'. Try something like 192.168.1.0/24.")
                exit(1)
        else:
            network_input = get_valid_network()

        # Port range
        if args.start_port is not None and args.end_port is not None:
            if not (1 <= args.start_port <= 65535) or not (1 <= args.end_port <= 65535):
                print("  [!] Ports must be between 1 and 65535.")
                exit(1)
            if args.start_port > args.end_port:
                print(f"  [!] Start port ({args.start_port}) must be <= end port ({args.end_port}).")
                exit(1)
            start_port, end_port = args.start_port, args.end_port
        else:
            start_port, end_port = get_valid_ports()

        # Thread count
        if args.threads is not None:
            if not (1 <= args.threads <= 200):
                print("  [!] Thread count must be between 1 and 200.")
                exit(1)
            thread_count = args.threads
        else:
            thread_count = get_valid_thread_count()
        print(f"Using {thread_count} threads.")

        # Report format
        if args.format:
            fmt = args.format
        else:
            print("\nReport format:")
            print("  txt  : plain text (default)")
            print("  json : structured JSON, easy to parse programmatically")
            print("  csv  : spreadsheet-friendly, one row per open port")
            fmt = input("Enter report format (txt / json / csv): ").strip().lower()
            if fmt not in ("txt", "json", "csv"):
                fmt = "txt"
                print("Unrecognised format — defaulting to txt.")

        scan_start = datetime.now()

        active_hosts = scan_active_hosts(network_input, thread_count)

        for host in active_hosts:
            report_data[host] = scan_ports_for_host(host, start_port, end_port, thread_count)

        scan_end = datetime.now()
        duration = scan_end - scan_start
        total_seconds = int(duration.total_seconds())
        mins, secs = divmod(total_seconds, 60)
        duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"

        generate_report(network_input, start_port, end_port, report_data, fmt, duration_str)

        print(f"\nScan complete. Time elapsed: {duration_str}")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print(f"[!] Saving partial results to scan_report.{fmt}...")
            generate_report(network_input, start_port, end_port, report_data, fmt, "interrupted")
        exit(0)import sys
import csv
import json
import argparse
import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", PING_PARAM, "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError) as e:
        print(f"[ERROR] ping failed for {ip}: {e}")
        return False

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    except (socket.error, OSError, OverflowError):
        return False

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror):
        return None

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        sock.connect((str(ip), port))
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except (socket.error, OSError):
            pass
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        for line in banner.splitlines():
            line = line.strip()
            if line:
                return line[:120]
        return None
    except (socket.error, OSError):
        return None

def print_progress(scanned, total, bar_width=40):
    filled = int(bar_width * scanned / total)
    bar = "#" * filled + "-" * (bar_width - filled)
    sys.stdout.write(f"\r  [{bar}] {scanned}/{total} ports scanned")
    sys.stdout.flush()

def port_scan_worker(ip, ports, open_ports_list, lock, progress_counter, total):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        with lock:
            progress_counter[0] += 1
            print_progress(progress_counter[0], total)
        ports.task_done()

def host_discovery_worker(ip_queue, active_hosts, lock):
    while not ip_queue.empty():
        ip = ip_queue.get()
        if ping_host(ip):
            hostname = get_hostname(ip)
            label = f"{ip} ({hostname})" if hostname else str(ip)
            with lock:
                active_hosts.append(str(ip))
                print(f"[ACTIVE] {label}")
        ip_queue.task_done()

def scan_active_hosts(network, thread_count=50):
    all_hosts = list(ipaddress.ip_network(network, strict=False).hosts())
    total = len(all_hosts)
    active_hosts = []
    lock = threading.Lock()
    ip_queue = Queue()

    print(f"\nScanning {total} hosts for activity...")
    print("----------------------------------")

    for ip in all_hosts:
        ip_queue.put(ip)

    actual_threads = min(thread_count, total)
    for _ in range(actual_threads):
        t = threading.Thread(target=host_discovery_worker, args=(ip_queue, active_hosts, lock))
        t.daemon = True
        t.start()

    ip_queue.join()

    if not active_hosts:
        print("\nNo active hosts found.")
    return active_hosts

def scan_ports_for_host(ip, start_port, end_port, thread_count=50):
    hostname = get_hostname(ip)
    label = f"{ip} ({hostname})" if hostname else ip
    print(f"\nScanning ports on {label} with {thread_count} threads...")
    print("----------------------------------")
    port_queue = Queue()
    open_ports = []
    lock = threading.Lock()
    progress_counter = [0]
    total = end_port - start_port + 1

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    actual_threads = min(thread_count, total)
    for _ in range(actual_threads):
        t = threading.Thread(
            target=port_scan_worker,
            args=(ip, port_queue, open_ports, lock, progress_counter, total)
        )
        t.daemon = True
        t.start()

    port_queue.join()
    print()

    port_info = {}
    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {label}:")
        for port in sorted_ports:
            service = get_service_name(port)
            banner = grab_banner(ip, port)
            banner_display = f"  ->  {banner}" if banner else ""
            print(f"  {port:<6} {service}{banner_display}")
            port_info[port] = {"service": service, "banner": banner or ""}
    else:
        print(f"No open ports found on {label}")

    return {
        "hostname": hostname or "N/A",
        "ports": port_info
    }

def generate_report(network, start_port, end_port, report_data, fmt="txt"):
    if fmt == "json":
        _generate_json(network, start_port, end_port, report_data)
    elif fmt == "csv":
        _generate_csv(network, start_port, end_port, report_data)
    else:
        _generate_txt(network, start_port, end_port, report_data)

def _generate_txt(network, start_port, end_port, report_data):
    with open("scan_report.txt", "w") as file:
        file.write("========== Network Scan Report ==========\n")
        file.write(f"Date: {datetime.now()}\n")
        file.write(f"Network: {network}\n")
        file.write(f"Port Range: {start_port}-{end_port}\n")
        file.write("-----------------------------------------\n\n")

        if not report_data:
            file.write("No active hosts found.\n")
        else:
            for host, data in report_data.items():
                hostname = data.get("hostname", "N/A")
                ports = data.get("ports", {})
                file.write(f"Host: {host} ({hostname})\n")
                if ports:
                    for port, info in ports.items():
                        service = info.get("service", "unknown")
                        banner = info.get("banner", "")
                        line = f"  {port:<6} {service}"
                        if banner:
                            line += f"  ->  {banner}"
                        file.write(line + "\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")
    print("\nReport saved to scan_report.txt")

def _generate_json(network, start_port, end_port, report_data):
    output = {
        "date": str(datetime.now()),
        "network": network,
        "port_range": {"start": start_port, "end": end_port},
        "hosts": []
    }
    for host, data in report_data.items():
        ports_list = []
        for port, info in data.get("ports", {}).items():
            ports_list.append({
                "port": port,
                "service": info.get("service", "unknown"),
                "banner": info.get("banner", "")
            })
        output["hosts"].append({
            "ip": host,
            "hostname": data.get("hostname", "N/A"),
            "open_ports": ports_list
        })
    with open("scan_report.json", "w") as f:
        json.dump(output, f, indent=2)
    print("\nReport saved to scan_report.json")

def _generate_csv(network, start_port, end_port, report_data):
    with open("scan_report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "hostname", "port", "service", "banner"])
        for host, data in report_data.items():
            hostname = data.get("hostname", "N/A")
            ports = data.get("ports", {})
            if ports:
                for port, info in ports.items():
                    writer.writerow([
                        host,
                        hostname,
                        port,
                        info.get("service", "unknown"),
                        info.get("banner", "")
                    ])
            else:
                writer.writerow([host, hostname, "", "", ""])
    print("\nReport saved to scan_report.csv")

def get_valid_network():
    while True:
        network_input = input("Enter network (e.g., 192.168.1.0/24): ").strip()
        try:
            ipaddress.ip_network(network_input, strict=False)
            return network_input
        except ValueError:
            print(f"  [!] '{network_input}' is not a valid network. Try something like 192.168.1.0/24.")

def get_valid_ports():
    while True:
        try:
            start_port = int(input("Enter start port (e.g., 1): ").strip())
            if not (1 <= start_port <= 65535):
                print("  [!] Port must be between 1 and 65535.")
                continue
            end_port = int(input("Enter end port (e.g., 1024): ").strip())
            if not (1 <= end_port <= 65535):
                print("  [!] Port must be between 1 and 65535.")
                continue
            if start_port > end_port:
                print(f"  [!] Start port ({start_port}) must be less than or equal to end port ({end_port}).")
                continue
            return start_port, end_port
        except ValueError:
            print("  [!] Please enter a valid integer.")

def get_valid_thread_count():
    print("\nThread count guide:")
    print("  10 - 30  : slow or unstable networks (WiFi, VPN, remote hosts)")
    print("  50       : default, good for most local networks")
    print("  100 - 200: fast local networks with large port ranges")
    while True:
        try:
            thread_count = int(input("Enter thread count (1-200): ").strip())
            if not (1 <= thread_count <= 200):
                print("  [!] Thread count must be between 1 and 200.")
                continue
            return thread_count
        except ValueError:
            print("  [!] Please enter a valid integer.")

def parse_args():
    parser = argparse.ArgumentParser(
        prog="network_scanner.py",
        description="Multithreaded network scanner — discovers active hosts and open ports.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-n", "--network",    help="Target network in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument("-s", "--start-port", type=int, help="Start of port range (1-65535, default: 1)",    default=None)
    parser.add_argument("-e", "--end-port",   type=int, help="End of port range (1-65535, default: 1024)",  default=None)
    parser.add_argument("-t", "--threads",    type=int, help="Number of threads (1-200, default: 50)",      default=None)
    parser.add_argument("-f", "--format",     choices=["txt", "json", "csv"], default=None,
                        help="Report format:\n  txt  - plain text (default)\n  json - structured JSON\n  csv  - one row per open port")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    report_data = {}
    fmt = "txt"
    network_input = ""
    start_port = end_port = 1

    try:
        print("\n----- Network Scanner -----\n")

        # Network
        if args.network:
            try:
                ipaddress.ip_network(args.network, strict=False)
                network_input = args.network
            except ValueError:
                print(f"  [!] Invalid network '{args.network}'. Try something like 192.168.1.0/24.")
                exit(1)
        else:
            network_input = get_valid_network()

        # Port range
        if args.start_port is not None and args.end_port is not None:
            if not (1 <= args.start_port <= 65535) or not (1 <= args.end_port <= 65535):
                print("  [!] Ports must be between 1 and 65535.")
                exit(1)
            if args.start_port > args.end_port:
                print(f"  [!] Start port ({args.start_port}) must be <= end port ({args.end_port}).")
                exit(1)
            start_port, end_port = args.start_port, args.end_port
        else:
            start_port, end_port = get_valid_ports()

        # Thread count
        if args.threads is not None:
            if not (1 <= args.threads <= 200):
                print("  [!] Thread count must be between 1 and 200.")
                exit(1)
            thread_count = args.threads
        else:
            thread_count = get_valid_thread_count()
        print(f"Using {thread_count} threads.")

        # Report format
        if args.format:
            fmt = args.format
        else:
            print("\nReport format:")
            print("  txt  : plain text (default)")
            print("  json : structured JSON, easy to parse programmatically")
            print("  csv  : spreadsheet-friendly, one row per open port")
            fmt = input("Enter report format (txt / json / csv): ").strip().lower()
            if fmt not in ("txt", "json", "csv"):
                fmt = "txt"
                print("Unrecognised format — defaulting to txt.")

        active_hosts = scan_active_hosts(network_input, thread_count)

        for host in active_hosts:
            report_data[host] = scan_ports_for_host(host, start_port, end_port, thread_count)

        generate_report(network_input, start_port, end_port, report_data, fmt)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print(f"[!] Saving partial results to scan_report.{fmt}...")
            generate_report(network_input, start_port, end_port, report_data, fmt)
        exit(0)
