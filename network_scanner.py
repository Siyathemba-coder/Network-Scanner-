import sys
import csv
import json
import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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
        # Some services (HTTP) need a nudge to send a banner
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except (socket.error, OSError):
            pass
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        # Return first non-empty line only
        for line in banner.splitlines():
            line = line.strip()
            if line:
                return line[:120]  # cap length
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

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            hostname = get_hostname(ip)
            label = f"{ip} ({hostname})" if hostname else str(ip)
            print(f"[ACTIVE] {label}")
            active_hosts.append(str(ip))
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
    print()  # newline after progress bar

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {label}:")
        port_info = {}
        for port in sorted_ports:
            service = get_service_name(port)
            banner = grab_banner(ip, port)
            banner_display = f"  ->  {banner}" if banner else ""
            print(f"  {port:<6} {service}{banner_display}")
            port_info[port] = {"service": service, "banner": banner or ""}
        report_data[ip] = {
            "hostname": hostname or "N/A",
            "ports": port_info
        }
    else:
        print(f"No open ports found on {label}")
        report_data[ip] = {"hostname": hostname or "N/A", "ports": {}}

    return open_ports

def generate_report(network, start_port, end_port, fmt="txt"):
    if fmt == "json":
        _generate_json(network, start_port, end_port)
    elif fmt == "csv":
        _generate_csv(network, start_port, end_port)
    else:
        _generate_txt(network, start_port, end_port)

def _generate_txt(network, start_port, end_port):
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
                        service = info.get("service", "unknown") if isinstance(info, dict) else info
                        banner = info.get("banner", "") if isinstance(info, dict) else ""
                        line = f"  {port:<6} {service}"
                        if banner:
                            line += f"  ->  {banner}"
                        file.write(line + "\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")
    print("\nReport saved to scan_report.txt")

def _generate_json(network, start_port, end_port):
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

def _generate_csv(network, start_port, end_port):
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

if __name__ == "__main__":
    try:
        print("\n----- Network Scanner -----\n")
        network_input = input("Enter network (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter start port (e.g., 1): "))
        end_port = int(input("Enter end port (e.g., 1024): "))
        print("\nThread count guide:")
        print("  10 - 30  : slow or unstable networks (WiFi, VPN, remote hosts)")
        print("  50       : default, good for most local networks")
        print("  100 - 200: fast local networks with large port ranges")
        thread_count = int(input("Enter thread count (1-200): "))
        thread_count = max(1, min(thread_count, 200))
        print(f"Using {thread_count} threads.")

        print("\nReport format:")
        print("  txt  : plain text (default)")
        print("  json : structured JSON, easy to parse programmatically")
        print("  csv  : spreadsheet-friendly, one row per open port")
        fmt = input("Enter report format (txt / json / csv): ").strip().lower()
        if fmt not in ("txt", "json", "csv"):
            fmt = "txt"
            print("Unrecognised format — defaulting to txt.")

        active_hosts = scan_active_hosts(network_input)

        for host in active_hosts:
            scan_ports_for_host(host, start_port, end_port, thread_count)

        generate_report(network_input, start_port, end_port, fmt)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print(f"[!] Saving partial results to scan_report.{fmt}...")
            generate_report(network_input, start_port, end_port, fmt)
        exit(0)import sys
import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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
        # Some services (HTTP) need a nudge to send a banner
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except (socket.error, OSError):
            pass
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        # Return first non-empty line only
        for line in banner.splitlines():
            line = line.strip()
            if line:
                return line[:120]  # cap length
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

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            hostname = get_hostname(ip)
            label = f"{ip} ({hostname})" if hostname else str(ip)
            print(f"[ACTIVE] {label}")
            active_hosts.append(str(ip))
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
    print()  # newline after progress bar

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {label}:")
        port_info = {}
        for port in sorted_ports:
            service = get_service_name(port)
            banner = grab_banner(ip, port)
            banner_display = f"  ->  {banner}" if banner else ""
            print(f"  {port:<6} {service}{banner_display}")
            port_info[port] = {"service": service, "banner": banner or ""}
        report_data[ip] = {
            "hostname": hostname or "N/A",
            "ports": port_info
        }
    else:
        print(f"No open ports found on {label}")
        report_data[ip] = {"hostname": hostname or "N/A", "ports": {}}

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
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
                        service = info.get("service", "unknown") if isinstance(info, dict) else info
                        banner = info.get("banner", "") if isinstance(info, dict) else ""
                        line = f"  {port:<6} {service}"
                        if banner:
                            line += f"  ->  {banner}"
                        file.write(line + "\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    try:
        print("\n----- Network Scanner -----\n")
        network_input = input("Enter network (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter start port (e.g., 1): "))
        end_port = int(input("Enter end port (e.g., 1024): "))
        print("\nThread count guide:")
        print("  10 - 30  : slow or unstable networks (WiFi, VPN, remote hosts)")
        print("  50       : default, good for most local networks")
        print("  100 - 200: fast local networks with large port ranges")
        thread_count = int(input("Enter thread count (1-200): "))
        thread_count = max(1, min(thread_count, 200))
        print(f"Using {thread_count} threads.")

        active_hosts = scan_active_hosts(network_input)

        for host in active_hosts:
            scan_ports_for_host(host, start_port, end_port, thread_count)

        generate_report(network_input, start_port, end_port)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print("[!] Saving partial results to scan_report.txt...")
            generate_report(network_input, start_port, end_port)
        exit(0)import sys
import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            hostname = get_hostname(ip)
            label = f"{ip} ({hostname})" if hostname else str(ip)
            print(f"[ACTIVE] {label}")
            active_hosts.append(str(ip))
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
    print()  # newline after progress bar

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {label}:")
        for port in sorted_ports:
            service = get_service_name(port)
            print(f"  {port:<6} {service}")
        report_data[ip] = {
            "hostname": hostname or "N/A",
            "ports": {p: get_service_name(p) for p in sorted_ports}
        }
    else:
        print(f"No open ports found on {label}")
        report_data[ip] = {"hostname": hostname or "N/A", "ports": {}}

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
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
                    for port, service in ports.items():
                        file.write(f"  {port:<6} {service}\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    try:
        print("\n----- Network Scanner -----\n")
        network_input = input("Enter network (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter start port (e.g., 1): "))
        end_port = int(input("Enter end port (e.g., 1024): "))
        print("\nThread count guide:")
        print("  10 - 30  : slow or unstable networks (WiFi, VPN, remote hosts)")
        print("  50       : default, good for most local networks")
        print("  100 - 200: fast local networks with large port ranges")
        thread_count = int(input("Enter thread count (1-200): "))
        thread_count = max(1, min(thread_count, 200))
        print(f"Using {thread_count} threads.")

        active_hosts = scan_active_hosts(network_input)

        for host in active_hosts:
            scan_ports_for_host(host, start_port, end_port, thread_count)

        generate_report(network_input, start_port, end_port)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print("[!] Saving partial results to scan_report.txt...")
            generate_report(network_input, start_port, end_port)
        exit(0)import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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

def port_scan_worker(ip, ports, open_ports_list, lock):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        ports.task_done()

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            hostname = get_hostname(ip)
            label = f"{ip} ({hostname})" if hostname else str(ip)
            print(f"[ACTIVE] {label}")
            active_hosts.append(str(ip))
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

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    actual_threads = min(thread_count, end_port - start_port + 1)
    for _ in range(actual_threads):
        t = threading.Thread(target=port_scan_worker, args=(ip, port_queue, open_ports, lock))
        t.daemon = True
        t.start()

    port_queue.join()

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {label}:")
        for port in sorted_ports:
            service = get_service_name(port)
            print(f"  {port:<6} {service}")
        report_data[ip] = {
            "hostname": hostname or "N/A",
            "ports": {p: get_service_name(p) for p in sorted_ports}
        }
    else:
        print(f"No open ports found on {label}")
        report_data[ip] = {"hostname": hostname or "N/A", "ports": {}}

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
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
                    for port, service in ports.items():
                        file.write(f"  {port:<6} {service}\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    try:
        print("\n----- Network Scanner -----\n")
        network_input = input("Enter network (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter start port (e.g., 1): "))
        end_port = int(input("Enter end port (e.g., 1024): "))
        print("\nThread count guide:")
        print("  10 - 30  : slow or unstable networks (WiFi, VPN, remote hosts)")
        print("  50       : default, good for most local networks")
        print("  100 - 200: fast local networks with large port ranges")
        thread_count = int(input("Enter thread count (1-200): "))
        thread_count = max(1, min(thread_count, 200))
        print(f"Using {thread_count} threads.")

        active_hosts = scan_active_hosts(network_input)

        for host in active_hosts:
            scan_ports_for_host(host, start_port, end_port, thread_count)

        generate_report(network_input, start_port, end_port)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print("[!] Saving partial results to scan_report.txt...")
            generate_report(network_input, start_port, end_port)
        exit(0)
import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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

def port_scan_worker(ip, ports, open_ports_list, lock):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        ports.task_done()

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            hostname = get_hostname(ip)
            label = f"{ip} ({hostname})" if hostname else str(ip)
            print(f"[ACTIVE] {label}")
            active_hosts.append(str(ip))
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

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    actual_threads = min(thread_count, end_port - start_port + 1)
    for _ in range(actual_threads):
        t = threading.Thread(target=port_scan_worker, args=(ip, port_queue, open_ports, lock))
        t.daemon = True
        t.start()

    port_queue.join()

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {label}:")
        for port in sorted_ports:
            service = get_service_name(port)
            print(f"  {port:<6} {service}")
        report_data[ip] = {
            "hostname": hostname or "N/A",
            "ports": {p: get_service_name(p) for p in sorted_ports}
        }
    else:
        print(f"No open ports found on {label}")
        report_data[ip] = {"hostname": hostname or "N/A", "ports": {}}

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
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
                    for port, service in ports.items():
                        file.write(f"  {port:<6} {service}\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    try:
        print("\n----- Network Scanner -----\n")
        network_input = input("Enter network (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter start port (e.g., 1): "))
        end_port = int(input("Enter end port (e.g., 1024): "))
        print("\nThread count guide:")
        print("  10 - 30  : slow or unstable networks (WiFi, VPN, remote hosts)")
        print("  50       : default, good for most local networks")
        print("  100 - 200: fast local networks with large port ranges")
        thread_count = int(input("Enter thread count (1-200): "))
        thread_count = max(1, min(thread_count, 200))
        print(f"Using {thread_count} threads.")

        active_hosts = scan_active_hosts(network_input)

        for host in active_hosts:
            scan_ports_for_host(host, start_port, end_port, thread_count)

        generate_report(network_input, start_port, end_port)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print("[!] Saving partial results to scan_report.txt...")
            generate_report(network_input, start_port, end_port)
        exit(0)
import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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

def port_scan_worker(ip, ports, open_ports_list, lock):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        ports.task_done()

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            hostname = get_hostname(ip)
            label = f"{ip} ({hostname})" if hostname else str(ip)
            print(f"[ACTIVE] {label}")
            active_hosts.append(str(ip))
    if not active_hosts:
        print("\nNo active hosts found.")
    return active_hosts

def scan_ports_for_host(ip, start_port, end_port):
    hostname = get_hostname(ip)
    label = f"{ip} ({hostname})" if hostname else ip
    print(f"\nScanning ports on {label}...")
    print("----------------------------------")
    port_queue = Queue()
    open_ports = []
    lock = threading.Lock()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    for _ in range(50):
        t = threading.Thread(target=port_scan_worker, args=(ip, port_queue, open_ports, lock))
        t.daemon = True
        t.start()

    port_queue.join()

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {label}:")
        for port in sorted_ports:
            service = get_service_name(port)
            print(f"  {port:<6} {service}")
        report_data[ip] = {
            "hostname": hostname or "N/A",
            "ports": {p: get_service_name(p) for p in sorted_ports}
        }
    else:
        print(f"No open ports found on {label}")
        report_data[ip] = {"hostname": hostname or "N/A", "ports": {}}

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
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
                    for port, service in ports.items():
                        file.write(f"  {port:<6} {service}\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    try:
        print("\n----- Network Scanner -----\n")
        network_input = input("Enter network (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter start port (e.g., 1): "))
        end_port = int(input("Enter end port (e.g., 1024): "))

        active_hosts = scan_active_hosts(network_input)

        for host in active_hosts:
            scan_ports_for_host(host, start_port, end_port)

        generate_report(network_input, start_port, end_port)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print("[!] Saving partial results to scan_report.txt...")
            generate_report(network_input, start_port, end_port)
        exit(0)import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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

def port_scan_worker(ip, ports, open_ports_list, lock):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        ports.task_done()

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            print(f"[ACTIVE] {ip}")
            active_hosts.append(str(ip))
    if not active_hosts:
        print("\nNo active hosts found.")
    return active_hosts

def scan_ports_for_host(ip, start_port, end_port):
    print(f"\nScanning ports on {ip}...")
    print("----------------------------------")
    port_queue = Queue()
    open_ports = []
    lock = threading.Lock()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    for _ in range(50):
        t = threading.Thread(target=port_scan_worker, args=(ip, port_queue, open_ports, lock))
        t.daemon = True
        t.start()

    port_queue.join()

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {ip}:")
        for port in sorted_ports:
            service = get_service_name(port)
            print(f"  {port:<6} {service}")
        report_data[ip] = {p: get_service_name(p) for p in sorted_ports}
    else:
        print(f"No open ports found on {ip}")
        report_data[ip] = {}

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
    with open("scan_report.txt", "w") as file:
        file.write("========== Network Scan Report ==========\n")
        file.write(f"Date: {datetime.now()}\n")
        file.write(f"Network: {network}\n")
        file.write(f"Port Range: {start_port}-{end_port}\n")
        file.write("-----------------------------------------\n\n")

        if not report_data:
            file.write("No active hosts found.\n")
        else:
            for host, ports in report_data.items():
                file.write(f"Host: {host}\n")
                if ports:
                    for port, service in ports.items():
                        file.write(f"  {port:<6} {service}\n")
                else:
                    file.write("  Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    try:
        print("\n----- Network Scanner -----\n")
        network_input = input("Enter network (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter start port (e.g., 1): "))
        end_port = int(input("Enter end port (e.g., 1024): "))

        active_hosts = scan_active_hosts(network_input)

        for host in active_hosts:
            scan_ports_for_host(host, start_port, end_port)

        generate_report(network_input, start_port, end_port)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print("[!] Saving partial results to scan_report.txt...")
            generate_report(network_input, start_port, end_port)
        exit(0)import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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

def port_scan_worker(ip, ports, open_ports_list, lock):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        ports.task_done()

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            print(f"[ACTIVE] {ip}")
            active_hosts.append(str(ip))
    if not active_hosts:
        print("\nNo active hosts found.")
    return active_hosts

def scan_ports_for_host(ip, start_port, end_port):
    print(f"\nScanning ports on {ip}...")
    print("----------------------------------")
    port_queue = Queue()
    open_ports = []
    lock = threading.Lock()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    for _ in range(50):
        t = threading.Thread(target=port_scan_worker, args=(ip, port_queue, open_ports, lock))
        t.daemon = True
        t.start()

    port_queue.join()

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {ip}: {sorted_ports}")
        report_data[ip] = sorted_ports
    else:
        print(f"No open ports found on {ip}")
        report_data[ip] = []

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
    with open("scan_report.txt", "w") as file:
        file.write("========== Network Scan Report ==========\n")
        file.write(f"Date: {datetime.now()}\n")
        file.write(f"Network: {network}\n")
        file.write(f"Port Range: {start_port}-{end_port}\n")
        file.write("-----------------------------------------\n\n")

        if not report_data:
            file.write("No active hosts found.\n")
        else:
            for host, ports in report_data.items():
                file.write(f"Host: {host}\n")
                if ports:
                    file.write(f"Open Ports: {ports}\n")
                else:
                    file.write("Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    try:
        print("\n----- Network Scanner -----\n")
        network_input = input("Enter network (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter start port (e.g., 1): "))
        end_port = int(input("Enter end port (e.g., 1024): "))

        active_hosts = scan_active_hosts(network_input)

        for host in active_hosts:
            scan_ports_for_host(host, start_port, end_port)

        generate_report(network_input, start_port, end_port)

        print("\nScan complete.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting cleanly.")
        if report_data:
            print("[!] Saving partial results to scan_report.txt...")
            generate_report(network_input, start_port, end_port)
        exit(0)import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime 

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

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

def port_scan_worker(ip, ports, open_ports_list, lock):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        ports.task_done()

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            print(f"[ACTIVE] {ip}")
            active_hosts.append(str(ip))
    if not active_hosts:
        print("\nNo active hosts found.")
    return active_hosts

def scan_ports_for_host(ip, start_port, end_port):
    print(f"\nScanning ports on {ip}...")
    print("----------------------------------")
    port_queue = Queue()
    open_ports = []
    lock = threading.Lock()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    for _ in range(50):
        t = threading.Thread(target=port_scan_worker, args=(ip, port_queue, open_ports, lock))
        t.daemon = True
        t.start()

    port_queue.join()

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {ip}: {sorted_ports}")
        report_data[ip] = sorted_ports 
    else:
        print(f"No open ports found on {ip}")
        report_data[ip] = []  

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
    with open("scan_report.txt", "w") as file:
        file.write("========== Network Scan Report ==========\n")
        file.write(f"Date: {datetime.now()}\n")
        file.write(f"Network: {network}\n")
        file.write(f"Port Range: {start_port}-{end_port}\n")
        file.write("-----------------------------------------\n\n")

        if not report_data:
            file.write("No active hosts found.\n")
        else:
            for host, ports in report_data.items():
                file.write(f"Host: {host}\n")
                if ports:
                    file.write(f"Open Ports: {ports}\n")
                else:
                    file.write("Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    print("\n----- Network Scanner -----\n")
    network_input = input("Enter network (e.g., 192.168.1.0/24): ")
    start_port = int(input("Enter start port (e.g., 1): "))
    end_port = int(input("Enter end port (e.g., 1024): "))

    active_hosts = scan_active_hosts(network_input)

    for host in active_hosts:
        scan_ports_for_host(host, start_port, end_port)

    generate_report(network_input, start_port, end_port)  # Generating a report for host and port analysis 

    print("\nScan complete.")import ipaddress
import socket
import threading
import subprocess
import platform
from queue import Queue
from datetime import datetime 

PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"

# Global report storage
report_data = {}

def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", PING_PARAM, "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    except:
        return False

def port_scan_worker(ip, ports, open_ports_list, lock):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
            with lock:
                open_ports_list.append(port)
        ports.task_done()

def scan_active_hosts(network):
    active_hosts = []
    print("\nScanning for active hosts...")
    print("----------------------------------")
    for ip in ipaddress.ip_network(network, strict=False).hosts():
        if ping_host(ip):
            print(f"[ACTIVE] {ip}")
            active_hosts.append(str(ip))
    if not active_hosts:
        print("\nNo active hosts found.")
    return active_hosts

def scan_ports_for_host(ip, start_port, end_port):
    print(f"\nScanning ports on {ip}...")
    print("----------------------------------")
    port_queue = Queue()
    open_ports = []
    lock = threading.Lock()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    for _ in range(50):
        t = threading.Thread(target=port_scan_worker, args=(ip, port_queue, open_ports, lock))
        t.daemon = True
        t.start()

    port_queue.join()

    if open_ports:
        sorted_ports = sorted(open_ports)
        print(f"Open ports on {ip}: {sorted_ports}")
        report_data[ip] = sorted_ports 
    else:
        print(f"No open ports found on {ip}")
        report_data[ip] = []  

    return open_ports

# Basic report generator
def generate_report(network, start_port, end_port):
    with open("scan_report.txt", "w") as file:
        file.write("========== Network Scan Report ==========\n")
        file.write(f"Date: {datetime.now()}\n")
        file.write(f"Network: {network}\n")
        file.write(f"Port Range: {start_port}-{end_port}\n")
        file.write("-----------------------------------------\n\n")

        if not report_data:
            file.write("No active hosts found.\n")
        else:
            for host, ports in report_data.items():
                file.write(f"Host: {host}\n")
                if ports:
                    file.write(f"Open Ports: {ports}\n")
                else:
                    file.write("Open Ports: None\n")
                file.write("\n")

        file.write("========== End of Report ==========\n")

    print("\nReport saved to scan_report.txt")

if __name__ == "__main__":
    print("\n----- Network Scanner -----\n")
    network_input = input("Enter network (e.g., 192.168.1.0/24): ")
    start_port = int(input("Enter start port (e.g., 1): "))
    end_port = int(input("Enter end port (e.g., 1024): "))

    active_hosts = scan_active_hosts(network_input)

    for host in active_hosts:
        scan_ports_for_host(host, start_port, end_port)

    generate_report(network_input, start_port, end_port)  # Generating a report for host and port analysis 

    print("\nScan complete.")
