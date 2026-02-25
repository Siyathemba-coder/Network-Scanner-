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

def port_scan_worker(ip, ports, open_ports_list):
    while not ports.empty():
        port = ports.get()
        if scan_port(ip, port):
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

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    for _ in range(50):
        t = threading.Thread(target=port_scan_worker, args=(ip, port_queue, open_ports))
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
