from cgi import print_arguments
import socket
import requests
import nmap
from datetime import datetime

def port_scan(target, start_port, end_port):
    print(f'Scanning target: {target} for open ports from {start_port} to {end_port} ...')
    open_ports = []
    for port in range(start_port, end_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def banner_grab(target, port):
    print(f"Grabbing banner for {target}:{port} ...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        sock.settimeout(2)
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner.strip()
    except:
        return None



def network_scan(target, start_port, end_port):
    #ask user to proved start_port and end_port numer
    print(f"Starting network scan for target: {target} ...")
    start_time = datetime.now()

    open_ports = port_scan(target, start_port, end_port)
    if open_ports:
        print(f"Open ports found: {open_ports}")
    else:
        print("No open ports found.")

    for port in open_ports:
        banner = banner_grab(target, port)
        if banner:
            print(f"Banner for {target}:{port} - {banner}")
        else:
            print(f"No banner found for {target}:{port}")
    vul_info = vulnerability_scan(target)
    if vul_info:
        if 'hostnames' in vul_info:
            print(f"Hostnames: {vul_info['hostnames']}")
        if 'osmatch' in vul_info:
            print(f"Operating system: {vul_info['osmatch']}")
        if 'vulns' in vul_info:
            print(f"Vulnerabilities: {vul_info['vulns']}")
    else:
        print("No vulnerability information found.")
    end_time = datetime.now()
    print(f"Scan completed in {end_time - start_time}")

def vulnerability_scan(target):
    print(f"Scanning for vulnerabilities on {target} ...")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='O -sV --script vuln')
        return nm[target]
    except Exception as e:
        print(f"Error scanning for vulnerabilities: {e}")
        return None

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    start_port = int(input("Enter the start port number: "))
    end_port = int(input("Enter the end port number: "))

    network_scan(target_ip, start_port, end_port)

