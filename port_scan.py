#!usr/bin/env python
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP

def syn_scan(ports, target):
    open_ports = []
    closed_ports = 0
    print("SYN SCAN......")
    for port in ports:
        resp = sr1(IP(dst=target) / TCP(dport=port, flags="S"), verbose=0, timeout=1)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:  # 0x12 corresponds to "SA" flags
            open_ports.append(port)
        else:
            closed_ports += 1
    return open_ports, [], closed_ports


def fin_scan(ports, target):
    open_ports = []
    closed_ports = 0
    filtered_ports = []
    print("FIN SCAN......")
    for port in ports:
        resp = sr1(IP(dst=target) / TCP(dport=port, flags='F'), timeout=1, verbose=0)
        if not resp:
            open_ports.append(port)
        elif TCP in resp and resp[TCP].flags == 0x14:
            closed_ports += 1
        elif ICMP in resp and resp[ICMP].type == 3 and resp[ICMP].code in [1, 2, 3, 9, 10, 13]:
            filtered_ports.append(port)
        else:
            closed_ports += 1
    return open_ports, filtered_ports, closed_ports


def xmas_scan(ports, target):
    open_ports = []
    closed_ports = 0
    filtered_port = []
    print("XMAS SCAN......")
    for port in ports:
        resp = sr1(IP(dst=target) / TCP(dport=port, flags='UPF'), verbose=0, timeout=1)
        if resp is None:
            open_ports.append(port)
        elif resp.getlayer(TCP).flags == 0x14:
            closed_ports += 1
        else:
            if resp.haslayer(ICMP) and (int(resp.getlayer(ICMP).type) == 3 and int(
                    resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                filtered_port.append(port)
            else:
                closed_ports += 1
    return open_ports, filtered_port, closed_ports


def null_scan(ports, target):
    open_ports = []
    closed_ports = 0
    filtered_port = []
    print("NULL SCAN......")
    for port in ports:
        resp = sr1(IP(dst=target) / TCP(dport=port, flags=''), verbose=0, timeout=1)
        if resp is None:
            open_ports.append(port)
        elif resp.getlayer(TCP).flags == 0x14:
            closed_ports += 1
        else:
            if resp.haslayer(ICMP) and (int(resp.getlayer(ICMP).type) == 3 and int(
                    resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                filtered_port.append(port)
            else:
                closed_ports += 1
    return open_ports, filtered_port, closed_ports


def portscan(target, port1, portn, scan_type):
    ports = range(port1, portn + 1)  # Inclure portn dans la plage
    print(f"Performing {scan_type} scan for: {target}")

    scan_functions = {
        "syn": syn_scan,
        "xmas": xmas_scan,
        "fin": fin_scan,
        "null": null_scan
    }

    try:
        if scan_type in scan_functions:
            open_ports, filtered_ports, closed_ports = scan_functions[scan_type](ports, target)
            if open_ports:
                print("Open ports:\n" + ", ".join(map(str, open_ports)))
            if filtered_ports:
                print("Filtered ports:\n" + ", ".join(map(str, filtered_ports)))
            if not open_ports and not filtered_ports:
                print("No open or filtered ports found.")
            print(f"{closed_ports} closed ports were scanned.")
        else:
            raise ValueError("Invalid scan type specified.")
    except Exception as e:
        print(f"Error occurred during scan for {target}: {e}")


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 5:
        print("Usage: python3 <path_to_port_scan.py> <scan_type> <ip_address> <start_port> <end_port>"
              "\nExample: python3 port_scan.py fin 10.1.0.2 1 1024")
    else:
        try:
            target_ip = sys.argv[2]
            start_port = int(sys.argv[3])
            end_port = int(sys.argv[4])
            scan_type = sys.argv[1]
            portscan(target_ip, start_port, end_port, scan_type)
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            sys.exit(0)