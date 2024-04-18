#!/bin/bash

# Create nftables rules for ICMP scan protection

nft add chain inet filter icmp_scan_protection { type filter hook input priority 0 \; policy drop \; }
nft add set inet filter icmp_scan_ips { type ipv4_addr \; flags timeout \; }
nft add rule inet filter icmp_scan_protection ip protocol icmp icmp type echo-request ip saddr @icmp_scan_ips counter accept
nft add rule inet filter icmp_scan_protection ip protocol icmp icmp type echo-request counter drop
nft add element inet filter icmp_scan_ips { 10.1.0.2, 10.1.0.3 } timeout 1h


# Run the network scan
python network_scan.py

# Delete the nftables rules after the scan
nft delete element inet filter icmp_scan_ips { 10.1.0.2, 10.1.0.3 }
nft delete table inet filter
