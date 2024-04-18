nft add set inet filter blocklist { type ipv4_addr \; flags dynamic, timeout \; timeout 5m \; }
nft add rule inet filter input tcp dport 21 ct state new, untracked limit rate over 5/minute add @blocklist { ip saddr }
nft add rule inet filter input ip saddr @blocklist drop