#!/bin/bash
# Route ONLY HTTP (port 80) through Suricata's NFQUEUE 0 so it can inspect and
# drop malicious web traffic inline. SSH (22) and everything else are never
# queued, so this cannot lock you out. --queue-bypass is a failsafe: if Suricata
# stops, queued packets flow normally instead of being dropped.
#
# Run on WEB01:  sudo bash setup-ips-iptables.sh
# Disable all:   sudo iptables -F
set -e

QUEUE=0

# idempotent: remove any existing copies first
iptables -D INPUT  -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE --queue-bypass 2>/dev/null || true
iptables -D OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE --queue-bypass 2>/dev/null || true

iptables -I INPUT  -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE --queue-bypass
iptables -I OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE --queue-bypass

echo "NFQUEUE rules installed (HTTP/80 -> queue $QUEUE). SSH is untouched."
iptables -S | grep NFQUEUE
