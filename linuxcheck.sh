#!/bin/bash
for host in 172.20.242.30 172.20.242.40 172.20.242.20; do
  echo "========== $host =========="
  ssh sysadmin@$host "
    echo '--- UID 0 accounts ---'
    awk -F: '\$3 == 0 {print}' /etc/passwd
    echo '--- NOPASSWD sudo ---'
    sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null
    echo '--- Listening ports ---'
    ss -tulpn | grep LISTEN
    echo '--- Running services ---'
    systemctl list-units --type=service --state=running | head -20
  "
done