#!/bin/bash
# Check if installer exists on other machines
for host in 172.20.242.40 172.20.242.20; do
  echo "=== $host ==="
  ssh sysadmin@$host "ls -la /usr/share/startup_check-installer.sh 2>/dev/null; systemctl status startup_check 2>/dev/null | head -5"
done