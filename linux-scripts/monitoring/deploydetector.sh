
# Copy and install
scp detect-outbound-ssh.sh root@server:/opt/ccdc-toolkit/linux-scripts/monitoring/
echo '* * * * * root /opt/ccdc-toolkit/linux-scripts/monitoring/detect-outbound-ssh.sh --quiet' > /etc/cron.d/ssh-detector