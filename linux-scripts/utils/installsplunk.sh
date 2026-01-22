#!/bin/bash

# Install Splunk Universal Forwarder

# Check if it's partially installed
ls -la /opt/splunkforwarder/bin/splunk

# If missing, try manual installation
cd /tmp
wget https://download.splunk.com/products/universalforwarder/releases/9.1.2/linux/splunkforwarder-9.1.2-Linux-x86_64.tgz
tar -xzf splunkforwarder-9.1.2-Linux-x86_64.tgz -C /opt/

# Verify binary exists
ls -la /opt/splunkforwarder/bin/splunk

# If it exists, configure and start
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt