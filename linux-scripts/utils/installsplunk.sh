#!/bin/bash

# Install Splunk Universal Forwarder

cd /tmp
wget https://download.splunk.com/products/universalforwarder/releases/10.2.0/linux/splunkforwarder-10.2.0-d749cb17ea65-linux-amd64.tgz
tar -xzf splunkforwarder-10.2.0-d749cb17ea65-linux-amd64.tgz -C /opt/
ls -la /opt/splunkforwarder/bin/splunk  # Verify it exists