#!/bin/bash
echo "Updating Ubuntu package list..."
sudo apt-get update -y
sudo apt-get install -y curl gnupg2

echo "Adding the official Zeek Repository..."
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
sudo apt-get update -y

echo "Installing Core Sensor Tools..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get install -y tcpdump suricata zeek tshark python3 python3-pip

echo "Installing PyShark..."
pip3 install pyshark

echo "Sensor tools installation is complete!"

echo "--- Installing Python dependencies globally for root ---"
sudo pip3 install pyshark requests

echo "--- Configuring Background Systemd Service for Sensor ---"
sudo bash -c 'cat <<EOF > /etc/systemd/system/soc-sensor.service
[Unit]
Description=SOC AI Network Sensor (Live Capture)
After=network.target

[Service]
User=root
Environment=PYTHONPATH=/users/sochamza/.local/lib/python3.10/site-packages
WorkingDirectory=/users/sochamza/SOC-AI
ExecStart=/usr/bin/python3 /users/sochamza/SOC-AI/extract_features.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF'

echo "--- Enabling and Starting Background Sensor ---"
sudo systemctl daemon-reload
sudo systemctl enable soc-sensor
sudo systemctl restart soc-sensor

echo "--- Sensor Node Setup Complete & Sniffing in Background! ---"
