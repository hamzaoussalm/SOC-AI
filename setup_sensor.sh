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
