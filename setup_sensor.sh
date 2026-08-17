#!/bin/bash
echo "Updating Ubuntu package list..."
sudo apt-get update -y

echo "Installing Core Sensor Tools (Tcpdump, Suricata, Zeek, Tshark, Python3)..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get install -y tcpdump suricata zeek tshark python3 python3-pip

echo "Installing PyShark..."
pip3 install pyshark

echo "Sensor tools installation is complete!"
