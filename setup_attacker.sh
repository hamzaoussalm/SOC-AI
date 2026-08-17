#!/bin/bash
echo "Updating Ubuntu package list..."
sudo apt-get update -y

echo "Installing Attacker Tools..."
sudo apt-get install -y nmap hydra hping3 curl iperf3 python3-scapy

echo "Attacker setup is complete!"
