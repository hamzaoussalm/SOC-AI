#!/bin/bash
echo "--- Starting Dashboard Node Provisioning ---"

echo "1. Installing required tools..."
sudo apt-get update
sudo apt-get install -y apt-transport-https software-properties-common wget

echo "2. Adding Grafana security keys..."
sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list

echo "3. Installing Grafana Server..."
sudo apt-get update
sudo apt-get install grafana -y

echo "4. Starting the engine..."
sudo systemctl start grafana-server
sudo systemctl enable grafana-server

echo "--- Grafana Installation Complete! ---"
