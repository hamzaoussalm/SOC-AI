#!/bin/bash
echo "Updating Ubuntu package list..."
sudo apt-get update -y

echo "Installing Apache Web Server..."
sudo apt-get install -y apache2

echo "Starting and enabling Apache service..."
sudo systemctl start apache2
sudo systemctl enable apache2

echo "Target web server setup is complete!"
