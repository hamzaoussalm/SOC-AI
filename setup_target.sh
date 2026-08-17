#!/bin/bash
echo "Updating Ubuntu package list..."
sudo apt-get update -y

echo "Installing Apache Web Server and OpenSSH Server..."
sudo apt-get install -y apache2 openssh-server

echo "Starting and enabling services..."
sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl start ssh
sudo systemctl enable ssh

echo "Target web server and SSH setup is complete!"
