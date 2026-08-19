#!/bin/bash
echo "--- Goal: Provide AI inference and prediction services ---"

echo "1. Updating Ubuntu..."
sudo apt-get update -y

echo "2. Installing Python 3, pip and Git..."
sudo apt-get install -y python3 python3-pip git

echo "3 & 4. Installing FastAPI, Uvicorn, and ML dependencies (scikit-learn, pandas)..."
pip3 install fastapi uvicorn scikit-learn pandas

echo "ML Node initial setup is complete!"

echo "--- Configuring Background Systemd Service ---"
sudo bash -c 'cat <<EOF > /etc/systemd/system/soc-ai.service
[Unit]
Description=SOC AI Detection & FastAPI Service
After=network.target

[Service]
User=sochamza
WorkingDirectory=/users/sochamza/SOC-AI
ExecStart=/usr/local/bin/uvicorn api:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF'

echo "--- Enabling and Starting Background Service ---"
sudo systemctl daemon-reload
sudo systemctl enable soc-ai
sudo systemctl restart soc-ai

echo "--- ML Node Setup Complete & Running in Background! ---"
