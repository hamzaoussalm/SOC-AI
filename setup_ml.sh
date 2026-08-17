#!/bin/bash
echo "--- Goal: Provide AI inference and prediction services ---"

echo "1. Updating Ubuntu..."
sudo apt-get update -y

echo "2. Installing Python 3, pip and Git..."
sudo apt-get install -y python3 python3-pip git

echo "3 & 4. Installing FastAPI, Uvicorn, and ML dependencies (scikit-learn, pandas)..."
pip3 install fastapi uvicorn scikit-learn pandas

echo "ML Node initial setup is complete!"
