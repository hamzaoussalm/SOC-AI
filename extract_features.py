import pyshark
import requests

print("Starting SOC Sensor... Reading PCAP and sending to ML Node...")

# The exact IP address and port of your ML Node
ML_API_URL = "http://10.10.3.10:8000/predict"

capture = pyshark.FileCapture('traffic.pcap')

for packet in capture:
    try:
        protocol = packet.transport_layer
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        byte_length = packet.length
        time_epoch = packet.sniff_timestamp

        features = {
            "timestamp": float(time_epoch),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "bytes": int(byte_length)
        }

        # Send the JSON data to the ML Node over the network!
        response = requests.post(ML_API_URL, json=features)

        # Print the AI's prediction to the screen
        print(f"Sensor Sent: {protocol} | AI Reply: {response.json()}")

    except AttributeError:
        pass

print("Sensor transmission complete!")
