import pyshark
import requests

print("Starting Live SOC Sensor on eth1... Sniffing and sending to ML Node...")

# The exact IP address and port of your ML Node
ML_API_URL = "http://10.10.3.10:8000/predict"

# 1. LIVE CAPTURE: Listen directly to the experimental network interface (eth1)
capture = pyshark.LiveCapture(interface='eth1', bpf_filter='not port 8000')

# 2. CONTINUOUS LOOP: Run infinitely to catch live attacks
for packet in capture.sniff_continuously():
    try:
        # Safely extract IP addresses. If it is not an IP packet (e.g., ARP), default to 0.0.0.0
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        elif hasattr(packet, 'ipv6'):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
        else:
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"

        # Safely extract the protocol. 
        # Fallback 1: Highest layer. Fallback 2: "UNKNOWN" (Prevents FastAPI crashes!)
        protocol = packet.transport_layer
        if not protocol:
            protocol = getattr(packet, 'highest_layer', "UNKNOWN")

        byte_length = packet.length
        time_epoch = packet.sniff_timestamp

        features = {
            "timestamp": float(time_epoch),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": str(protocol),  # Force it to be a string
            "bytes": int(byte_length)
        }

        # Send the JSON data to the ML Node over the network!
        response = requests.post(ML_API_URL, json=features)

        # Print the AI's prediction to the screen
        print(f"Sensor Sent: {protocol} ({src_ip} -> {dst_ip}) | AI Reply: {response.json()}")

    except Exception as e:
        # If any packet causes a weird error, pass and keep sniffing! 
        pass
