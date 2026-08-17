import pyshark
import json

print("Loading PCAP file and extracting ML features...\n")

# Load the packet capture file
capture = pyshark.FileCapture('traffic.pcap')

packet_count = 0

for packet in capture:
    try:
        # Extract basic features requested in the project plan
        protocol = packet.transport_layer
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        byte_length = packet.length
        time_epoch = packet.sniff_timestamp

        # Format the features as a JSON dictionary
        features = {
            "timestamp": float(time_epoch),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "bytes": int(byte_length)
        }

        # Print the JSON output (Later, this will be sent via HTTP POST)
        print(json.dumps(features))
        packet_count += 1

        # Stop after 5 packets just for this quick test
        if packet_count >= 5:
            break

    except AttributeError:
        # Skip packets that are not standard TCP/UDP (like ARP pings)
        pass

print("\nFeature extraction test complete!")
