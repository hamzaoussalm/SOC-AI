#!/usr/bin/env python3
"""
SOC-AI Flow-Based Feature Extractor (v2)
Aggregates network packets into behavioral flows and sends
flow summaries to the ML Node API for multi-class classification.
"""

import pyshark
import requests
import time

# --- CONFIGURATION ---
ML_API_URL = "http://10.10.3.10:8000/predict_flow"
CAPTURE_INTERFACE = 'eth3'
BPF_FILTER = 'not port 8000'  # Prevent API feedback loop
FLUSH_WINDOW = 2.0  # Aggregate flows for 2 seconds before sending

# --- FLOW STATE ---
# Key: (src_ip, dst_ip, protocol)
# Value: aggregated statistics dict
flows = {}
last_flush_time = time.time()

def compute_flow_features(flow_key, flow_data):
    """Transform raw flow aggregation into ML-ready features."""
    src_ip, dst_ip, protocol = flow_key

    duration = flow_data['last_time'] - flow_data['start_time']
    if duration <= 0:
        duration = 0.001  # Prevent division by zero

    pkt_count = flow_data['packet_count']
    byte_count = flow_data['byte_count']

    packets_per_second = pkt_count / duration
    bytes_per_second = byte_count / duration
    avg_packet_size = byte_count / pkt_count if pkt_count > 0 else 0
    unique_dst_ports = len(flow_data['dst_ports'])
    syn_ratio = flow_data['syn_count'] / pkt_count if pkt_count > 0 else 0

    # Inter-arrival time mean
    iat_list = flow_data['iat_list']
    iat_mean = (sum(iat_list) / len(iat_list)) if iat_list else 0.0

    # Protocol mapping
    proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
    protocol_num = proto_map.get(protocol.upper(), 0)

    return {
        "timestamp": flow_data['start_time'],
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol,
        "flow_duration": round(duration, 4),
        "packets_per_second": round(packets_per_second, 2),
        "bytes_per_second": round(bytes_per_second, 2),
        "avg_packet_size": round(avg_packet_size, 2),
        "unique_dst_ports": unique_dst_ports,
        "syn_ratio": round(syn_ratio, 4),
        "iat_mean": round(iat_mean, 6),
        "protocol_num": protocol_num
    }

def flush_expired_flows(force=False):
    """Send completed flows to the ML API and clear memory."""
    global last_flush_time
    now = time.time()

    if not force and (now - last_flush_time) < FLUSH_WINDOW:
        return

    # Identify flows ready for flushing
    keys_to_flush = []
    for key, flow in list(flows.items()):
        if force or (now - flow['start_time'] >= FLUSH_WINDOW):
            keys_to_flush.append(key)

    for key in keys_to_flush:
        flow_data = flows.pop(key)
        features = compute_flow_features(key, flow_data)

        try:
            response = requests.post(ML_API_URL, json=features, timeout=5)
            result = response.json()
            print(
                f"[FLOW] {features['source_ip']}->{features['destination_ip']} | "
                f"Pred: {result.get('prediction')} | Conf: {result.get('confidence')} | "
                f"PPS: {features['packets_per_second']} | Ports: {features['unique_dst_ports']} | "
                f"SYN: {features['syn_ratio']}"
            )
        except Exception as e:
            print(f"[ERROR] Failed to transmit flow {key}: {e}")

    last_flush_time = now

def main():
    print("=" * 55)
    print("  SOC-AI Flow-Based Network Sensor")
    print(f"  Interface: {CAPTURE_INTERFACE}")
    print(f"  ML API:    {ML_API_URL}")
    print(f"  Window:    {FLUSH_WINDOW}s")
    print("=" * 55)

    capture = pyshark.LiveCapture(
        interface=CAPTURE_INTERFACE,
        bpf_filter=BPF_FILTER
    )

    for packet in capture.sniff_continuously():
        try:
            # --- Layer 3: Extract IPs ---
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            else:
                continue  # Skip non-IP (ARP, etc.)

            # --- Transport Protocol ---
            protocol = packet.transport_layer
            if not protocol:
                protocol = getattr(packet, 'highest_layer', None)
            if not protocol or protocol in ["DATA", "ARP", "UNKNOWN"]:
                continue

            # --- Timing & Size ---
            pkt_time = float(packet.sniff_timestamp)
            pkt_size = int(packet.length)

            # --- Layer 4: Ports & TCP Flags ---
            dst_port = 0
            syn_flag = 0

            if hasattr(packet, 'tcp'):
                dst_port = int(packet.tcp.dstport)
                if hasattr(packet.tcp, 'flags'):
                    flags_str = str(packet.tcp.flags).upper()
                    # Pure SYN (scan probe) vs SYN-ACK (handshake response)
                    if 'SYN' in flags_str and 'ACK' not in flags_str:
                        syn_flag = 1

            elif hasattr(packet, 'udp'):
                dst_port = int(packet.udp.dstport)

            # --- Flow Aggregation ---
            flow_key = (src_ip, dst_ip, str(protocol))

            if flow_key not in flows:
                flows[flow_key] = {
                    'start_time': pkt_time,
                    'last_time': pkt_time,
                    'packet_count': 0,
                    'byte_count': 0,
                    'dst_ports': set(),
                    'syn_count': 0,
                    'iat_list': [],
                }

            flow = flows[flow_key]

            # Inter-arrival time (skip first packet)
            if flow['packet_count'] > 0:
                flow['iat_list'].append(pkt_time - flow['last_time'])

            flow['last_time'] = pkt_time
            flow['packet_count'] += 1
            flow['byte_count'] += pkt_size
            flow['dst_ports'].add(dst_port)
            flow['syn_count'] += syn_flag

            # --- Periodic Flush ---
            flush_expired_flows()

        except Exception:
            # Silently skip malformed packets to maintain uptime
            pass

if __name__ == "__main__":
    main()
