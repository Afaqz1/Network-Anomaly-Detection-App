import matplotlib
matplotlib.use('Agg')  # Set the backend to 'Agg' before importing pyplot

import ipaddress
import scapy.all as scapy
from scapy.layers.inet import IP
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import numpy as np
import psutil
import socket
import logging
import pickle

# Initialize the set of blocked IPs
blocked_ips = set()

# Get network interfaces and their friendly names
def get_interfaces():
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces[iface] = addr.address
    return interfaces

# Convert IP address to a numeric representation
def ip_to_numeric(ip):
    return int(ipaddress.IPv4Address(ip))

# Capture network traffic
def capture_packets(interface, packet_count):
    packets = scapy.sniff(iface=interface, count=packet_count)
    return packets

# Extract features from captured packets
def extract_features(packets):
    features = []
    for packet in packets:
        feature = [len(packet)]  # Packet length
        if IP in packet:
            feature.append(packet[IP].ttl)  # Time to live
            feature.append(packet[IP].proto)  # Protocol
            feature.append(ip_to_numeric(packet[IP].src))  # Source IP
            feature.append(ip_to_numeric(packet[IP].dst))  # Destination IP
        else:
            feature.extend([0, 0, 0, 0])  # Default values for non-IP packets
        features.append(feature)
    return features

# Train an Isolation Forest model for anomaly detection
def train_model(features):
    iso_forest = IsolationForest(contamination=0.3)
    iso_forest.fit(features)
    with open('models/trained_model.pkl', 'wb') as f:
        pickle.dump(iso_forest, f)
    return iso_forest

# Detect anomalies in network traffic and return anomalous IP pairs
def detect_anomalies(model, features, packets):
    global blocked_ips  # Access the global blocked_ips set
    predictions = model.predict(features)
    anomalies = []
    for i, prediction in enumerate(predictions):
        if prediction == -1:
            try:
                ip_pair = f"{packets[i][IP].src} --> {packets[i][IP].dst}"
                anomalies.append(ip_pair)
                # Add anomalous IPs to blocked_ips
                blocked_ips.add(packets[i][IP].src)
                blocked_ips.add(packets[i][IP].dst)
            except Exception as e:
                print(f"Error extracting IP pair: {e}")
    return anomalies

# Identify and collect packets or features associated with anomalies
def identify_anomalies(model, features, packets):
    predictions = detect_anomalies(model, features, packets)
    anomalies = [packets[i] for i, prediction in enumerate(predictions) if prediction == -1]
    return anomalies

# Print details of anomalous networks or IP addresses
def print_anomalies(anomalies):
    print("Anomalous Networks/IPs:")
    for packet in anomalies:
        if IP in packet:
            print(f"From: {packet[IP].src} --> To: {packet[IP].dst}")
        else:
            print("Unknown IP format")

# Visualize anomalies
def visualize_anomalies(features, predictions):
    features = np.array(features)
    anomalies = features[predictions == -1]
    plt.figure(figsize=(12, 8))
    plt.scatter(features[:, 0], features[:, 1], color='blue', label='Normal')
    plt.scatter(anomalies[:, 0], anomalies[:, 1], color='red', label='Anomalies')
    plt.xlabel('Packet Length')
    plt.ylabel('Time to Live (TTL)')
    plt.legend()
    plt.title('Network Traffic Anomalies')
    plt.savefig('static/anomalies.png')  # Save plot as static file
    plt.close()

# Additional Visualizations

def plot_packet_length_distribution(features):
    packet_lengths = [feature[0] for feature in features]
    plt.figure(figsize=(10, 6))
    plt.hist(packet_lengths, bins=30, edgecolor='black')
    plt.xlabel('Packet Length')
    plt.ylabel('Frequency')
    plt.title('Packet Length Distribution')
    plt.savefig('static/packet_length_distribution.png')  # Save plot as static file
    plt.close()

def plot_protocol_distribution(features):
    protocols = [feature[2] if len(feature) > 2 else 0 for feature in features]
    protocol_names = ['Unknown' if proto == 0 else {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, 'Other') for proto in protocols]
    protocol_counts = pd.Series(protocol_names).value_counts()
    plt.figure(figsize=(8, 6))
    protocol_counts.plot(kind='bar', color='skyblue')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.title('Protocol Distribution')
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig('static/protocol_distribution.png')  # Save plot as static file
    plt.close()

def plot_time_series_packet_length(packets):
    packet_lengths = [len(packet) for packet in packets]
    timestamps = range(len(packet_lengths))
    plt.figure(figsize=(12, 6))
    plt.plot(timestamps, packet_lengths, marker='o', linestyle='-', color='b')
    plt.xlabel('Time')
    plt.ylabel('Packet Length')
    plt.title('Time Series: Packet Length over Time')
    plt.savefig('static/time_series_packet_length.png')  # Save plot as static file
    plt.close()

# Logging function
def log_message(message, level=logging.INFO):
    logging.log(level, message)

# Main function for standalone execution
def main():
    global blocked_ips  # Access the global blocked_ips set

    # Get network interfaces
    interfaces = get_interfaces()
    # Display available interfaces for selection
    print("Available interfaces:")
    for index, (name, ip) in enumerate(interfaces.items(), start=1):
        print(f"{index}. {name}: {ip}")

    # Prompt user to select an interface
    selection = input("Enter the number of the interface to use: ")

    try:
        selection_index = int(selection)
        if selection_index < 1 or selection_index > len(interfaces):
            raise ValueError("Invalid selection number")
    except ValueError:
        print("Invalid input. Please enter a valid number.")
        return

    interface_name = list(interfaces.keys())[selection_index - 1]
    print(f"Selected interface: {interface_name}")

    packet_count = 1000

    # Capture packets
    packets = capture_packets(interface_name, packet_count)
    print(f"Captured {len(packets)} packets from {interface_name}")

    # Extract features
    features = extract_features(packets)

    # Train model
    model = train_model(features)

    # Detect anomalies
    predictions = detect_anomalies(model, features, packets)

    # Plot additional visualizations
    plot_packet_length_distribution(features)
    plot_protocol_distribution(features)
    plot_time_series_packet_length(packets)

    # Visualize anomalies
    visualize_anomalies(features, predictions)

    # Log results
    log_message(f"Anomalies detected: {sum(predictions == -1)}")
    log_message(f"Normal traffic detected: {sum(predictions == 1)}")

    # Print results
    print("Anomalies detected:", sum(predictions == -1))
    print("Normal traffic detected:", sum(predictions == 1))

    # Block IP addresses
    print("Blocked IP addresses based on anomalies:")
    for ip in blocked_ips:
        print(ip)
    # Implement your IP blocking mechanism here, e.g., using firewall rules or API calls

# Execute main function if script is run directly
if __name__ == "__main__":
    main()
