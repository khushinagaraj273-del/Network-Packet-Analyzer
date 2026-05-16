from scapy.all import sniff, IP, TCP, UDP
import pandas as pd

# This list will hold our data before we save it to a CSV
captured_data = []

def packet_callback(packet):
    # We only care about packets with an IP layer (Source/Destination)
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        length = len(packet)
        
        # Determine the protocol name
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Other"

        # Append a dictionary of the data to our list
        captured_data.append({
            "Source": source_ip,
            "Destination": dest_ip,
            "Protocol": protocol,
            "Length_Bytes": length
        })
        
        print(f"Captured: {protocol} | {source_ip} -> {dest_ip} ({length} bytes)")

# --- MAIN EXECUTION ---
print("Starting Capture... (Generating 100 packets)")
# count=100 means it will stop automatically after 100 packets
sniff(prn=packet_callback, count=100)

# Convert the list to a Pandas DataFrame
df = pd.DataFrame(captured_data)

# Save to CSV
df.to_csv("network_traffic.csv", index=False)
print("\n--- DONE! Data saved to 'network_traffic.csv' ---")