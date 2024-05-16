import scapy.all as scapy

def sniff_packets():
    print("Sniffing packets...")

    # Sniff packets with a filter for TCP packets
    packets = scapy.sniff(filter="tcp", count=3)

    # Analyze captured packets
    for packet in packets:
        if packet.haslayer(scapy.IP):
            # Extract relevant information from the IP layer
            source_ip = packet[scapy.IP].src
            destination_ip = packet[scapy.IP].dst
            protocol = "TCP"

            print(f"Source IP: {source_ip}, Destination IP: {destination_ip}, Protocol: {protocol}")

            # Extract payload data if present
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                print("Payload data:", payload.hex())

def main():
    sniff_packets()

if __name__ == "__main__":
    main()
