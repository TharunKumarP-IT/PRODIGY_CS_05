!pip install scapy
from scapy.all import IP, TCP, UDP, Raw

def analyze_packet(packet):
    print("\n📦 Packet Captured")

    if IP in packet:
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {packet[IP].proto}")

        if TCP in packet:
            print("Protocol Name  : TCP")
            if packet.haslayer(Raw):
                print(f"Payload        : {packet[Raw].load}")

        elif UDP in packet:
            print("Protocol Name  : UDP")
            if packet.haslayer(Raw):
                print(f"Payload        : {packet[Raw].load}")

        else:
            print("Protocol Name  : Other")
packet1 = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1")
packet2 = IP(src="10.0.0.5", dst="192.168.1.1") / UDP(dport=53) / Raw(load=b"DNS Query")
packet3 = IP(src="172.16.0.2", dst="142.250.183.46") / TCP(dport=443) / Raw(load=b"HTTPS Data")

packets = [packet1, packet2, packet3]

print("🚀 Packet Sniffer Simulation Started")

for pkt in packets:
    analyze_packet(pkt)