from scapy.all import sniff, IP, TCP

from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

sniff(prn=packet_callback, count=10)
from scapy.all import sniff, conf, L3RawSocket

conf.L3socket = L3RawSocket

def packet_callback(packet):
    print(packet.show())

sniff(prn=packet_callback, filter="ip", store=0)


# Function to process each captured packet
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        print(f"IP Packet: {src_ip} -> {dst_ip}")

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            print(f"TCP Segment: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Start sniffing on the specified network interface
sniff(prn=process_packet, filter="ip", store=0)
