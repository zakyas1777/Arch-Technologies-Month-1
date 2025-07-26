from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "OTHER"

        if TCP in packet:
            proto = "TCP"
            print(f"protocol: [TCP] src.ip: {ip_layer.src}:{packet[TCP].sport} -> dst.ip: {ip_layer.dst}:{packet[TCP].dport}")
        elif UDP in packet:
            proto = "UDP"
            print(f"protocol: [UDP] src.ip: {ip_layer.src}:{packet[UDP].sport} -> dst.ip: {ip_layer.dst}:{packet[UDP].dport}")
        elif ICMP in packet:
            proto = "ICMP"
            print(f"protocol: [ICMP] src.ip: {ip_layer.src} -> dst.ip: {ip_layer.dst}")

print("Packet capture & analyzing started:")
sniff(prn=packet_callback, store=False)
