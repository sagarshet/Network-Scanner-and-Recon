#! /usr/bin/env python3

# Scapy is the packet manipulation lib
import scapy.all as scapy

def scan(ip):
	arp_request = scapy.ARP(pdst=ip)

	# Ethernet frame has to be constructed for MAC
	bcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

	# appending both pcks
	arp_bcast_request = bcast/arp_request

	# To sent and recv pkt srp func is used where p stands for custom Ether pkt
	ans_list,unans_list = scapy.srp(arp_bcast_request,timeout=1,verbose=False)

	res_list = []
	for element in ans_list:
		ele_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
		res_list.append(ele_dict)

	return res_list

def print_res(res_list):
	print("IP\t\t\tMAC Addr\n-----------------------------------")
	for ele in res_list:
		print(ele["ip"] + "\t\t" + ele["mac"])


res = scan('10.0.2.1/24') 
# for specifying the range 10.0.2.1/24

print_res(res)