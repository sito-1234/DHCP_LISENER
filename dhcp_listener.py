#import nessacary module
from scapy.all import*
import time



def listen_dhcp():
	#Make sue it is DHCP with the filter options
	sniff(prn=priint_packet, filter='udp and (port 67 or port 68)')
def print_packet(packet): # we define the print_packet
	#initialize these variables to None first
	target_mac, requested_ip, hostname, vendor_id = [None] * 4
	#get the mac address of the requester
	if packet.haslayer(Ether):
		target_mac = packet.getlayer(Ether).src
	if packet.haslayer(DHCP):
		dhcp_option = packet[DHCP].options
		for item in dhcp_options:
			try:
				label, value = item
			except valueError:
				continue
			if label == 'requested _addr':
				# get the requested ip
				requested_ip = value
				elif label == 'hostname':
					#get the vendor id
					vendor_id = value.decode()
	if target_mac and vendor_id and hostname and requested_ip:
		#if all variables are not None,print the device details
		time_now = time.strftimae("[%Y-%m-%d - %H:%M:%S]")
		print(f"{time_now} : {target__mac} - {hostname } / {vendor_id} requested{requested_ip}")
# let start sniffing
if __name__ == "__main__":
	listen_dhcp()

