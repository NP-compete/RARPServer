import struct
import binascii
import socket
import io
import csv
import arp_core


def CheckMac(mac_add):
	data = open("rarp_server.csv", "r")
	csvdata = csv.reader(data)
	csvdata = list(csvdata)
	for row in csvdata:
		if row[0] == mac_add:
			arp_core.SendRArpReplyPacket(mac_add, row[1])
			print()
			data.close()
			return row[1]
	data.close()
	return False
	
def main():
	if __name__ == "__main__":
	
		count = 0
		
		rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
		while True:

			packet = rawSocket.recvfrom(2048)

			ethernet_header = packet[0][0:14]
			ethernet_layer = struct.unpack("!6s6s2s", ethernet_header)

			arp_header = packet[0][14:42]
			arp_layer = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
			
			ethernet_type = binascii.hexlify(ethernet_layer[2]).decode('ascii')

			if (ethernet_type == "0806" or ethernet_type == "8035") and binascii.hexlify(arp_layer[4]).decode('ascii') == "0003":
				
				# Ethernet Layer
				dest_mac   = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", ethernet_layer[0])
				source_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", ethernet_layer[1])
				
				# ARP Layer
				hardware_type = binascii.hexlify(arp_layer[0]).decode('ascii')
				protocol_type = binascii.hexlify(arp_layer[1]).decode('ascii')
				hardware_size = binascii.hexlify(arp_layer[2]).decode('ascii')
				protocol_size = binascii.hexlify(arp_layer[3]).decode('ascii')
				opcode        = binascii.hexlify(arp_layer[4]).decode('ascii')
				sender_mac    = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", arp_layer[5])
				sender_ip     = socket.inet_ntoa(arp_layer[6])
				target_mac    = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", arp_layer[7])
				target_ip     = socket.inet_ntoa(arp_layer[8])	
				
				print()
						
				count = count + 1
				print("Packet RARP request {0}:".format(count))
				print()
				
				print("================_ETHERNET_FRAME_=================")
				
				print("Dest MAC        :", dest_mac)
				print("Source MAC      :", source_mac)
				print("Type            :", ethernet_type)
				
				print("==================_ARP_HEADER_===================")
				
				print("Hardware type   :", hardware_type)
				print("Protocol type   :", protocol_type)
				print("Hardware size   :", hardware_size)
				print("Protocol size   :", protocol_size)
				print("Opcode          :", opcode)
				print("Sender MAC      :", sender_mac)
				print("Sender IP       :", sender_ip)
				print("Target MAC      :", target_mac)
				print("Target IP       :", target_ip)
				
				print("=================================================")
				
				print()
				
				result = CheckMac(sender_mac)
				
				if result is False:
					print()
					print("{} doesn't in mapping".format(sender_mac))
				else:
					print()
					print("Send RARP reply to {}. It's IP is {}".format(sender_mac, result))
					
				print()
					
			
main()			