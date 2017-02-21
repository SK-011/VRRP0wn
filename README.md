# VRRP0wn
VRRP VIP stealer based on scapy.

Main thread:
  Try to sniff VRRP packets.
  Then parse each VRRP packets in order to retrieve each VIP and it's configuration data.
  Those datas are then used to craft VRRP packets with highest priority that will be send at regular intervals.

Responder thread:
  Basicaly an ARP/ICMP responder.
  It will respond to any ICMP echo request and ARP request for the VIPs that are being stole.
