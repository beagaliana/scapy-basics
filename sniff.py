from scapy.all import *
from scapy.layers.http import HTTPRequest

def sniff_ip_packet(packet):
    if(packet.haslayer(IP)):
        psrc = packet[IP].src
        pdst = packet[IP].dst
        pttl = packet[IP].ttl
        print("IP Packet: %s is going to %s and has TTL value %s" % (psrc, pdst, pttl))

def sniff_http_packet(packet):
    if(packet.haslayer(HTTPRequest)):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        
        print("HTTP Packet: %s" % (url))

def sniff_dns_packet(packet):
    if(packet.haslayer(DNS)):
        print("DNS Packet:",packet.summary())



def main():
     print("Sniffing IP Packets...")
     sniff(filter="ip", iface="wlp1s0", prn=sniff_ip_packet)
#    print("Sniffing HTTP packets...")
#    sniff(filter="port 80", iface="wlp1s0", prn=sniff_http_packet)
#    print("Sniffing DNS packets")
#    sniff(filter="port 53", iface="wlp1s0", prn=sniff_dns_packet)
        

if __name__=='__main__':
    main()
