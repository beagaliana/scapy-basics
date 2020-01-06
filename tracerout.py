from scapy.all import *
import sys

def main():
    max_hops = sys.argv[1]
    timeout = sys.argv[2]
    host = sys.argv[3]
    print("Tracing route of", host)
    ans, unans = sr(IP(dst=host, ttl=(1,int(max_hops)),id=RandShort())/ICMP(),timeout=int(timeout))
    
    hop = 0
    for snd,rcv in ans:
        hop += 1
        print('Hop', hop, 'TTL', snd.ttl, 'with IP address', rcv.src)

if __name__ == "__main__":
    main()
