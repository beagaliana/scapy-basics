from scapy.all import *

#capturaPackets = rdpcap('pcap.pcapng')
def show_packets(capturaPackets):
    for index, packet in enumerate(capturaPackets):
        print("SHOW PACKET " + str(index) + "\n ")
        packet.show()
        print("########## END OF THE PACKET " + str(index) + " ##########" + "\n")
    print("TOTAL NUMBER OF PACKETS: " + str(index + 1))


def packets_summary(packets):
    for index, packet in enumerate(packets):
        print("PACKET SUMMARY " + str(index) + " ->  " + packet.summary() + "\n")

    print("TOTAL NUMBER OF PACKETS: " + str(index + 1))

def generatePacketList(packets):
    return [packet for packet in packets]

def selectLayer(packet):
    selectLayer = input("Select one layer to see in detail >>> ")
    return packet[selectLayer.upper()]

def main():
    capturaPackets = rdpcap(input('Please enter the pathfile of the capture: '))
    packets_summary(capturaPackets)
    selection = int(input("Select one packet >>> "))
    generatePacketList(capturaPackets)[selection].show()
    print(selectLayer(generatePacketList(capturaPackets)[selection]))

if __name__ == "__main__":
    main()

