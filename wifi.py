from scapy.all import sniff, Dot11
from rich.table import Table
from utils import Console


def wifi_info(interface):

    

    print("Using interface:")
    print(interface)

    def analyze(packet):

        if packet.haslayer(Dot11):

            print(
                "WiFi Packet:",
                packet.addr1,
                packet.addr2
            )


    sniff(
        iface=interface,
        prn=analyze,
        count=10
    )