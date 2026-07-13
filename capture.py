from scapy.all import sniff, IP, TCP, UDP, ARP, wrpcap
from rich.table import Table
from rich.console import Console
from datetime import datetime


console = Console()

def save_capture():

    print("Capturing 100 packets...")

    packets = sniff(count=100)

    wrpcap("network_traffic.pcap", packets)

    print("Capture saved as network_traffic.pcap")


def capture_packets():

    table = Table(title="GhostScan Packet Capture")

    table.add_column("No")
    table.add_column("Time")
    table.add_column("Protocol")
    table.add_column("Source IP")
    table.add_column("Destination IP")
    table.add_column("Ports")
    table.add_column("Length")
    table.add_column("Info")


    counter = 0


    def analyze(packet):

        nonlocal counter

        counter += 1

        time = datetime.now().strftime("%H:%M:%S")

        protocol = "-"
        src = "-"
        dst = "-"
        ports = "-"
        info = "-"


        # ARP
        if packet.haslayer(ARP):

            protocol = "ARP"

            src = packet[ARP].psrc
            dst = packet[ARP].pdst

            info = "ARP Request"


        # IP paketleri
        elif packet.haslayer(IP):

            src = packet[IP].src
            dst = packet[IP].dst


            # TCP
            if packet.haslayer(TCP):

                protocol = "TCP"

                ports = (
                    f"{packet[TCP].sport}"
                    " -> "
                    f"{packet[TCP].dport}"
                )


            # UDP
            elif packet.haslayer(UDP):

                protocol = "UDP"

                ports = (
                    f"{packet[UDP].sport}"
                    " -> "
                    f"{packet[UDP].dport}"
                )


            else:

                protocol = "IP"


        table.add_row(
            str(counter),
            time,
            protocol,
            src,
            dst,
            ports,
            str(len(packet)),
            info
        )


    sniff(
        prn=analyze,
        count=20
    )


    console.print(table)