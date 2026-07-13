from scapy.all import sniff, IP, TCP, UDP, ARP
from rich.table import Table
from rich.console import Console

def scan():

    console = Console()

    print("Scanning...")

    table = Table(title="GhostScan Network Scan")

    table.add_column("Protocol")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Info")

    def analyze(packet):

        protocol = ""
        source = ""
        destination = ""
        info = ""

        if packet.haslayer(ARP):
            protocol = "ARP"
            source = packet[ARP].psrc
            destination = packet[ARP].pdst
            info = "ARP Request"

        elif packet.haslayer(IP):

            source = packet[IP].src
            destination = packet[IP].dst

            if packet.haslayer(TCP):
                protocol = "TCP"

                info = (
                    f"{packet[TCP].sport}"
                    " -> "
                    f"{packet[TCP].dport}"
                )

            elif packet.haslayer(UDP):

                protocol = "UDP"

                info = (
                    f"{packet[UDP].sport}"
                    " -> "
                    f"{packet[UDP].dport}"
                )

            else: 
                protocol = "IP"
        if protocol:

            table.add_row(
                protocol,
                source,
                destination,
                info
            )
    

    sniff(
        count=10,
        prn=analyze
    )

    console.print(table)