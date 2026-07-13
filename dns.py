import os
from scapy.all import rdpcap, DNS, DNSQR, IP
from rich.table import Table
from rich.console import Console

console = Console()

def read_dns():

    filename = "network_traffic.pcap"


    if not os.path.exists(filename):
        console.print("[red]network_traffic.pcap bulunamadı![/red]")
        return
    
    packets = rdpcap(filename)

    table = Table(title="GhostScan DNS Analyzer")

    table.add_column("NO")
    table.add_column("Time")
    table.add_column("Type")
    table.add_column("Source IP")
    table.add_column("Destination IP")
    table.add_column("Domain")
    table.add_column("Record")
    table.add_column("Status")

    counter = 1

    dns_types = {
        1: "A",
        28: "AAAA",
        5: "CNAME",
        15: "MX",
        16: "TXT"
    }

    dns_status = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN"
    }

    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):

            if packet[DNS].qr == 0:
                packet_type = "Query"
            else:
                packet_type = "Response"
            
            src = packet[IP].src
            dst = packet[IP].dst

            domain = "-"

            if packet.haslayer(DNSQR):
                domain = packet[DNSQR].qname.decode().rstrip(".")

                record = dns_types.get(
                    packet[DNSQR].qtype,
                    str(packet[DNSQR].qtype)
                )
            else:
                record = "-"

            if packet[DNS].qr == 1:
                status = dns_status.get(
                    packet[DNS].rcode,
                    str(packet[DNS].rcode)
                )
            else:
                status = "-"

            table.add_row(
                str(counter),
                packet_type,
                src,
                dst,
                domain,
                record,
                status
            )

            counter += 1

    console.print(table)