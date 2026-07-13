import os
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from rich.table import Table
from rich.console import Console
from datetime import datetime

console = Console()

def read_pcap_file():
    """Reads the saved network_traffic.pcap file and displays a summary table."""
    filename = "network_traffic.pcap"

    # Check if the PCAP file exists
    if not os.path.exists(filename):
        console.print(f"[red]Error: '{filename}' not found. Capture some packets first![/red]")
        return

    console.print(f"[yellow]Reading packets from {filename}... Please wait.[/yellow]")
    
    try:
        # Read the PCAP file using Scapy
        packets = rdpcap(filename)
    except Exception as e:
        console.print(f"[red]Failed to read PCAP file: {e}[/red]")
        return

    # Create a beautiful table to display packet summary
    table = Table(title=f"PCAP Analysis Summary ({len(packets)} packets found)")
    table.add_column("No", justify="center", style="cyan")
    table.add_column("Time", justify="center")
    table.add_column("Source IP", style="green")
    table.add_column("Destination IP", style="green")
    table.add_column("Protocol", style="bold yellow")
    table.add_column("Length (Bytes)", justify="right")

    # Limit the display to the first 50 packets to prevent terminal overflow
    max_packets = min(len(packets), 50)

    for i in range(max_packets):
        packet = packets[i]
        
        # Format the arrival time
        time_str = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")
        
        # Default values if not an IP packet
        src_ip = "-"
        dst_ip = "-"
        protocol = "Other"
        length = len(packet)

        # Extract IP layers if present
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Determine the protocol
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "IP"

        # Add row to the table
        table.add_row(
            str(i + 1),
            time_str,
            src_ip,
            dst_ip,
            protocol,
            str(length)
        )

    console.print(table)
    
    if len(packets) > 50:
        console.print(f"[dim]* Only showing the first 50 of {len(packets)} packets to keep the terminal clean.[/dim]")