import os
import sys
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel

console = Console()

stats = {
    "total_packets": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "dns": 0,
    "other": 0
}

src_ips = Counter()
dst_ips = Counter()

def packet_callback(packet):
    
    if not packet.haslayer(IP):
        return
    
    stats["total_packets"] += 1
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if packet.haslayer(TCP):
        stats["tcp"] += 1
    elif packet.haslayer(UDP):
        stats["udp"] += 1
        if packet.haslayer(DNS):
            stats["dns"] += 1
    elif packet.haslayer(ICMP):
        stats["icmp"] += 1
    else:
        stats["other"] += 1
def generate_dashboard() -> Layout:
    layout = Layout()

    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="body", ratio=1)
    )

    layout["header"].update(
        Panel(
            f"[bold green]GhostScan Live Monitor[/bold green] | Total Packets Captured: [bold yellow]{stats['total_packets']}[/bold yellow] | [red]Press Ctrl+C to Stop[/red]",
            border_style="cyan"
        )
    )
    
    # Split the body into left (protocols) and right (top talkers)
    layout["body"].split_row(
        Layout(name="protocols", ratio=1),
        Layout(name="talkers", ratio=1)
    )
    
    # Left Side Table: Protocol Statistics
    proto_table = Table(title="Protocol Distribution", expand=True)
    proto_table.add_column("Protocol", style="cyan", justify="left")
    proto_table.add_column("Count", style="bold magenta", justify="right")
    proto_table.add_column("Percentage", style="green", justify="right")
    
    total = stats["total_packets"] if stats["total_packets"] > 0 else 1
    
    proto_table.add_row("TCP", str(stats["tcp"]), f"{(stats['tcp']/total)*100:.1f}%")
    proto_table.add_row("UDP", str(stats["udp"]), f"{(stats['udp']/total)*100:.1f}%")
    proto_table.add_row("ICMP", str(stats["icmp"]), f"{(stats['icmp']/total)*100:.1f}%")
    proto_table.add_row("DNS (over UDP)", str(stats["dns"]), f"{(stats['dns']/total)*100:.1f}%")
    proto_table.add_row("Other", str(stats["other"]), f"{(stats['other']/total)*100:.1f}%")
    
    layout["protocols"].update(Panel(proto_table, border_style="blue"))
    
    # Right Side Table: Top Talkers
    talker_table = Table(title="Top Talkers (IP Activity)", expand=True)
    talker_table.add_column("Source IP", style="yellow", justify="left")
    talker_table.add_column("Packets Sent", style="bold red", justify="right")
    
    # Get top 5 active source IPs
    for ip, count in src_ips.most_common(5):
        talker_table.add_row(ip, str(count))
        
    layout["talkers"].update(Panel(talker_table, border_style="magenta"))
    
    return layout
def start_live_stats():
    console.print("[bold yellow]Starting Live Monitor... Press Ctrl+C to stop.[/bold yellow]")

    with Live(generate_dashboard(), refresh_per_second=4, screen=True) as live:
        try:
            sniff(
                prn=lambda pkt: [packet_callback(pkt), live.update(generate_dashboard())],
                store=False
            )
        except KeyboardInterrupt:
            pass