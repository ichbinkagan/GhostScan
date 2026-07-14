import time
from collections import defaultdict
from scapy.all import sniff, IP, conf, get_if_addr
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

console = Console()

# Configuration Thresholds
PACKET_LIMIT = 100        # Maximum allowed packets per second (PPS) from a single IP
TIME_WINDOW = 10         # Time window in seconds to analyze and reset metrics

packet_counts = defaultdict(int)
start_time = time.time()
attack_detected = False

def packet_callback(packet):
    """Callback function to count incoming IP packets per source IP address."""
    global packet_counts
    if IP in packet:
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1

def generate_dashboard():
    """Generates a dynamic console dashboard summarizing network traffic and attack states."""
    global packet_counts, start_time, attack_detected

    current_time = time.time()
    elapsed_time = current_time - start_time

    # Initialize the visual UI Table
    table = Table(title="GhostScan Network Traffic Monitoring", show_header=True, header_style="bold magenta")
    table.add_column("Source IP", style="cyan", justify="left")
    table.add_column("Packets / Sec", style="green", justify="right")
    table.add_column("Status", style="bold yellow", justify="center")

    max_pps = 0

    # Calculate packets-per-second (PPS) for each active host
    for ip, count in packet_counts.items():
        pps = int(count / elapsed_time) if elapsed_time > 0 else count

        if pps > max_pps:
            max_pps = pps

        # Check if the individual PPS exceeds our threshold limit
        if pps > PACKET_LIMIT:
            status = "[bold red]⚠️  SUSPECTED ATTACK!"
        else:
            status = "[green]Normal"

        table.add_row(ip, str(pps), status)
    
    # Process the threat status and reset the tracking window
    if elapsed_time >= TIME_WINDOW:
        if max_pps > PACKET_LIMIT:
            attack_detected = True
        else:
            attack_detected = False
        
        # Reset counters for the next tracking window
        packet_counts.clear()
        start_time = time.time()

    # Dynamic styling based on current threat detection state
    panel_color = "red" if attack_detected else "blue"
    panel_title = "🚨 [bold blink white]DDoS ALERT ACTIVE[/] 🚨" if attack_detected else "🛡️ Network Guard Active"

    return Panel(table, title=panel_title, border_style=panel_color, expand=True)

def main():
    """Resolves active network interface and starts the real-time DDoS detection dashboard."""
    console.print("[bold green]Initializing DDoS Detection Engine...[/bold green]")
    
    # Automatically resolve the system's default active network interface
    active_interface = None
    try:
        default_route_ip = get_if_addr(conf.iface)
        for interface_name, interface_data in conf.ifaces.items():
            if getattr(interface_data, "ip", None) == default_route_ip:
                active_interface = interface_data
                break
    except Exception:
        pass

    if not active_interface:
        active_interface = "WLAN"

    interface_desc = getattr(active_interface, 'description', active_interface)
    console.print(f"[green]Successfully bound to: {interface_desc}[/green]")
    console.print("[yellow]Press CTRL+C to safely exit the application.[/yellow]\n")
    
    # Launch the real-time interactive terminal UI
    with Live(generate_dashboard(), refresh_per_second=4, console=console) as live:
        while True:
            # Continuously capture packets in small chunks on the active interface
            sniff(prn=packet_callback, count=50, store=False, iface=active_interface)
            live.update(generate_dashboard())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Detection engine stopped by the user.[/bold red]")