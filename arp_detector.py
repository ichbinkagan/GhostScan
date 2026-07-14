import os
from scapy.all import sniff, ARP, conf, get_if_addr
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# In-memory database to store IP-to-MAC address mappings
ip_mac_database = {}

def process_arp_packet(packet):
    """
    Analyzes incoming ARP packets, updates the mapping database,
    and triggers security alerts if spoofing activities are detected.
    """
    if not packet.haslayer(ARP):
        return

    # op = 2 represents an ARP Reply packet
    if packet[ARP].op == 2:
        ip_address = str(packet[ARP].psrc).strip()
        mac_address = str(packet[ARP].hwsrc).strip().lower()

        if ip_address in ip_mac_database:
            original_mac = ip_mac_database[ip_address].strip().lower()
            
            # [DEBUG] Optional inspection line to view comparisons in real-time
            # console.print(f"[dim][DEBUG] Comparing {ip_address}: Database MAC ({original_mac}) vs Incoming MAC ({mac_address})[/dim]")
            
            if original_mac != mac_address:
                alert_message = (
                    f"[bold red]⚠️  WARNING: POSSIBLE ARP SPOOFING DETECTED! ⚠️[/bold red]\n\n"
                    f"[bold yellow]Target IP Address:[/bold yellow] {ip_address}\n"
                    f"[bold green]Original MAC Address:[/bold green] {original_mac}\n"
                    f"[bold red]New (Attacker) MAC Address:[/bold red] {mac_address}\n\n"
                    f"[dim]An attacker might be attempting a Man-in-the-Middle (MITM) attack on your network.[/dim]"
                )
                console.print(Panel(alert_message, border_style="red", title="[ALERT] Security Threat", expand=False))
        else:
            # Register the new IP-to-MAC mapping to the in-memory database
            ip_mac_database[ip_address] = mac_address
            console.print(f"[green][+] Learned mapping: {ip_address} -> {mac_address}[/green]")

def start_arp_detector():
    """
    Resolves the primary active network interface and starts
    the real-time ARP spoofing detection engine.
    """
    
    # Automatically resolve the system's default active network interface
    active_interface = None
    try:
        # Retrieve the IP address of the default gateway gateway interface
        default_route_ip = get_if_addr(conf.iface)
        
        # Scan system interfaces to match the active IP address configuration
        for interface_name, interface_data in conf.ifaces.items():
            if getattr(interface_data, "ip", None) == default_route_ip:
                active_interface = interface_data
                break
    except Exception:
        pass
            
    # Fallback to standard "WLAN" interface name if automatic discovery fails
    if not active_interface:
        active_interface = "WLAN"

    interface_description = getattr(active_interface, 'description', active_interface)

    console.print(Panel(
        f"[bold cyan]GhostScan ARP Spoof Detector Active[/bold cyan]\n"
        f"[green]Bound to interface: {interface_description}[/green]\n"
        "[yellow]Monitoring network traffic for Man-in-the-Middle (MITM) anomalies...[/yellow]\n"
        "[red]Press Ctrl+C to stop the detector and review gathered network maps.[/red]",
        border_style="cyan"
    ))

    try:
        # Bind the sniffer exclusively to the identified active network interface
        sniff(filter="arp", prn=process_arp_packet, store=False, iface=active_interface)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping detector engine...[/yellow]")
        
        if ip_mac_database:
            table = Table(title="Learned IP-MAC Database Summary")
            table.add_column("IP Address", style="cyan")
            table.add_column("MAC Address", style="bold green")
            for ip, mac in ip_mac_database.items():
                table.add_row(ip, mac)
            console.print(table)
        else:
            console.print("[dim]No active IP-to-MAC mappings were recorded during this session.[/dim]")