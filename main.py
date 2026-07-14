import os
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

# Importing project modules
from banner import show_banner
from scanner import scan
from capture import capture_packets, save_capture
from wifi import wifi_info
from scapy.all import rdpcap, DNS
from dns import read_dns
from http_analyzer import http_analyze
from ports import port_scan
from live_stats import start_live_stats
from pcap import read_pcap_file
from geopy import get_data
from arp_detector import start_arp_detector
from ddos_detector import main as start_ddos_detector
from ddos import main as start_ddos_attack

console = Console()

def clear_screen():
    """Clears the terminal screen based on the operating system."""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_interface():
    """Clears the screen, displays the neon banner, and prints the stylized menu grid."""
    clear_screen()
    show_banner()
    
    # Grid table for a clean 2-column layout
    table = Table(
        title="[bold #ff0055]« AVAILABLE COMMANDS »[/]", 
        title_justify="center", 
        box=None, 
        expand=True
    )
    
    table.add_column("Command", justify="left", style="bold #00ffff")
    table.add_column("Command", justify="left", style="bold #00ffff")

    # Grouping tools neatly into 2 columns
    table.add_row("[1] Network Scan",       "[8] Save Capture")
    table.add_row("[2] Packet Capture",     "[9] Live Statistics")
    table.add_row("[3] WiFi Analyzer",      "[10] IP Geolocation (Ipinfo)")
    table.add_row("[4] DNS Analyzer",       "[11] ARP Spoof Detector")
    table.add_row("[5] HTTP/HTTPS Analyzer","[12] DDoS Detector")
    table.add_row("[6] Port Scanner",       "[13] DDoS Attack Vector")
    table.add_row("[7] Read PCAP File",     "[0] Terminate Session (Exit)")

    # Wrapping the table inside a cyber panel
    console.print(Panel(
        table, 
        border_style="bold #39ff14", 
        title="[bold #00ffff]GHOSTSCAN CONTROL PANEL[/]", 
        title_align="center"
    ))

def main():
    while True:
        # Render interface on every loop iteration
        show_interface()

        # Stylized input prompt using rich
        choice = Prompt.ask("\n[bold #39ff14]ghostscan@terminal[/][bold white]:~$[/]")

        if choice == "1":
            scan()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

        elif choice == "2":
            capture_packets()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

        elif choice == "3":
            from network import get_wifi_interface
            iface = get_wifi_interface()
            if iface:
                wifi_info(iface)
            else:
                console.print("[bold red][!] WiFi interface not found![/]")
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

        elif choice == "4":
            read_dns()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

        elif choice == "5":
            http_analyze()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

        elif choice == "6":
            port_scan()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

        elif choice == "7":
            read_pcap_file()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

        elif choice == "8":
            save_capture()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

        elif choice == "9":
            start_live_stats()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")
            
        elif choice == "10":
            get_data()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")
            
        elif choice == "11":
            start_arp_detector()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")
            
        elif choice == "12":
            start_ddos_detector()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")
            
        elif choice == "13":
            start_ddos_attack()
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")
            
        elif choice == "0":
            console.print("\n[bold #ff0055][!] Closing core engines. Session terminated.[/]")
            time.sleep(1)
            break
        else:
            console.print("[bold red][!] Invalid command code. Try again.[/]")
            Prompt.ask("\n[dim cyan]Press Enter to return to main menu...[/]")

if __name__ == "__main__":
    main()