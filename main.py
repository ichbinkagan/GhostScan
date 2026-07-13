import os
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

def clear_screen():
    """Clears the terminal screen based on the operating system."""
    # Runs 'cls' for Windows, 'clear' for Linux/macOS
    os.system('cls' if os.name == 'nt' else 'clear')

def show_interface():
    """Clears the screen, displays the banner, and prints the menu."""
    clear_screen()
    show_banner()
    print("""
[1] Network Scan
[2] Packet Capture
[3] WiFi Analyzer
[4] DNS Analyzer
[5] HTTP/HTTPS Analyzer
[6] Port Scanner
[7] Read PCAP
[8] Save Capture
[9] Live Statistics
[10] Ipinfo
[0] Exit
    """)

def main():
    while True:
        # Clear screen and display the menu on every iteration
        show_interface()

        choice = input("> ")

        if choice == "1":
            scan()
            input("\nPress Enter to continue...")  # Pauses so the user can read the output

        elif choice == "2":
            capture_packets()
            input("\nPress Enter to continue...")

        elif choice == "3":
            from network import get_wifi_interface
            iface = get_wifi_interface()
            if iface:
                wifi_info(iface)
            else:
                print("WiFi interface not found")
            input("\nPress Enter to continue...")

        elif choice == "4":
            read_dns()
            input("\nPress Enter to continue...")

        elif choice == "5":
            http_analyze()
            input("\nPress Enter to continue...")

        elif choice == "6":
            port_scan()
            input("\nPress Enter to continue...")

        elif choice == "7":
            read_pcap_file()
            input("\nPress Enter to continue...")

        elif choice == "8":
            save_capture()
            input("\nPress Enter to continue...")

        elif choice == "9":
            start_live_stats()
            input("\nPress Enter to continue...")
        elif choice == "10":
            get_data()
            input("\nPress Enter to continue...")
        elif choice == "0":
            print("Exiting...")
            break

        else:
            print("Invalid choice")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()