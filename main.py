from banner import show_banner
from scanner import scan
from capture import capture_packets
from wifi import wifi_info


def main():

    show_banner()

    while True:

        print("""
[1] Network Scan
[2] Capture Packets
[3] WiFi Info
[4] Exit
        """)

        choice = input("> ")

        if choice == "1":
            scan()

        elif choice == "2":
            capture_packets()

        elif choice=="3":

            from network import get_wifi_interface

            iface = get_wifi_interface()

            if iface:

                wifi_info(iface)

            else:

                print("WiFi interface bulunamadı")

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()