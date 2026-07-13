from scapy.all import get_if_list, get_if_hwaddr


def get_wifi_interface():

    target_mac = "70:CD:0D:08:F0:61"

    for iface in get_if_list():

        try:
            mac = get_if_hwaddr(iface)

            if mac.lower() == target_mac.lower():
                return iface

        except:
            pass

    return None