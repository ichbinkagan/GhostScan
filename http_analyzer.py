from scapy.all import rdpcap, IP, TCP, Raw
from rich.table import Table
from rich.console import Console
from datetime import datetime
import os

console = Console()

def parse_sni_from_raw(payload):
    """
    Scapy TLS modülüne güvenmeden, ham TCP verisindeki TLS Client Hello
    paketinden el ile Server Name Indication (SNI) / Domain adını ayıklar.
    """
    try:
        if len(payload) < 5:
            return None
        
        # TLS Handshake (0x16) ve Client Hello (0x01) kontrolü
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None
        
        pos = 43  # Session ID öncesi sabit offset
        if len(payload) < pos: return None
        
        # Session ID atla
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        
        # Cipher Suites atla
        if len(payload) < pos + 2: return None
        cipher_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
        pos += 2 + cipher_len
        
        # Compression Methods atla
        if len(payload) < pos + 1: return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        
        # Extensions alanına gelindi mi?
        if len(payload) < pos + 2: return None
        extensions_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
        pos += 2
        
        end_pos = pos + extensions_len
        
        # Uzantılar içinde SNI (Extension Type: 0x0000) ara
        while pos + 4 <= end_pos and pos < len(payload):
            ext_type = int.from_bytes(payload[pos:pos+2], byteorder='big')
            ext_len = int.from_bytes(payload[pos+2:pos+4], byteorder='big')
            pos += 4
            
            if ext_type == 0:  # server_name extension
                if pos + 2 <= len(payload):
                    list_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
                    # Name Type: 0x00 (host_name)
                    if pos + 5 <= len(payload) and payload[pos+2] == 0x00:
                        name_len = int.from_bytes(payload[pos+3:pos+5], byteorder='big')
                        if pos + 5 + name_len <= len(payload):
                            return payload[pos+5:pos+5+name_len].decode('utf-8', errors='ignore')
            pos += ext_len
    except Exception:
        pass
    return None

def http_analyze():
    filename = "network_traffic.pcap"

    if not os.path.exists(filename):
        console.print("[red]cannot find network_traffic.pcap[/red]")
        return

    try:
        packets = rdpcap(filename)
    except Exception as e:
        console.print(f"[red]Error reading PCAP: {e}[/red]")
        return

    table = Table(title="GhostScan HTTP/HTTPS Analyzer")

    table.add_column("NO", justify="center")
    table.add_column("Time", justify="center")
    table.add_column("Protocol/Method", style="cyan")
    table.add_column("Source IP", style="green")
    table.add_column("Destination IP", style="green")
    table.add_column("Host (Domain)", style="bold yellow")
    table.add_column("Path")
    table.add_column("Status", justify="center")
    table.add_column("User-Agent")

    counter = 1

    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            continue

        time_str = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Paket içinde ham veri (Raw) var mı?
        if packet.haslayer(Raw):
            payload = packet[Raw].load

            # --- 1. HTTP TESPİTİ (Port 80) ---
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                try:
                    data = payload.decode("utf-8", errors="ignore")
                    lines = data.split("\r\n")
                    if lines and len(lines[0]) > 0:
                        first_line = lines[0].split(" ")
                        
                        if data.startswith(("GET", "POST", "PUT", "DELETE")):
                            method = first_line[0]
                            path = first_line[1] if len(first_line) > 1 else "-"
                            host = "-"
                            user_agent = "-"
                            
                            for line in lines:
                                if line.startswith("Host:"):
                                    host = line.replace("Host:", "").strip()
                                elif line.startswith("User-Agent:"):
                                    user_agent = line.replace("User-Agent:", "").strip()

                            table.add_row(
                                str(counter), time_str, method, src_ip, dst_ip,
                                host, path, "-", user_agent[:25] if user_agent != "-" else "-"
                            )
                            counter += 1
                            continue

                        elif data.startswith("HTTP/"):
                            status = first_line[1] if len(first_line) > 1 else "RESP"
                            table.add_row(
                                str(counter), time_str, "HTTP RESP", src_ip, dst_ip,
                                "-", "-", status, "-"
                            )
                            counter += 1
                            continue
                except Exception:
                    pass

            # --- 2. HTTPS TESPİTİ (Port 443 - SNI Ayıklama) ---
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                server_name = parse_sni_from_raw(payload)
                if server_name:
                    table.add_row(
                        str(counter), time_str, "HTTPS (TLS)", src_ip, dst_ip,
                        server_name, "[ENCRYPTED]", "-", "-"
                    )
                    counter += 1

    console.print(table)