import socket
import threading
from queue import Queue
from rich.table import Table
from rich.console import Console

console = Console()

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

def scan_port(target_ip, port, open_ports):

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((target_ip, port))

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            open_ports.append((port, service))
        s.close()
    except Exception:
        pass
def worker(target_ip, queue, open_ports):
    while not queue.empty():
        port = queue.get()
        scan_port(target_ip, port, open_ports)
        queue.task_done()
def port_scan():
    console.print("[bold cyan]--- GhostScan Port Scanner ---[/bold cyan]")
    target = input("Enter Target IP or Domain (e.g., 192.168.1.1): ").strip()

    if not target:
        console.print("[red]Target cannot be empty![/red]")
        return

    try:
        # Resolve target domain to IP if a hostname is given
        target_ip = socket.gethostbyname(target)
        console.print(f"[yellow]Scanning target: {target} ({target_ip})[/yellow]")
    except socket.gaierror:
        console.print("[red]Could not resolve hostname. Please check the IP/Domain.[/red]")
        return
    
    open_ports = []
    queue = Queue()

    for port in COMMON_PORTS.keys():
        queue.put(port)

    threads = []
    for _ in range(10):
        t = threading.Thread(target=worker, args=(target_ip, queue, open_ports))
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()

    table = Table(title=f"Scan Results for {target_ip}")
    table.add_column("Port", justify="center", style="cyan")
    table.add_column("Status", justify="center", style="green")
    table.add_column("Service/Protocol", style="bold yellow")

    if open_ports:
        # Sort the open ports numerically before displaying
        for port, service in sorted(open_ports):
            table.add_row(str(port), "OPEN", service)
    else:
        # If no ports are open, show a clean message inside the table
        table.add_row("-", "No open ports found", "Try scanning a different host")

    console.print(table)
    