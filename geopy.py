import ipinfo
import socket
from rich.table import Table
from rich.console import Console

console = Console()



ACCESS_TOKEN = '18667333398b8e'
handler = ipinfo.getHandler(ACCESS_TOKEN)

def get_data():
    console.print("[bold cyan]--- GhostScan IP Geolocation ---[/bold cyan]")

    target_ip = input("Enter Target IP (leave empty for your own public IP): ").strip()

    try:
        console.print("[yellow]Fetching geolocation data... Please wait.[/yellow]")

        details = handler.getDetails(target_ip)

        table = Table(title=f"IP Geolocation Results ({details.ip})")
        table.add_column("Property", style="cyan", justify="left")
        table.add_column("Value", style="bold yellow", justify="left")

        table.add_row("IP Address", getattr(details, "ip", "-"))
        table.add_row("Hostname", getattr(details, "hostname", "N/A"))
        table.add_row("Country", getattr(details, "country_name", "-"))
        table.add_row("Region/State", getattr(details, "region", "-"))
        table.add_row("City", getattr(details, "city", "-"))
        table.add_row("Postal Code", getattr(details, "postal", "-"))
        table.add_row("Coordinates (Lat,Lon)", getattr(details, "loc", "-"))
        table.add_row("Timezone", getattr(details, "timezone", "-"))

        org = getattr(details, "org", "-")
        table.add_row("Provider/ISP", org)
        
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error fetching IP data: {e}[/red]")