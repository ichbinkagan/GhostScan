import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def show_banner():
    # Cyberpunk style border top
    console.print("[bold #39ff14]┌───────────────────────────────────────────────────────────┐[/]")
    
    # Vertical RGB/Rainbow gradient using precise neon Hex colors
    console.print(" [bold #ff0055]██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗[/]")
    console.print(" [bold #ff5500]██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝[/]")
    console.print(" [bold #ffcc00]██║  ███╗███████║██║   ██║███████╗   ██║   [/]")
    console.print(" [bold #33ff00]██║   ██║██╔══██║██║   ██║╚════██║   ██║   [/]")
    console.print(" [bold #00ffcc]╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   [/]")
    console.print(" [bold #0099ff] ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   [/]")
    
    # Cyberpunk style border bottom
    console.print("[bold #39ff14]└───────────────────────────────────────────────────────────┘[/]")
    
    # Subtitle and versioning details
    console.print("\n[bold #ff0055]»»»[/] [bold white on #8a2be2]  GHOSTSCAN  [/] [bold #00ffff]Network Analyzer v1.0-Beta[/] [bold #ff0055]«««[/]")
    console.print("[dim cyan]    [SYS] Initializing stealth scanning modules...[/]\n")

    # Animated loading sequence
    with Progress(
        SpinnerColumn("bouncingBar", speed=1.5, style="bold #00ffff"),
        TextColumn("[progress.description]{task.description}"),
        console=Console(),
        transient=True # Automatically clears the progress bar when done
    ) as progress:
        task = progress.add_task("[bold #39ff14]Loading Ghost Engines...[/]", total=100)
        while not progress.finished:
            progress.update(task, advance=4)
            time.sleep(0.04)

    # Success / Status panel
    console.print(Panel(
        "[bold #39ff14][✓] ACCESS GRANTED[/] | [bold #00ffff]STALKER MODE: ACTIVE[/] | [bold #ffcc00]VPN: SECURE[/]", 
        border_style="bold #39ff14",
        title="[bold #ff0055]SYSTEM STATUS[/]",
        title_align="left"
    ))
    console.print("")

# Run the banner
show_banner()