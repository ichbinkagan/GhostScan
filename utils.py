from rich.console import Console

console = Console()

import json

def save_json(data,filename):

    with open(filename, "w") as f:
        json.dump(
            data,
            f,
            indent=4
        )