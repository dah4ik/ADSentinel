import typer
from rich.console import Console
from core.logger import logger

app = typer.Typer()
console = Console()


@app.command()
def scan():
    console.print("[bold cyan]ADSentinel - Active Directory Security Assessment Platform[/bold cyan]")
    logger.info("Starting ADSentinel scan")

    console.print("[yellow]Project skeleton is ready. LDAP module will be added in the next commit.[/yellow]")

    logger.info("Scan finished")


if __name__ == "__main__":
    app()