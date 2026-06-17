import typer

from rich.console import Console

from core.logger import logger
from core.ldap_client import LDAPClient

from modules.user_collector import UserCollector

app = typer.Typer()
console = Console()


@app.command()
def scan():

    console.print(
        "[bold cyan]ADSentinel[/bold cyan]"
    )

    logger.info(
        "Starting ADSentinel scan"
    )

    ldap_client = LDAPClient()

    try:

        ldap_client.connect()

        collector = UserCollector(
            ldap_client
        )

        users = collector.collect()

        console.print(
            f"[green]Collected {len(users)} users[/green]"
        )

    except Exception as e:

        logger.error(
            str(e)
        )

        console.print(
            f"[red]{e}[/red]"
        )

    finally:

        ldap_client.disconnect()

    logger.info(
        "Scan finished"
    )


if __name__ == "__main__":
    app()