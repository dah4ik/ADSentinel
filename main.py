import typer

from rich.console import Console
from rich.table import Table

from core.logger import logger
from core.ldap_client import LDAPClient

from modules.user_collector import UserCollector
from modules.user_audit import UserAudit

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

        user_audit = UserAudit(
            users
        )

        findings = user_audit.run()

        console.print(
            f"[yellow]Findings detected: {len(findings)}[/yellow]"
        )

        show_findings_table(
            findings
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


def show_findings_table(findings):

    table = Table(
        title="ADSentinel Findings"
    )

    table.add_column(
        "Risk",
        style="bold"
    )

    table.add_column(
        "User"
    )

    table.add_column(
        "Category"
    )

    table.add_column(
        "Finding"
    )

    table.add_column(
        "Score"
    )

    for finding in findings[:20]:
        table.add_row(
            finding.risk_level,
            finding.username,
            finding.category,
            finding.finding,
            str(finding.risk_score)
        )

    console.print(table)


if __name__ == "__main__":
    app()