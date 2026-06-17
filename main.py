import typer

from rich.console import Console
from rich.table import Table

from core.logger import logger
from core.ldap_client import LDAPClient
from core.risk_engine import RiskEngine

from modules.user_collector import UserCollector
from modules.user_audit import UserAudit

from reports.report_generator import ReportGenerator

app = typer.Typer()
console = Console()


@app.command()
def scan(
        json_report: bool = typer.Option(
            True,
            "--json/--no-json",
            help="Generate JSON report"
        ),
        csv_report: bool = typer.Option(
            True,
            "--csv/--no-csv",
            help="Generate CSV report"
        ),
        html_report: bool = typer.Option(
            True,
            "--html/--no-html",
            help="Generate HTML dashboard report"
        )
):

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

        security_score = RiskEngine.calculate_security_score(
            findings
        )

        overall_risk_level = RiskEngine.get_overall_risk_level(
            security_score
        )

        console.print(
            f"[yellow]Findings detected: {len(findings)}[/yellow]"
        )

        console.print(
            f"[bold green]AD Security Score: {security_score}/100[/bold green]"
        )

        console.print(
            f"[bold yellow]Overall Risk Level: {overall_risk_level}[/bold yellow]"
        )

        show_findings_table(
            findings
        )

        report_generator = ReportGenerator(
            findings
        )

        if json_report:
            json_file = report_generator.generate_json()

            console.print(
                f"[green]JSON report saved:[/green] {json_file}"
            )

        if csv_report:
            csv_file = report_generator.generate_csv()

            console.print(
                f"[green]CSV report saved:[/green] {csv_file}"
            )

        if html_report:
            html_file = report_generator.generate_html()

            console.print(
                f"[green]HTML report saved:[/green] {html_file}"
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