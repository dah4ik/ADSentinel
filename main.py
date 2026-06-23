import typer

from rich.console import Console
from rich.table import Table

from api.cache import update_cache

from core.logger import logger
from core.ldap_client import LDAPClient
from core.risk_engine import RiskEngine

from database.db import init_db
from database.repository import ScanRepository

from modules.user_collector import UserCollector
from modules.user_audit import UserAudit
from modules.privileged_group_audit import PrivilegedGroupAudit
from modules.account_age_audit import AccountAgeAudit
from modules.kerberoasting_audit import KerberoastingAudit
from modules.domain_policy_audit import DomainPolicyAudit
from modules.computer_audit import ComputerAudit
from modules.gpo_audit import GPOAudit
from modules.attack_path_audit import AttackPathAudit
from modules.graph_builder import GraphBuilder
from modules.history_manager import HistoryManager

from reports.report_generator import ReportGenerator

app = typer.Typer()
console = Console()


@app.command()
def scan(
        profile: str = typer.Option(
            "full",
            "--profile",
            help="Scan profile: quick, full, deep"
        ),
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
        ),
        graph_report: bool = typer.Option(
            True,
            "--graph/--no-graph",
            help="Generate BloodHound Lite graph JSON and HTML"
        )
):

    profile = profile.lower()

    if profile not in ["quick", "full", "deep"]:
        console.print(
            "[red]Invalid profile. Use: quick, full, deep[/red]"
        )
        raise typer.Exit(code=1)

    console.print("[bold cyan]ADSentinel[/bold cyan]")
    console.print(f"[cyan]Scan profile: {profile}[/cyan]")

    logger.info(f"Starting ADSentinel scan with profile: {profile}")

    init_db()

    ldap_client = LDAPClient()

    try:
        ldap_client.connect()

        collector = UserCollector(ldap_client)
        users = collector.collect()

        console.print(
            f"[green]Collected {len(users)} users[/green]"
        )

        findings = []

        findings.extend(UserAudit(users).run())
        findings.extend(PrivilegedGroupAudit(users).run())

        if profile in ["full", "deep"]:
            domain_policy = ldap_client.get_domain_policy()

            findings.extend(AccountAgeAudit(users).run())
            findings.extend(KerberoastingAudit(users).run())
            findings.extend(DomainPolicyAudit(domain_policy).run())
            findings.extend(ComputerAudit(ldap_client).run())
            findings.extend(GPOAudit(ldap_client).run())

        if profile == "deep":
            findings.extend(AttackPathAudit(users).run())

        history_manager = HistoryManager(findings)

        comparison = history_manager.compare_with_previous()
        history_file = history_manager.save_current_scan()

        update_cache(findings)

        security_score = RiskEngine.calculate_security_score(findings)
        overall_risk_level = RiskEngine.get_overall_risk_level(
            security_score
        )

        scan_id = ScanRepository.save_scan(
            findings=findings,
            profile=profile,
            security_score=security_score,
            overall_risk_level=overall_risk_level
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

        console.print(
            f"[green]Database scan ID:[/green] {scan_id}"
        )

        console.print(
            f"[cyan]New Findings: +{comparison['new_findings']}[/cyan]"
        )

        console.print(
            f"[green]Resolved Findings: -{comparison['resolved_findings']}[/green]"
        )

        console.print(
            f"[green]Historical scan saved:[/green] {history_file}"
        )

        show_findings_table(findings)

        report_generator = ReportGenerator(findings)

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

        if graph_report and profile == "deep":
            graph_builder = GraphBuilder(
                users=users,
                ldap_client=ldap_client
            )

            graph_json_file = graph_builder.save_json()
            graph_html_file = graph_builder.save_html()

            console.print(
                f"[green]Graph JSON saved:[/green] {graph_json_file}"
            )

            console.print(
                f"[green]Graph HTML saved:[/green] {graph_html_file}"
            )

        elif graph_report and profile != "deep":
            console.print(
                "[yellow]Graph generation is available only in deep profile[/yellow]"
            )

    except Exception as e:
        logger.error(str(e))
        console.print(f"[red]{e}[/red]")

    finally:
        ldap_client.disconnect()

    logger.info("Scan finished")


def show_findings_table(findings):

    table = Table(title="ADSentinel Findings")

    table.add_column("Risk", style="bold")
    table.add_column("User")
    table.add_column("Category")
    table.add_column("Finding")
    table.add_column("MITRE")
    table.add_column("Score")

    sorted_findings = sorted(
        findings,
        key=lambda finding: finding.risk_score,
        reverse=True
    )

    for finding in sorted_findings[:20]:
        table.add_row(
            finding.risk_level,
            finding.username,
            finding.category,
            finding.finding,
            finding.mitre_id,
            str(finding.risk_score)
        )

    console.print(table)


if __name__ == "__main__":
    app()