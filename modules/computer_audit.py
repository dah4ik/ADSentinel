from core.models import Finding
from core.logger import logger
from core.risk_engine import RiskEngine
from core.mitre_mapper import MitreMapper

from datetime import datetime


class ComputerAudit:

    SUPPORTED_OS = [
        "Windows 10",
        "Windows 11",
        "Windows Server 2019",
        "Windows Server 2022"
    ]

    def __init__(self, ldap_client):
        self.ldap_client = ldap_client
        self.findings = []

    def run(self):

        logger.info(
            "Running computer audit"
        )

        computers = self.ldap_client.get_computers()

        logger.info(
            f"Collected {len(computers)} computers"
        )

        for computer in computers:

            computer_name = self.safe_get(
                computer,
                "name"
            )

            operating_system = self.safe_get(
                computer,
                "operatingSystem"
            )

            user_account_control = self.safe_get(
                computer,
                "userAccountControl"
            )

            if not computer_name:
                continue

            self.check_disabled_computer(
                computer_name,
                user_account_control
            )

            self.check_os(
                computer_name,
                operating_system
            )

        logger.info(
            f"Computer audit completed with {len(self.findings)} findings"
        )

        return self.findings

    def safe_get(self, obj, attribute):

        try:
            value = obj[attribute].value

            if value is None:
                return None

            return value

        except Exception:
            return None

    def check_disabled_computer(
            self,
            computer_name,
            user_account_control
    ):

        try:

            if int(user_account_control) & 0x2:

                self.add_finding(
                    computer_name,
                    "Disabled computer object",
                    "Low",
                    "Review disabled computer accounts and remove stale objects."
                )

        except Exception:
            pass

    def check_os(
            self,
            computer_name,
            operating_system
    ):

        if not operating_system:
            return

        supported = False

        for os_name in self.SUPPORTED_OS:

            if os_name.lower() in operating_system.lower():
                supported = True

        if not supported:

            self.add_finding(
                computer_name,
                f"Unsupported operating system: {operating_system}",
                "High",
                "Upgrade operating system to a supported version."
            )

    def add_finding(
            self,
            computer_name,
            finding,
            risk_level,
            recommendation
    ):

        mitre = MitreMapper.map_finding(
            finding
        )

        self.findings.append(
            Finding(
                category="Computer Audit",
                username=computer_name,
                finding=finding,
                risk_level=risk_level,
                risk_score=RiskEngine.calculate_risk_score(
                    risk_level
                ),
                recommendation=recommendation,
                mitre_id=mitre["mitre_id"],
                mitre_tactic=mitre["mitre_tactic"],
                mitre_technique=mitre["mitre_technique"]
            )
        )