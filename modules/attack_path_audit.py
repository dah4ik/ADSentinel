from core.models import Finding
from core.risk_engine import RiskEngine
from core.logger import logger
from core.mitre_mapper import MitreMapper


class AttackPathAudit:

    HIGH_RISK_GROUPS = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators"
    ]

    INTERMEDIATE_GROUPS = [
        "Backup Operators",
        "Server Operators",
        "Account Operators",
        "DNSAdmins"
    ]

    def __init__(self, users):
        self.users = users
        self.findings = []

    def run(self):

        logger.info(
            "Running attack path audit"
        )

        for user in self.users:

            username = self.safe_get(
                user,
                "sAMAccountName"
            )

            member_of = self.safe_get(
                user,
                "memberOf"
            )

            if not username:
                continue

            if not member_of:
                continue

            groups = []

            for group in member_of:
                groups.append(str(group))

            self.detect_attack_paths(
                username,
                groups
            )

        logger.info(
            f"Attack path audit completed with {len(self.findings)} findings"
        )

        return self.findings

    def detect_attack_paths(
            self,
            username,
            groups
    ):

        has_intermediate_group = False
        has_admin_group = False

        for group in groups:

            for admin_group in self.HIGH_RISK_GROUPS:

                if f"CN={admin_group}" in group:
                    has_admin_group = True

            for operator_group in self.INTERMEDIATE_GROUPS:

                if f"CN={operator_group}" in group:
                    has_intermediate_group = True

        if has_intermediate_group and has_admin_group:

            self.add_finding(
                username=username,
                finding=(
                    "Potential privilege escalation attack path detected"
                ),
                risk_level="Critical",
                recommendation=(
                    "Review group nesting and privileged memberships. "
                    "Remove unnecessary operator privileges."
                )
            )

    def add_finding(
            self,
            username,
            finding,
            risk_level,
            recommendation
    ):

        mitre = MitreMapper.map_finding(
            finding
        )

        self.findings.append(
            Finding(
                category="Attack Path",
                username=username,
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

    def safe_get(
            self,
            obj,
            attribute
    ):

        try:
            value = obj[attribute].value

            if value is None:
                return None

            return value

        except Exception:
            return None