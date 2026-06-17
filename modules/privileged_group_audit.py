from core.models import Finding
from core.logger import logger
from core.risk_engine import RiskEngine
from core.mitre_mapper import MitreMapper


class PrivilegedGroupAudit:

    PRIVILEGED_GROUPS = {
        "Domain Admins": "Critical",
        "Enterprise Admins": "Critical",
        "Schema Admins": "Critical",
        "Administrators": "High",
        "Account Operators": "High",
        "Backup Operators": "Medium",
        "Server Operators": "Medium",
        "DNSAdmins": "High"
    }

    def __init__(self, users):
        self.users = users
        self.findings = []

    def run(self):
        logger.info("Running privileged group audit")

        for user in self.users:
            username = self.safe_get(user, "sAMAccountName")
            member_of = self.safe_get(user, "memberOf")

            if not username:
                continue

            if not member_of:
                continue

            for group_dn in member_of:
                group_dn = str(group_dn)

                for group_name, risk_level in self.PRIVILEGED_GROUPS.items():
                    if f"CN={group_name}" in group_dn:
                        self.add_finding(
                            username=username,
                            group_name=group_name,
                            risk_level=risk_level
                        )

        logger.info(
            f"Privileged group audit completed with {len(self.findings)} findings"
        )

        return self.findings

    def safe_get(self, user, attribute):
        try:
            value = user[attribute].value

            if value is None:
                return None

            return value

        except Exception:
            return None

    def add_finding(self, username, group_name, risk_level):
        finding_text = f"Member of privileged group: {group_name}"
        mitre = MitreMapper.map_finding(finding_text)

        self.findings.append(
            Finding(
                category="Privileged Access",
                username=username,
                finding=finding_text,
                risk_level=risk_level,
                risk_score=RiskEngine.calculate_risk_score(risk_level),
                recommendation=(
                    f"Review membership of {group_name} "
                    f"and ensure least privilege principles are applied."
                ),
                mitre_id=mitre["mitre_id"],
                mitre_tactic=mitre["mitre_tactic"],
                mitre_technique=mitre["mitre_technique"]
            )
        )