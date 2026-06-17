from core.models import Finding
from core.logger import logger
from core.risk_engine import RiskEngine
from core.mitre_mapper import MitreMapper


class KerberoastingAudit:

    PRIVILEGED_GROUP_KEYWORDS = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "DNSAdmins"
    ]

    def __init__(self, users):
        self.users = users
        self.findings = []

    def run(self):
        logger.info("Running Kerberoasting risk audit")

        for user in self.users:
            username = self.safe_get(user, "sAMAccountName")

            if not username:
                continue

            spns = self.safe_get(user, "servicePrincipalName")
            member_of = self.safe_get(user, "memberOf")
            user_account_control = self.safe_get(user, "userAccountControl")

            if not spns:
                continue

            is_privileged = self.is_privileged(member_of)
            is_disabled = self.is_disabled(user_account_control)

            self.add_spn_finding(
                username=username,
                spns=spns,
                is_privileged=is_privileged,
                is_disabled=is_disabled
            )

        logger.info(
            f"Kerberoasting audit completed with {len(self.findings)} findings"
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

    def is_disabled(self, user_account_control):
        try:
            return int(user_account_control) & 0x2 != 0
        except Exception:
            return False

    def is_privileged(self, member_of):
        if not member_of:
            return False

        for group in member_of:
            group = str(group)

            for privileged_group in self.PRIVILEGED_GROUP_KEYWORDS:
                if f"CN={privileged_group}" in group:
                    return True

        return False

    def add_spn_finding(
            self,
            username,
            spns,
            is_privileged,
            is_disabled
    ):
        spn_count = len(spns) if isinstance(spns, list) else 1

        if is_disabled:
            risk_level = "Low"
            finding = f"Disabled account has {spn_count} SPN value(s)"
            recommendation = (
                "Review and remove unnecessary SPN values from disabled accounts."
            )

        elif is_privileged:
            risk_level = "Critical"
            finding = f"Privileged account has {spn_count} SPN value(s), Kerberoasting risk"
            recommendation = (
                "Immediately review this privileged SPN account. "
                "Use strong managed passwords or gMSA where possible, "
                "and verify that privileged rights are required."
            )

        else:
            risk_level = "High"
            finding = f"Account has {spn_count} SPN value(s), Kerberoasting risk"
            recommendation = (
                "Review service account password strength, rotation process, "
                "and consider using gMSA for service authentication."
            )

        mitre = MitreMapper.map_finding(finding)

        self.findings.append(
            Finding(
                category="Kerberoasting",
                username=username,
                finding=finding,
                risk_level=risk_level,
                risk_score=RiskEngine.calculate_risk_score(risk_level),
                recommendation=recommendation,
                mitre_id=mitre["mitre_id"],
                mitre_tactic=mitre["mitre_tactic"],
                mitre_technique=mitre["mitre_technique"]
            )
        )