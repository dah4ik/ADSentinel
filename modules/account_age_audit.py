from config.settings import settings
from core.models import Finding
from core.logger import logger
from core.risk_engine import RiskEngine
from core.mitre_mapper import MitreMapper
from utils.helpers import days_since


class AccountAgeAudit:

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
        logger.info("Running account age and password audit")

        for user in self.users:
            username = self.safe_get(user, "sAMAccountName")

            if not username:
                continue

            last_logon = self.safe_get(user, "lastLogonTimestamp")
            pwd_last_set = self.safe_get(user, "pwdLastSet")
            member_of = self.safe_get(user, "memberOf")
            user_account_control = self.safe_get(user, "userAccountControl")

            is_disabled = self.is_disabled(user_account_control)
            is_privileged = self.is_privileged(member_of)

            self.check_inactive_account(
                username=username,
                last_logon=last_logon,
                is_disabled=is_disabled,
                is_privileged=is_privileged
            )

            self.check_old_password(
                username=username,
                pwd_last_set=pwd_last_set,
                is_privileged=is_privileged
            )

        logger.info(
            f"Account age audit completed with {len(self.findings)} findings"
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

    def check_inactive_account(
            self,
            username,
            last_logon,
            is_disabled,
            is_privileged
    ):
        inactive_days = days_since(last_logon)

        if inactive_days is None:
            return

        if inactive_days >= settings.INACTIVE_DAYS and not is_disabled:
            if is_privileged:
                risk_level = "Critical"
                finding = f"Privileged account inactive for {inactive_days} days"
                recommendation = (
                    "Immediately review this privileged account, disable it if unused, "
                    "and verify whether privileged access is still required."
                )
            else:
                risk_level = "High"
                finding = f"Enabled account inactive for {inactive_days} days"
                recommendation = (
                    "Review the account owner and disable or remove the account if it is no longer needed."
                )

            self.add_finding(
                category="Account Hygiene",
                username=username,
                finding=finding,
                risk_level=risk_level,
                recommendation=recommendation
            )

    def check_old_password(self, username, pwd_last_set, is_privileged):
        password_age_days = days_since(pwd_last_set)

        if password_age_days is None:
            return

        if password_age_days >= settings.OLD_PASSWORD_DAYS:
            if is_privileged:
                risk_level = "High"
                finding = f"Privileged account password age is {password_age_days} days"
                recommendation = (
                    "Rotate the privileged account password and review password management controls."
                )
            else:
                risk_level = "Medium"
                finding = f"Password age is {password_age_days} days"
                recommendation = (
                    "Review password rotation policy and verify that password age meets organizational requirements."
                )

            self.add_finding(
                category="Password Policy",
                username=username,
                finding=finding,
                risk_level=risk_level,
                recommendation=recommendation
            )

    def add_finding(
            self,
            category,
            username,
            finding,
            risk_level,
            recommendation
    ):
        mitre = MitreMapper.map_finding(finding)

        self.findings.append(
            Finding(
                category=category,
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