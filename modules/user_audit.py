from core.models import Finding
from core.risk_engine import RiskEngine
from core.logger import logger
from core.mitre_mapper import MitreMapper


class UserAudit:

    PASSWORD_NEVER_EXPIRES_FLAG = 0x10000
    ACCOUNT_DISABLED_FLAG = 0x2

    SERVICE_ACCOUNT_KEYWORDS = [
        "svc",
        "service",
        "srv",
        "sql",
        "backup",
        "app",
        "iis"
    ]

    def __init__(self, users):
        self.users = users
        self.findings = []

    def run(self):
        logger.info("Running user security audit")

        for user in self.users:
            username = self.safe_get(user, "sAMAccountName")
            display_name = self.safe_get(user, "displayName")
            user_account_control = self.safe_get(user, "userAccountControl")
            member_of = self.safe_get(user, "memberOf")

            if not username:
                continue

            if user_account_control:
                user_account_control = int(user_account_control)
            else:
                user_account_control = 0

            self.check_password_never_expires(username, user_account_control)
            self.check_disabled_account(username, user_account_control)
            self.check_service_account(username, display_name)
            self.check_domain_admin(username, member_of)
            self.check_user_without_last_logon(username, user)

        logger.info(
            f"User audit completed with {len(self.findings)} findings"
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

    def add_finding(
            self,
            category,
            username,
            finding,
            risk_level,
            recommendation
    ):
        risk_score = RiskEngine.calculate_risk_score(risk_level)
        mitre = MitreMapper.map_finding(finding)

        self.findings.append(
            Finding(
                category=category,
                username=username,
                finding=finding,
                risk_level=risk_level,
                risk_score=risk_score,
                recommendation=recommendation,
                mitre_id=mitre["mitre_id"],
                mitre_tactic=mitre["mitre_tactic"],
                mitre_technique=mitre["mitre_technique"]
            )
        )

    def check_password_never_expires(self, username, user_account_control):
        if user_account_control & self.PASSWORD_NEVER_EXPIRES_FLAG:
            self.add_finding(
                category="Password Policy",
                username=username,
                finding="Password never expires is enabled",
                risk_level="High",
                recommendation="Disable Password Never Expires unless this is a properly managed service account."
            )

    def check_disabled_account(self, username, user_account_control):
        if user_account_control & self.ACCOUNT_DISABLED_FLAG:
            self.add_finding(
                category="Account Hygiene",
                username=username,
                finding="Account is disabled",
                risk_level="Low",
                recommendation="Review disabled accounts and remove unnecessary stale objects."
            )

    def check_service_account(self, username, display_name):
        username_lower = username.lower()

        for keyword in self.SERVICE_ACCOUNT_KEYWORDS:
            if keyword in username_lower:
                self.add_finding(
                    category="Service Account",
                    username=username,
                    finding="Potential service account detected",
                    risk_level="Medium",
                    recommendation="Verify that the service account has minimum required privileges and a documented owner."
                )
                break

    def check_domain_admin(self, username, member_of):
        if not member_of:
            return

        for group in member_of:
            if "CN=Domain Admins" in str(group):
                self.add_finding(
                    category="Privileged Access",
                    username=username,
                    finding="User is a member of Domain Admins",
                    risk_level="Critical",
                    recommendation="Review privileged access and ensure the account is required, monitored, and protected with MFA."
                )

    def check_user_without_last_logon(self, username, user):
        last_logon = self.safe_get(user, "lastLogonTimestamp")

        if not last_logon:
            self.add_finding(
                category="Account Hygiene",
                username=username,
                finding="User has no last logon timestamp",
                risk_level="Medium",
                recommendation="Review the account and verify whether it is unused, newly created, or stale."
            )