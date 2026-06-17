from core.models import Finding
from core.logger import logger
from core.risk_engine import RiskEngine
from core.mitre_mapper import MitreMapper


class DomainPolicyAudit:

    MIN_PASSWORD_LENGTH_RECOMMENDED = 14
    PASSWORD_HISTORY_RECOMMENDED = 24
    LOCKOUT_THRESHOLD_RECOMMENDED = 10

    def __init__(self, domain_policy):
        self.domain_policy = domain_policy
        self.findings = []

    def run(self):
        logger.info("Running domain password policy audit")

        if not self.domain_policy:
            logger.warning("Skipping domain policy audit because policy object is empty")
            return self.findings

        min_pwd_length = self.safe_get("minPwdLength")
        pwd_history_length = self.safe_get("pwdHistoryLength")
        lockout_threshold = self.safe_get("lockoutThreshold")

        self.check_min_password_length(min_pwd_length)
        self.check_password_history(pwd_history_length)
        self.check_lockout_threshold(lockout_threshold)

        logger.info(
            f"Domain policy audit completed with {len(self.findings)} findings"
        )

        return self.findings

    def safe_get(self, attribute):
        try:
            value = self.domain_policy[attribute].value

            if value is None:
                return None

            return int(value)

        except Exception:
            return None

    def add_finding(
            self,
            finding,
            risk_level,
            recommendation
    ):
        mitre = MitreMapper.map_finding(finding)

        self.findings.append(
            Finding(
                category="Domain Policy",
                username="DOMAIN",
                finding=finding,
                risk_level=risk_level,
                risk_score=RiskEngine.calculate_risk_score(risk_level),
                recommendation=recommendation,
                mitre_id=mitre["mitre_id"],
                mitre_tactic=mitre["mitre_tactic"],
                mitre_technique=mitre["mitre_technique"]
            )
        )

    def check_min_password_length(self, min_pwd_length):
        if min_pwd_length is None:
            return

        if min_pwd_length < self.MIN_PASSWORD_LENGTH_RECOMMENDED:
            self.add_finding(
                finding=f"Minimum password length is {min_pwd_length}",
                risk_level="High",
                recommendation="Set minimum password length to at least 14 characters."
            )

    def check_password_history(self, pwd_history_length):
        if pwd_history_length is None:
            return

        if pwd_history_length < self.PASSWORD_HISTORY_RECOMMENDED:
            self.add_finding(
                finding=f"Password history length is {pwd_history_length}",
                risk_level="Medium",
                recommendation="Configure password history to remember at least 24 previous passwords."
            )

    def check_lockout_threshold(self, lockout_threshold):
        if lockout_threshold is None:
            return

        if lockout_threshold == 0:
            self.add_finding(
                finding="Account lockout threshold is disabled",
                risk_level="High",
                recommendation="Enable account lockout policy to reduce password guessing risk."
            )

        elif lockout_threshold > self.LOCKOUT_THRESHOLD_RECOMMENDED:
            self.add_finding(
                finding=f"Account lockout threshold is too high: {lockout_threshold}",
                risk_level="Medium",
                recommendation="Review lockout threshold and align it with organizational security baseline."
            )