from core.models import Finding
from core.logger import logger
from core.risk_engine import RiskEngine
from core.mitre_mapper import MitreMapper


class GPOAudit:

    RISKY_KEYWORDS = {
        "LLMNR": {
            "risk": "High",
            "recommendation": "Disable LLMNR to reduce poisoning and relay attack exposure."
        },
        "SMBv1": {
            "risk": "Critical",
            "recommendation": "Disable SMBv1 across the domain."
        },
        "NTLMv1": {
            "risk": "Critical",
            "recommendation": "Disable NTLMv1 and enforce NTLMv2 or Kerberos."
        },
        "WDigest": {
            "risk": "High",
            "recommendation": "Disable WDigest credential caching."
        },
        "Guest": {
            "risk": "High",
            "recommendation": "Ensure Guest account is disabled and not used."
        },
        "Anonymous": {
            "risk": "High",
            "recommendation": "Restrict anonymous access and null session exposure."
        }
    }

    def __init__(self, ldap_client):
        self.ldap_client = ldap_client
        self.findings = []

    def run(self):
        logger.info("Running GPO security audit")

        gpos = self.ldap_client.get_gpos()

        logger.info(
            f"Collected {len(gpos)} GPO objects"
        )

        for gpo in gpos:
            display_name = self.safe_get(gpo, "displayName")
            gpc_file_sys_path = self.safe_get(gpo, "gPCFileSysPath")
            description = self.safe_get(gpo, "description")

            if not display_name:
                continue

            combined_text = f"{display_name} {gpc_file_sys_path} {description}"

            for keyword, details in self.RISKY_KEYWORDS.items():
                if keyword.lower() in combined_text.lower():
                    self.add_finding(
                        gpo_name=display_name,
                        finding=f"GPO contains risky security keyword: {keyword}",
                        risk_level=details["risk"],
                        recommendation=details["recommendation"]
                    )

        logger.info(
            f"GPO audit completed with {len(self.findings)} findings"
        )

        return self.findings

    def safe_get(self, obj, attribute):
        try:
            value = obj[attribute].value

            if value is None:
                return ""

            return str(value)

        except Exception:
            return ""

    def add_finding(
            self,
            gpo_name,
            finding,
            risk_level,
            recommendation
    ):
        mitre = MitreMapper.map_finding(finding)

        self.findings.append(
            Finding(
                category="GPO Audit",
                username=gpo_name,
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