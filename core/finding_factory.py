from core.models import Finding
from core.risk_engine import RiskEngine
from core.mitre_mapper import MitreMapper
from core.compliance_mapper import ComplianceMapper


class FindingFactory:

    @staticmethod
    def create(
            category,
            username,
            finding,
            risk_level,
            recommendation
    ):
        mitre = MitreMapper.map_finding(
            finding
        )

        compliance = ComplianceMapper.map_category(
            category
        )

        return Finding(
            category=category,
            username=username,
            finding=finding,
            risk_level=risk_level,
            risk_score=RiskEngine.calculate_risk_score(
                risk_level
            ),
            recommendation=recommendation,
            mitre_id=mitre["mitre_id"],
            mitre_tactic=mitre["mitre_tactic"],
            mitre_technique=mitre["mitre_technique"],
            cis_control=compliance["cis_control"],
            nist_csf=compliance["nist_csf"],
            iso_27001=compliance["iso_27001"]
        )