class RiskEngine:

    RISK_LEVELS = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1,
        "Info": 0
    }

    @staticmethod
    def calculate_risk_score(risk_level):
        return RiskEngine.RISK_LEVELS.get(risk_level, 0)

    @staticmethod
    def calculate_security_score(findings):
        if not findings:
            return 100

        total_risk = sum(
            finding.risk_score
            for finding in findings
        )

        score = 100 - total_risk

        if score < 0:
            score = 0

        return score

    @staticmethod
    def get_overall_risk_level(score):
        if score >= 85:
            return "Low"
        elif score >= 70:
            return "Medium"
        elif score >= 50:
            return "High"

        return "Critical"