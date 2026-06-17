class RiskEngine:

    RISK_LEVELS = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1
    }

    @staticmethod
    def calculate_risk_score(risk_level):
        return RiskEngine.RISK_LEVELS.get(risk_level, 0)

    @staticmethod
    def get_risk_level(score):
        if score >= 10:
            return "Critical"
        elif score >= 7:
            return "High"
        elif score >= 4:
            return "Medium"
        elif score >= 1:
            return "Low"

        return "Info"