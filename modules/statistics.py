class Statistics:

    @staticmethod
    def count_privileged_accounts(findings):

        return len(
            [
                finding
                for finding in findings
                if finding.category == "Privileged Access"
            ]
        )

    @staticmethod
    def count_critical(findings):

        return len(
            [
                finding
                for finding in findings
                if finding.risk_level == "Critical"
            ]
        )

    @staticmethod
    def count_high(findings):

        return len(
            [
                finding
                for finding in findings
                if finding.risk_level == "High"
            ]
        )