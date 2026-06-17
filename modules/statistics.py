from collections import defaultdict


class Statistics:

    @staticmethod
    def count_privileged_accounts(findings):
        privileged_users = set()

        for finding in findings:
            if finding.category == "Privileged Access":
                privileged_users.add(finding.username)

        return len(privileged_users)

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

    @staticmethod
    def top_risky_users(findings, limit=10):
        user_scores = defaultdict(int)

        for finding in findings:
            user_scores[finding.username] += finding.risk_score

        sorted_users = sorted(
            user_scores.items(),
            key=lambda item: item[1],
            reverse=True
        )

        return [
            {
                "username": username,
                "score": score
            }
            for username, score in sorted_users[:limit]
        ]