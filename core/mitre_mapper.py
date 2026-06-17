class MitreMapper:

    MAPPINGS = {
        "Password never expires is enabled": {
            "mitre_id": "T1078",
            "mitre_tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "mitre_technique": "Valid Accounts"
        },
        "User is a member of Domain Admins": {
            "mitre_id": "T1098",
            "mitre_tactic": "Persistence, Privilege Escalation",
            "mitre_technique": "Account Manipulation"
        },
        "Member of privileged group": {
            "mitre_id": "T1098",
            "mitre_tactic": "Persistence, Privilege Escalation",
            "mitre_technique": "Account Manipulation"
        },
        "Potential service account detected": {
            "mitre_id": "T1078.002",
            "mitre_tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "mitre_technique": "Domain Accounts"
        },
        "User has no last logon timestamp": {
            "mitre_id": "T1078",
            "mitre_tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "mitre_technique": "Valid Accounts"
        },
        "Enabled account inactive": {
            "mitre_id": "T1078",
            "mitre_tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "mitre_technique": "Valid Accounts"
        },
        "Privileged account inactive": {
            "mitre_id": "T1078.002",
            "mitre_tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "mitre_technique": "Domain Accounts"
        },
        "Password age is": {
            "mitre_id": "T1078",
            "mitre_tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "mitre_technique": "Valid Accounts"
        },
        "Privileged account password age": {
            "mitre_id": "T1078.002",
            "mitre_tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "mitre_technique": "Domain Accounts"
        },
        "Account is disabled": {
            "mitre_id": "N/A",
            "mitre_tactic": "N/A",
            "mitre_technique": "N/A"
        },
        "Kerberoasting risk": {
            "mitre_id": "T1558.003",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Kerberoasting"
        },
        "SPN value": {
            "mitre_id": "T1558.003",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Kerberoasting"
        },
        "Minimum password length": {
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force"
        },
        "Password history length": {
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force"
        },
        "Account lockout threshold": {
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force"
        }
    }

    @staticmethod
    def map_finding(finding_text):
        for keyword, mapping in MitreMapper.MAPPINGS.items():
            if keyword.lower() in finding_text.lower():
                return mapping

        return {
            "mitre_id": "N/A",
            "mitre_tactic": "N/A",
            "mitre_technique": "N/A"
        }