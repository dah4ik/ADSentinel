class ComplianceMapper:

    MAPPINGS = {
        "Privileged Access": {
            "cis_control": "CIS Control 6 - Access Control Management",
            "nist_csf": "PR.AC - Identity Management, Authentication and Access Control",
            "iso_27001": "A.5.15 - Access Control"
        },
        "Password Policy": {
            "cis_control": "CIS Control 5 - Account Management",
            "nist_csf": "PR.AC - Identity Management, Authentication and Access Control",
            "iso_27001": "A.5.17 - Authentication Information"
        },
        "Account Hygiene": {
            "cis_control": "CIS Control 5 - Account Management",
            "nist_csf": "PR.AC - Identity Management, Authentication and Access Control",
            "iso_27001": "A.5.18 - Access Rights"
        },
        "Service Account": {
            "cis_control": "CIS Control 5 - Account Management",
            "nist_csf": "PR.AC - Identity Management, Authentication and Access Control",
            "iso_27001": "A.5.16 - Identity Management"
        },
        "Kerberoasting": {
            "cis_control": "CIS Control 6 - Access Control Management",
            "nist_csf": "PR.AC - Identity Management, Authentication and Access Control",
            "iso_27001": "A.5.17 - Authentication Information"
        },
        "Domain Policy": {
            "cis_control": "CIS Control 5 - Account Management",
            "nist_csf": "PR.AC - Identity Management, Authentication and Access Control",
            "iso_27001": "A.5.17 - Authentication Information"
        },
        "Computer Audit": {
            "cis_control": "CIS Control 7 - Continuous Vulnerability Management",
            "nist_csf": "ID.AM - Asset Management",
            "iso_27001": "A.8.8 - Management of Technical Vulnerabilities"
        },
        "GPO Audit": {
            "cis_control": "CIS Control 4 - Secure Configuration of Enterprise Assets",
            "nist_csf": "PR.IP - Information Protection Processes and Procedures",
            "iso_27001": "A.8.9 - Configuration Management"
        },
        "Attack Path": {
            "cis_control": "CIS Control 6 - Access Control Management",
            "nist_csf": "PR.AC - Identity Management, Authentication and Access Control",
            "iso_27001": "A.5.15 - Access Control"
        }
    }

    @staticmethod
    def map_category(category):
        return ComplianceMapper.MAPPINGS.get(
            category,
            {
                "cis_control": "N/A",
                "nist_csf": "N/A",
                "iso_27001": "N/A"
            }
        )