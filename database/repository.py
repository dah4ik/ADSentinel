from database.db import get_db_session
from database.models import Scan
from database.models import FindingRecord
from database.models import ScanStatistic


class ScanRepository:

    @staticmethod
    def save_scan(
            findings,
            profile,
            security_score,
            overall_risk_level
    ):
        db = get_db_session()

        try:
            scan = Scan(
                profile=profile,
                total_findings=len(findings),
                security_score=security_score,
                overall_risk_level=overall_risk_level
            )

            db.add(scan)
            db.commit()
            db.refresh(scan)

            for finding in findings:
                finding_dict = finding.to_dict()

                record = FindingRecord(
                    scan_id=scan.id,
                    category=finding_dict.get("category"),
                    username=finding_dict.get("username"),
                    finding=finding_dict.get("finding"),
                    risk_level=finding_dict.get("risk_level"),
                    risk_score=finding_dict.get("risk_score"),
                    recommendation=finding_dict.get("recommendation"),
                    mitre_id=finding_dict.get("mitre_id"),
                    mitre_tactic=finding_dict.get("mitre_tactic"),
                    mitre_technique=finding_dict.get("mitre_technique"),
                    cis_control=finding_dict.get("cis_control"),
                    nist_csf=finding_dict.get("nist_csf"),
                    iso_27001=finding_dict.get("iso_27001")
                )

                db.add(record)

            statistic = ScanStatistic(
                scan_id=scan.id,
                critical_count=ScanRepository.count_by_risk(
                    findings,
                    "Critical"
                ),
                high_count=ScanRepository.count_by_risk(
                    findings,
                    "High"
                ),
                medium_count=ScanRepository.count_by_risk(
                    findings,
                    "Medium"
                ),
                low_count=ScanRepository.count_by_risk(
                    findings,
                    "Low"
                )
            )

            db.add(statistic)
            db.commit()

            return scan.id

        finally:
            db.close()

    @staticmethod
    def count_by_risk(findings, risk_level):
        return len(
            [
                finding
                for finding in findings
                if finding.risk_level == risk_level
            ]
        )

    @staticmethod
    def get_scans():
        db = get_db_session()

        try:
            scans = (
                db.query(Scan)
                .order_by(Scan.started_at.desc())
                .all()
            )

            return [
                {
                    "id": scan.id,
                    "started_at": scan.started_at.isoformat(),
                    "profile": scan.profile,
                    "total_findings": scan.total_findings,
                    "security_score": scan.security_score,
                    "overall_risk_level": scan.overall_risk_level
                }
                for scan in scans
            ]

        finally:
            db.close()

    @staticmethod
    def get_latest_scan():
        db = get_db_session()

        try:
            scan = (
                db.query(Scan)
                .order_by(Scan.started_at.desc())
                .first()
            )

            if not scan:
                return None

            return {
                "id": scan.id,
                "started_at": scan.started_at.isoformat(),
                "profile": scan.profile,
                "total_findings": scan.total_findings,
                "security_score": scan.security_score,
                "overall_risk_level": scan.overall_risk_level
            }

        finally:
            db.close()