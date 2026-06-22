import json
import os
from datetime import datetime

from core.logger import logger

HISTORY_DIR = "output/json/scan_history"
LATEST_FILE = "output/json/latest_findings.json"
COMPARISON_FILE = "output/json/scan_comparison.json"


class HistoryManager:

    def __init__(self, findings):
        self.findings = [
            finding.to_dict()
            for finding in findings
        ]

        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def save_current_scan(self):
        os.makedirs(
            HISTORY_DIR,
            exist_ok=True
        )

        file_path = (
            f"{HISTORY_DIR}/"
            f"scan_{self.timestamp}.json"
        )

        with open(
                file_path,
                "w",
                encoding="utf-8"
        ) as file:
            json.dump(
                self.findings,
                file,
                indent=4,
                ensure_ascii=False
            )

        logger.info(
            f"Historical scan saved: {file_path}"
        )

        return file_path

    def load_previous_scan(self):
        if not os.path.exists(HISTORY_DIR):
            return []

        files = [
            file
            for file in os.listdir(HISTORY_DIR)
            if file.endswith(".json")
        ]

        if len(files) < 1:
            return []

        files = sorted(files)

        latest_file = files[-1]

        file_path = os.path.join(
            HISTORY_DIR,
            latest_file
        )

        with open(
                file_path,
                "r",
                encoding="utf-8"
        ) as file:
            return json.load(file)

    def compare_with_previous(self):
        previous_findings = self.load_previous_scan()

        previous_keys = {
            self.finding_key(finding)
            for finding in previous_findings
        }

        current_keys = {
            self.finding_key(finding)
            for finding in self.findings
        }

        new_findings = [
            finding
            for finding in self.findings
            if self.finding_key(finding) not in previous_keys
        ]

        resolved_findings = [
            finding
            for finding in previous_findings
            if self.finding_key(finding) not in current_keys
        ]

        comparison = {
            "previous_total": len(previous_findings),
            "current_total": len(self.findings),
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
            "new_critical": self.count_by_risk(new_findings, "Critical"),
            "new_high": self.count_by_risk(new_findings, "High"),
            "resolved_critical": self.count_by_risk(resolved_findings, "Critical"),
            "resolved_high": self.count_by_risk(resolved_findings, "High"),
            "new_findings_details": new_findings,
            "resolved_findings_details": resolved_findings
        }

        os.makedirs(
            "output/json",
            exist_ok=True
        )

        with open(
                COMPARISON_FILE,
                "w",
                encoding="utf-8"
        ) as file:
            json.dump(
                comparison,
                file,
                indent=4,
                ensure_ascii=False
            )

        logger.info(
            f"Scan comparison saved: {COMPARISON_FILE}"
        )

        return comparison

    def finding_key(self, finding):
        return (
            f"{finding.get('username')}|"
            f"{finding.get('category')}|"
            f"{finding.get('finding')}"
        )

    def count_by_risk(self, findings, risk_level):
        return len(
            [
                finding
                for finding in findings
                if finding.get("risk_level") == risk_level
            ]
        )