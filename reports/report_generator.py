import csv
import json
import os
from datetime import datetime

from jinja2 import Environment
from jinja2 import FileSystemLoader

from config.settings import settings
from core.logger import logger
from core.risk_engine import RiskEngine


class ReportGenerator:

    def __init__(self, findings):
        self.findings = findings
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_json(self):
        os.makedirs(
            settings.OUTPUT_JSON_DIR,
            exist_ok=True
        )

        file_path = (
            f"{settings.OUTPUT_JSON_DIR}/"
            f"adsentinel_report_{self.timestamp}.json"
        )

        data = [
            finding.to_dict()
            for finding in self.findings
        ]

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False
            )

        logger.info(
            f"JSON report created: {file_path}"
        )

        return file_path

    def generate_csv(self):
        os.makedirs(
            settings.OUTPUT_CSV_DIR,
            exist_ok=True
        )

        file_path = (
            f"{settings.OUTPUT_CSV_DIR}/"
            f"adsentinel_report_{self.timestamp}.csv"
        )

        fieldnames = [
            "category",
            "username",
            "finding",
            "risk_level",
            "risk_score",
            "recommendation"
        ]

        with open(
                file_path,
                "w",
                newline="",
                encoding="utf-8-sig"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames
            )

            writer.writeheader()

            for finding in self.findings:
                writer.writerow(
                    finding.to_dict()
                )

        logger.info(
            f"CSV report created: {file_path}"
        )

        return file_path

    def generate_html(self):
        os.makedirs(
            settings.OUTPUT_HTML_DIR,
            exist_ok=True
        )

        file_path = (
            f"{settings.OUTPUT_HTML_DIR}/"
            f"adsentinel_dashboard_{self.timestamp}.html"
        )

        env = Environment(
            loader=FileSystemLoader("reports/templates")
        )

        template = env.get_template(
            "dashboard.html"
        )

        security_score = RiskEngine.calculate_security_score(
            self.findings
        )

        overall_risk_level = RiskEngine.get_overall_risk_level(
            security_score
        )

        html_content = template.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=self.findings,
            total_findings=len(self.findings),
            critical_count=self.count_by_risk("Critical"),
            high_count=self.count_by_risk("High"),
            medium_count=self.count_by_risk("Medium"),
            low_count=self.count_by_risk("Low"),
            security_score=security_score,
            overall_risk_level=overall_risk_level
        )

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(html_content)

        logger.info(
            f"HTML report created: {file_path}"
        )

        return file_path

    def count_by_risk(self, risk_level):
        return len(
            [
                finding
                for finding in self.findings
                if finding.risk_level == risk_level
            ]
        )