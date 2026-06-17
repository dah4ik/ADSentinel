import csv
import json
import os
from datetime import datetime

from config.settings import settings
from core.logger import logger


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