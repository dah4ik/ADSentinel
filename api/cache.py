import json
import os

from api.server import FINDINGS_CACHE

LATEST_FINDINGS_FILE = "output/json/latest_findings.json"


def update_cache(findings):
    os.makedirs(
        "output/json",
        exist_ok=True
    )

    FINDINGS_CACHE.clear()

    serialized_findings = [
        finding.to_dict()
        for finding in findings
    ]

    FINDINGS_CACHE.extend(
        serialized_findings
    )

    with open(
            LATEST_FINDINGS_FILE,
            "w",
            encoding="utf-8"
    ) as file:
        json.dump(
            serialized_findings,
            file,
            indent=4,
            ensure_ascii=False
        )


def load_cache_from_file():
    if not os.path.exists(
            LATEST_FINDINGS_FILE
    ):
        return

    with open(
            LATEST_FINDINGS_FILE,
            "r",
            encoding="utf-8"
    ) as file:
        data = json.load(file)

    FINDINGS_CACHE.clear()
    FINDINGS_CACHE.extend(data)