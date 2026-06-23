import os
import subprocess
import time

import schedule

from core.logger import logger


def run_scan():
    logger.info("Scheduled scan started")

    try:
        subprocess.run(
            [
                "python",
                "main.py",
                "scan",
                "--profile",
                "deep"
            ],
            check=True
        )

        logger.info("Scheduled scan completed successfully")

    except subprocess.CalledProcessError as e:
        logger.error(
            f"Scheduled scan failed: {e}"
        )


def start_scheduler(interval):
    interval = interval.lower()

    if interval == "daily":
        schedule.every().day.at("09:00").do(run_scan)

    elif interval == "weekly":
        schedule.every().monday.at("09:00").do(run_scan)

    elif interval == "monthly":
        schedule.every(30).days.at("09:00").do(run_scan)

    else:
        raise ValueError(
            "Invalid schedule interval. Use daily, weekly, or monthly."
        )

    logger.info(
        f"Scheduler started with interval: {interval}"
    )

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    interval = os.getenv(
        "SCAN_SCHEDULE",
        "daily"
    )

    start_scheduler(
        interval
    )