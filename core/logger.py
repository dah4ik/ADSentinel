import logging
import os
from datetime import datetime


def setup_logger():
    os.makedirs("logs", exist_ok=True)

    log_file = f"logs/adsentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logger = logging.getLogger("ADSentinel")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


logger = setup_logger()