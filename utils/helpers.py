from datetime import datetime


def days_since(date_value):
    if not date_value:
        return None

    try:
        if isinstance(date_value, datetime):
            return (datetime.now(date_value.tzinfo) - date_value).days

        return None

    except Exception:
        return None