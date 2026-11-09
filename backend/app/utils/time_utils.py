from datetime import datetime, timezone

def utcnow() -> datetime:
    """
    Return timezone-naive UTC timestamp for SQLite compatibility without Python 3.12+
    datetime.datetime.utcnow() deprecation warnings.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
