import re
from pathlib import Path

# Search by regex instead of parsing the whole JSON.
DATE_PUBLISHED = re.compile(rb'"datePublished"\s*:\s*"([^"]{0,10})')


def record_date(record: Path) -> str:
    # Rejected records have no publication date: "" puts them outside any range.
    match = DATE_PUBLISHED.search(record.read_bytes())
    return match[1].decode() if match else ""


def date_in_range(date: str, from_date: str | None, to_date: str | None) -> bool:
    # Limits can be a year, month or day: compare at the same precision.
    if from_date:
        start_of_date = date[0 : len(from_date)]
        if start_of_date < from_date:
            return False
    if to_date:
        start_of_date = date[0 : len(to_date)]
        if start_of_date > to_date:
            return False
    return True
