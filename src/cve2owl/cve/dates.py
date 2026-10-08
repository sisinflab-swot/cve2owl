import json
from pathlib import Path


def record_date(record: Path) -> str:
    # Rejected records have no publication date: "" puts them outside any range.
    with record.open(encoding="utf-8") as f:
        data = json.load(f)
    metadata = data.get("cveMetadata", {})
    date = metadata.get("datePublished")
    if date is None:
        return ""
    return date[0:10]


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
