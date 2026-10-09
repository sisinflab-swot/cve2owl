import json
from collections.abc import Iterator
from pathlib import Path

from cve2owl.core.fetch import download, get_json, replace_dir
from cve2owl.core.jsonio import JSONValue
from cve2owl.core.log import logger as log
from cve2owl.data import CWE_CATALOGUE_DIR, CWE_SCHEMA

SCHEMA_URL = "https://raw.githubusercontent.com/CWE-CAPEC/REST-API-wg/main/openapi.json"
API_URL = "https://cwe-api.mitre.org/api/v1/cwe"

# Not in view 1000, but referenced by CVE records.
DEPRECATED_REFERENCED = [92, 216, 249, 292, 443, 533, 534, 592, 769]

# Avoid weakness/all: it may silently return truncated responses.
BATCH_SIZE = 50


class CweFetchError(Exception):
    pass


def fetch_schema(*, force: bool = False) -> None:
    download(SCHEMA_URL, CWE_SCHEMA, force=force)


def fetch_catalogue() -> None:
    replace_dir(CWE_CATALOGUE_DIR, _download_catalogue)


def _download_catalogue(catalogue_dir: Path) -> None:
    descendants = get_json(f"{API_URL}/1000/descendants?view=1000")
    ids = sorted({*_weakness_ids(descendants), *DEPRECATED_REFERENCED})
    count = 0
    for start in range(0, len(ids), BATCH_SIZE):
        batch = ids[start : start + BATCH_SIZE]
        url = f"{API_URL}/weakness/{','.join(map(str, batch))}"
        count = count + _save(get_json(url), "Weaknesses", catalogue_dir / "weaknesses", len(batch))
    log.info("  %d weaknesses", count)

    count = _save(get_json(f"{API_URL}/category/all"), "Categories", catalogue_dir / "categories")
    log.info("  %d categories", count)
    count = _save(get_json(f"{API_URL}/view/all"), "Views", catalogue_dir / "views")
    log.info("  %d views", count)


def _weakness_ids(node: JSONValue) -> Iterator[int]:
    if isinstance(node, dict):
        node_type = node.get("Type")
        if isinstance(node_type, str) and node_type.endswith("_weakness"):
            yield int(str(node["ID"]))
        for value in node.values():
            yield from _weakness_ids(value)
    elif isinstance(node, list):
        for value in node:
            yield from _weakness_ids(value)


def _save(response: JSONValue, key: str, folder: Path, expected: int | None = None) -> int:
    entries = response.get(key) if isinstance(response, dict) else None
    if not isinstance(entries, list) or (expected is not None and len(entries) != expected):
        found = len(entries) if isinstance(entries, list) else 0
        msg = f"CWE API returned {found} {key.lower()}, expected {expected or 'some'}"
        raise CweFetchError(msg)

    folder.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        text = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        (folder / f"CWE-{entry['ID']}.json").write_text(text, encoding="utf-8")
    return len(entries)
