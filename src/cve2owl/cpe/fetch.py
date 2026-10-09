import json
import tarfile
from pathlib import Path

from cve2owl.core.fetch import download, replace_dir
from cve2owl.core.jsonio import JSONValue
from cve2owl.core.log import logger as log
from cve2owl.data import CPE_FEED, CPE_RECORDS_DIR, CPE_SCHEMA

from .uri import CpeComponents, CpeParseError, field_to_name, parse_cpe

SCHEMA_URL = "https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema"
FEED_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"

# Only the product dictionary is needed: NVD's match criteria feed duplicates the
# cpeApplicability data already in the CVE records.
PRODUCTS_KEY = "products"
RECORD_KEY = "cpe"
NAME_KEY = "cpeName"


def record_path(records_dir: Path, cpe: CpeComponents) -> Path:
    folder = field_to_name(cpe.vendor)
    return records_dir / folder / (cpe.individual_name + ".json")


def explode_page(page: JSONValue, records_dir: Path) -> tuple[int, int]:
    written = 0
    skipped = 0
    if not isinstance(page, dict) or not isinstance(products := page.get(PRODUCTS_KEY), list):
        return written, skipped

    created_folders: set[Path] = set()

    for wrapper in products:
        record = wrapper.get(RECORD_KEY) if isinstance(wrapper, dict) else None
        cpe_string = record.get(NAME_KEY) if isinstance(record, dict) else None
        if not isinstance(cpe_string, str) or not cpe_string:
            skipped = skipped + 1
            continue

        try:
            path = record_path(records_dir, parse_cpe(cpe_string))
        except CpeParseError:
            skipped = skipped + 1
            continue

        if path.parent not in created_folders:
            path.parent.mkdir(parents=True, exist_ok=True)
            created_folders.add(path.parent)

        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        written = written + 1

    return written, skipped


def explode_archive(archive_path: Path, records_dir: Path) -> tuple[int, int]:
    written = 0
    skipped = 0
    page_number = 0
    with tarfile.open(archive_path, "r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            try:
                page = json.load(f)
            except json.JSONDecodeError as e:
                log.info("  skipping %s: not valid JSON (%s)", member.name, e)
                continue

            page_written, page_skipped = explode_page(page, records_dir)
            written = written + page_written
            skipped = skipped + page_skipped
            page_number = page_number + 1
            log.info("  page %d (%s): %d records written so far", page_number, member.name, written)
    return written, skipped


def fetch_schema(*, force: bool = False) -> None:
    download(SCHEMA_URL, CPE_SCHEMA, force=force)


def fetch_dictionary(*, force: bool = False) -> None:
    changed = download(FEED_URL, CPE_FEED, force=force)
    if not changed and CPE_RECORDS_DIR.exists():
        return

    def build(records_dir: Path) -> None:
        log.info("Splitting %s into one file per product...", CPE_FEED)
        written, skipped = explode_archive(CPE_FEED, records_dir)
        log.info("  %d record files written (%d skipped)", written, skipped)

    replace_dir(CPE_RECORDS_DIR, build)
