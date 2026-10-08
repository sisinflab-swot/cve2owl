import argparse
import json
import tarfile
from pathlib import Path

from cve2owl.core.jsonio import JSONValue
from cve2owl.core.log import logger as log

from .uri import CpeParseError, cpe_individual_name, field_to_name, parse_cpe

DEFAULT_CPE_DIR = "data/cpe"

# Only the product dictionary is needed: NVD's match criteria feed duplicates the
# cpeApplicability data already in the CVE records.
PRODUCTS_KEY = "products"
RECORD_KEY = "cpe"
NAME_KEY = "cpeName"


def record_path(records_dir: Path, cpe_string: str) -> Path:
    # Derived from the CPE string alone, so products mentioned by CVE records can be found.
    components = parse_cpe(cpe_string)
    folder = field_to_name(components.vendor)
    return records_dir / folder / (cpe_individual_name(cpe_string) + ".json")


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
            path = record_path(records_dir, cpe_string)
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Explode the downloaded NVD CPE dictionary into one JSON file per product.",
    )
    parser.add_argument(
        "feed",
        help="The downloaded .tar.gz feed, for example data/cpe/nvdcpe-2.0.tar.gz",
    )
    parser.add_argument(
        "--out-dir",
        default=DEFAULT_CPE_DIR,
        help=f"Where to write the product files (default: {DEFAULT_CPE_DIR}).",
    )
    args = parser.parse_args()

    feed_path = Path(args.feed)
    if not feed_path.exists():
        log.info("%s does not exist", feed_path)
        return

    records_dir = Path(args.out_dir) / "dictionary" / "records"
    log.info("processing %s ...", feed_path)
    written, skipped = explode_archive(feed_path, records_dir)
    log.info(
        "Done: %d record file(s) written under %s (%d skipped).",
        written,
        records_dir,
        skipped,
    )


if __name__ == "__main__":
    main()
