import argparse
import sys
from pathlib import Path

from .app import CPE_MODES, DEFAULT_OUTPUT_DIR, MissingDataError, generate
from .data import DATA_DIR
from .fetch import DATASETS, fetch


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cve2owl",
        description="Transforms the CVE data from cvelistV5 into an OWL ontology, "
        "integrated with the CPE dictionary and the CWE catalogue.",
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    fetch_parser = commands.add_parser(
        "fetch",
        help=f"Download or update the input data under {DATA_DIR}.",
        description=f"Download or update the input data under {DATA_DIR}. The CVE, CPE and "
        "CWE schemas are always fetched, as every generate run needs them.",
    )
    fetch_parser.add_argument(
        "datasets",
        metavar="DATASET",
        nargs="*",
        choices=DATASETS,
        help=f"Datasets to fetch, among {', '.join(DATASETS)} (default: all of them).",
    )
    fetch_parser.add_argument(
        "--cve-ref",
        help="Tag or commit of cvelistV5 to check out, e.g. a snapshot tag for "
        "reproducibility (default: the latest commit).",
    )
    fetch_parser.add_argument(
        "--force",
        action="store_true",
        help="Download and preprocess the files again even if they are up to date.",
    )

    generate_parser = commands.add_parser(
        "generate",
        help="Generate the OWL ontology from the fetched data.",
        description="Generate the OWL ontology from the fetched data.",
    )
    generate_parser.add_argument(
        "--ids",
        metavar="PATTERN",
        nargs="+",
        help="Only process the CVE records whose ID matches one of these glob patterns, "
        "e.g. 'CVE-2024-1*'.",
    )
    generate_parser.add_argument(
        "--from-date",
        help="Only process the CVE records published on this date or after it. "
        "The date can be a year, a month or a day: 2024, 2024-03, 2024-03-15.",
    )
    generate_parser.add_argument(
        "--to-date",
        help="Only process the CVE records published on this date or before it. "
        "Same formats as --from-date.",
    )
    generate_parser.add_argument(
        "--cpe",
        choices=CPE_MODES,
        default="referenced",
        help="Which products to read from the CPE dictionary: none, those referenced "
        "by the CVE records, or all of them (about 1.7 million, so a much bigger "
        "output). CPE individuals are described by their components in any case "
        "(default: referenced).",
    )
    generate_parser.add_argument(
        "--no-cwe",
        dest="cwe",
        action="store_false",
        help="Do not read the CWE catalogue: the CWE individuals linked from the CVE "
        "records stay bare.",
    )
    generate_parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory where the ontology and metrics are saved (default: {DEFAULT_OUTPUT_DIR}).",
    )

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(2)
    return args


def main() -> None:
    args = parse_args()
    if args.command == "fetch":
        fetch(args.datasets, cve_ref=args.cve_ref, force=args.force)
        return
    try:
        generate(
            ids=args.ids,
            from_date=args.from_date,
            to_date=args.to_date,
            cpe=args.cpe,
            cwe=args.cwe,
            output_dir=args.output_dir,
        )
    except MissingDataError as e:
        sys.exit(str(e))
