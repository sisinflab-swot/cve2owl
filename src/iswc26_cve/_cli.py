import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from ._cve import add_vulnerability
from ._schema import schema_to_ontology


def setup_logger() -> logging.Logger:
    log = logging.getLogger("iswc26_cve")
    fmt = "[%(asctime)s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    handler = logging.StreamHandler(sys.stdout)
    handler.formatter = logging.Formatter(fmt, datefmt=datefmt)
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    return log


def app() -> None:
    parser = argparse.ArgumentParser(
        description="Transforms the CVE data from cvelistV5 into an OWL ontology.",
    )
    parser.add_argument(
        "--schema-file",
        "-s",
        required=True,
        help="Path to the JSON Schema file defining the structure of the CVE data.",
    )
    parser.add_argument(
        "--input-dirs",
        "-i",
        nargs="+",
        required=True,
        help="Paths to the directories containing the CVE JSON files.",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="output",
        help="Path to the directory where the OWL ontology will be saved.",
    )
    args = parser.parse_args()

    log = setup_logger()
    log.info("Loading schema... ")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with Path(args.schema_file).open(encoding="utf-8") as f:
        onto = schema_to_ontology(json.load(f))

    log.info("Processing CVE data...")
    count = 0
    for input_dir in args.input_dirs:
        for json_file in Path(input_dir).rglob("CVE-*.json"):
            with json_file.open(encoding="utf-8") as f:
                count += 1
                name = json_file.stem
                log.info("[%d] %s (%d axioms)...", count, name, len(onto))
                add_vulnerability(onto, json_file.stem, json.load(f))

    log.info("Done. Total CVEs: %d, total axioms: %d", count, len(onto))
    log.info("Saving ontology...")
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"iswc26_cve_{timestamp}.owl"
    onto.to_path(output_path)
    log.info("Done: %s", output_path)
