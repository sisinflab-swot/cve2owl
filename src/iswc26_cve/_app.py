import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import cowl

from ._cve import CVEWriter
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


def parse_args() -> argparse.Namespace:
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
    return parser.parse_args()


def app() -> None:
    log = setup_logger()
    args = parse_args()

    log.info("Loading schema... ")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with Path(args.schema_file).open(encoding="utf-8") as f:
        schema = schema_to_ontology(json.load(f))

    log.info("Processing CVE data...")

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"iswc26_cve_{timestamp}.owl"
    writer = cowl.Writer.functional()

    with writer.stream(output_path) as stream:
        # Write schema
        stream.write(cowl.Header.from_ontology(schema))
        for axiom in schema.axioms():
            stream.write(axiom)
        # Process CVE records
        cw = CVEWriter(schema, stream)
        for input_dir in args.input_dirs:
            for json_file in Path(input_dir).rglob("CVE-*.json"):
                cw.process_record(json_file)
                log.info("%s (%d records, %d axioms)...", json_file.stem, cw.count, cw.axiom_count)

    total_axiom_count = cw.axiom_count + schema.axiom_count()
    log.info("Done. Total CVEs: %d, total axioms: %d", cw.count, total_axiom_count)
    log.info("Ontology written to %s", output_path)
